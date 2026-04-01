#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

// ==========================================
// 运行模式开关 (互斥！每次编译前选择 1 个置为 1)
// ==========================================
#define DATA_COLLECT 0 // 开启收集模式 (向 RingBuffer 发送特征)
#define DEPLOY       1 // 关闭部署模式

#define WINDOW_SIZE 100
#define SAMPLING_MASK 0xFF 

enum policy_type {
    POLICY_LRU = 0,
    POLICY_MRU = 1,
};

static u64 main_list; 

// ==========================================
// 【隔离区】DATA_COLLECT 专属 Map 与结构体
// ==========================================
#if DATA_COLLECT
struct feature_event {
    u32 window_id;
    u32 seq_ratio_10000;    
    u32 avg_irr;            
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); 
} feature_events SEC(".maps");
#endif

// 内部页面追踪Map (公用，用于计算物理访存距离)
struct page_track_info {
    u64 last_access_tick;
    u32 window_id; 
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH); 
    __uint(max_entries, 200000); 
    __type(key, __u64); 
    __type(value, struct page_track_info); 
} page_tracking_map SEC(".maps");

// ==========================================
// 核心统计结构体 (根据模式剪裁多余指令)
// ==========================================
struct thread_stat {
    u64 tick;
    u64 seq_access_count;
    u64 total_irr;
    u64 irr_event_count;
    u64 last_mapping;
    u64 last_index;
    u32 current_window_id;
    u32 smoothed_seq; 
    u32 smoothed_irr;
    u32 current_policy; 
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 4096);           
    __type(key, u32);                    
    __type(value, struct thread_stat);
} thread_stats_map SEC(".maps");

static inline u32 get_thread_policy() {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct thread_stat *st = bpf_map_lookup_elem(&thread_stats_map, &tid);
    if (st) return st->current_policy;
    return POLICY_LRU; // 默认相信是好人，走原生 LRU 旁路
}

static inline void record_access(u64 mapping, u64 index) {
    u64 raw_tick = bpf_ktime_get_ns();
    if ((raw_tick & SAMPLING_MASK) != 0) return; 

    u32 tid = (u32)bpf_get_current_pid_tgid(); 
    struct thread_stat *st = bpf_map_lookup_elem(&thread_stats_map, &tid);
    
    if (!st) {
        // 第一次见到这个线程，建档
        struct thread_stat new_st = {};
        new_st.last_mapping = mapping;
        new_st.last_index = index;
        new_st.current_policy = POLICY_LRU; 
        bpf_map_update_elem(&thread_stats_map, &tid, &new_st, BPF_ANY);
        return;
    }

    st->tick++;
    
    // 1. 连续性计算 (锁定同一个文件 mapping)
    if (mapping == st->last_mapping) {
        u64 diff = index - st->last_index;
        if (diff > 0 && diff <= 512) {
            st->seq_access_count++;
        }
    }
    st->last_mapping = mapping;
    st->last_index = index;

    // 2. 窗口结算与硬核裁决
    if (st->tick > 0 && (st->tick % WINDOW_SIZE) == 0) {
        u64 events = st->irr_event_count; 
        u64 total = st->total_irr;
        
        u32 cur_seq_ratio_10000 = (st->seq_access_count * 10000) / WINDOW_SIZE;
        u32 cur_avg_irr = events > 0 ? (total / events) : 0;
        
        st->smoothed_seq = (st->smoothed_seq * 3 + cur_seq_ratio_10000) >> 2;
        st->smoothed_irr = (st->smoothed_irr * 3 + cur_avg_irr) >> 2;

#if DEPLOY
        // 铁阈值：不信 AI，只信物理规律
        // 如果当前线程的顺序扫描比例超过 80%，死锁它为 MRU！
        if (st->smoothed_seq > 8000) {
            st->current_policy = POLICY_MRU;
        } else {
            st->current_policy = POLICY_LRU;
        }
#endif

#if DATA_COLLECT
        struct feature_event *event = bpf_ringbuf_reserve(&feature_events, sizeof(*event), 0);
        if (event) {
            event->window_id = st->current_window_id;
            event->seq_ratio_10000 = cur_seq_ratio_10000;
            event->avg_irr = cur_avg_irr;
            bpf_ringbuf_submit(event, 0);
        }
#endif

        st->current_window_id++;
        st->seq_access_count = 0;
        st->total_irr = 0;
        st->irr_event_count = 0;
    }

    u64 page_id = mapping ^ (index << 12);
    u32 win_id = st->current_window_id;
    struct page_track_info *info = bpf_map_lookup_elem(&page_tracking_map, &page_id);
    
    if (info) {
        u64 irr = (st->tick - info->last_access_tick);
        st->total_irr += irr;
        st->irr_event_count++;
        info->last_access_tick = st->tick;
        info->window_id = win_id;
    } else {
        struct page_track_info new_info = {
            .last_access_tick = st->tick,
            .window_id = win_id
        };
        bpf_map_update_elem(&page_tracking_map, &page_id, &new_info, BPF_ANY);
    }
}

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    record_access((u64)mapping, index);


    if (get_thread_policy() == POLICY_MRU) {
        bpf_cache_ext_list_add(main_list, folio);
    }
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    record_access((u64)mapping, index);

    // 🌟 核心：如果是毒药线程重访了页面，维持它在 MRU 隔离区的位置
    if (get_thread_policy() == POLICY_MRU) {
        bpf_cache_ext_list_move(main_list, folio, false); 
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {

}

static int evict_mru_cb(int idx, struct cache_ext_list_node *a) {
    if (!a || !a->folio) return CACHE_EXT_CONTINUE_ITER;

    bool uptodate = folio_test_uptodate(a->folio);
    bool lru = folio_test_lru(a->folio);
    bool dirty = folio_test_dirty(a->folio);
    bool writeback = folio_test_writeback(a->folio);
    bool locked = folio_test_locked(a->folio);
    
    bpf_folio_check_referenced(a->folio); 

    int action = CACHE_EXT_EVICT_NODE;
    int reason = 0; 

    if (locked) reason = 1;
    else if (writeback) reason = 2;
    else if (dirty) reason = 3;
    else if (!uptodate) reason = 4;
    else if (!lru) reason = 5;

    if (reason > 0) {
        action = CACHE_EXT_CONTINUE_ITER;
    }

    return action;
}

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    bpf_cache_ext_list_iterate(memcg, main_list, evict_mru_cb, eviction_ctx);
}

SEC(".struct_ops.link")
struct cache_ext_ops chameleon_ops = {
    .init = (void *)chameleon_init,
    .evict_folios = (void *)chameleon_evict_folios,
    .folio_accessed = (void *)chameleon_folio_accessed,
    .folio_evicted = (void *)chameleon_folio_evicted,
    .folio_added = (void *)chameleon_folio_added,
};