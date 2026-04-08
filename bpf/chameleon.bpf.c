// chameleon.bpf.c - 基于访问模式动态调整页面回收优先级的 BPF 实现
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

// ==========================================
// 运行模式开关 (互斥！每次编译前选择 1 个置为 1)
// ==========================================
#define DATA_COLLECT 0 // 收集模式 (向 RingBuffer 发送特征)
#define DEPLOY       1 // 部署模式

#define WINDOW_SIZE 10
#define SAMPLING_MASK 0x3F
#define TRACK_DEPTH 4

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
    u32 tid;
    u32 window_id;
    u32 seq_ratio_10000;    
    u32 hot_ratio_10000;
    u32 new_ratio_10000;       
    u64 stride_variance;    
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
    __uint(type, BPF_MAP_TYPE_HASH); 
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
    u64 hot_access_count;
    u64 new_page_count;
    u64 last_mappings[TRACK_DEPTH];
    u64 last_indexes[TRACK_DEPTH];
    u64 last_mapping;
    u64 last_index;
    u32 current_window_id;
    u32 smoothed_seq; 
    u32 smoothed_hot;
    u32 smoothed_new;
    u32 current_policy; 

    u64 stride_count;
    s64 stride_mean;
    s64 stride_m2;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct thread_stat);
} thread_stats_map SEC(".maps");

static inline struct thread_stat *get_or_create_thread_stat(void) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct thread_stat *st = bpf_map_lookup_elem(&thread_stats_map, &tid);
    
    if (!st) {
        struct thread_stat new_st = {};
        new_st.current_policy = POLICY_LRU;
        // 插入新线程的统计结构体
        bpf_map_update_elem(&thread_stats_map, &tid, &new_st, BPF_ANY);
        // 重新获取指针，确保可以直接原地修改
        st = bpf_map_lookup_elem(&thread_stats_map, &tid);
    }
    return st;
}

static inline u32 get_thread_policy(void) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct thread_stat *st = bpf_map_lookup_elem(&thread_stats_map, &tid);
    if (st) return st->current_policy;
    return POLICY_LRU; 
}

static inline void record_access(u64 mapping, u64 index, u64 raw_tick) {
    struct thread_stat *st = get_or_create_thread_stat();
    if (!st) return;

    st->tick++;

    // 1. Welford 算法：流式计算跨步偏移量方差 (提取 Compaction 与 GET 的极性差异)
    if (st->last_mapping == mapping) {
        s64 delta_d = (s64)index - (s64)st->last_index;
        st->stride_count++;
        
        s64 diff = delta_d - st->stride_mean;

        // 🌟 修复：将有符号除法 (sdiv) 转换为无符号除法 (udiv)
        u64 abs_diff = (diff < 0) ? -diff : diff;
        u64 u_div = abs_diff / st->stride_count;
        s64 s_div = (diff < 0) ? -(s64)u_div : (s64)u_div;
        
        st->stride_mean += s_div;
        
        s64 diff2 = delta_d - st->stride_mean;
        st->stride_m2 += diff * diff2;
    }
    st->last_mapping = mapping;
    st->last_index = index;
    
    // 2. 连续性计算 (支持最高 4 路交替顺序读)
    bool is_seq = false;
    #pragma unroll
    for (int i = 0; i < TRACK_DEPTH; i++) {
        if (st->last_mappings[i] == mapping) {
            u64 diff = index - st->last_indexes[i];
            if (diff > 0 && diff <= 512) {
                st->seq_access_count++;
                is_seq = true;
            }
            st->last_indexes[i] = index; 
            break;
        }
    }
    
    if (!is_seq) {
        int replace_idx = st->tick & (TRACK_DEPTH - 1); 
        st->last_mappings[replace_idx] = mapping;
        st->last_indexes[replace_idx] = index;
    }

    // 3. 窗口结算与推断
    if (st->tick > 0 && (st->tick % WINDOW_SIZE) == 0) {
        u32 cur_seq_ratio = (st->seq_access_count * 10000) / WINDOW_SIZE;
        u32 cur_hot_ratio = (st->hot_access_count * 10000) / WINDOW_SIZE;
        u32 cur_new_ratio = (st->new_page_count * 10000) / WINDOW_SIZE;
        
        st->smoothed_seq = (st->smoothed_seq * 3 + cur_seq_ratio) >> 2;
        st->smoothed_hot = (st->smoothed_hot * 3 + cur_hot_ratio) >> 2;
        st->smoothed_new = (st->smoothed_new * 3 + cur_new_ratio) >> 2;

#if DEPLOY
        if (st->smoothed_seq > 8000) {
            st->current_policy = POLICY_MRU;
        } else {
            st->current_policy = POLICY_LRU;
        }
#endif

#if DATA_COLLECT
        struct feature_event *event = bpf_ringbuf_reserve(&feature_events, sizeof(*event), 0);
        if (event) {
            event->tid = (u32)bpf_get_current_pid_tgid();
            event->window_id = st->current_window_id;
            event->seq_ratio_10000 = cur_seq_ratio;
            event->hot_ratio_10000 = cur_hot_ratio;
            event->new_ratio_10000 = cur_new_ratio;
            // 总体方差 V = m2 / n
            event->stride_variance = st->stride_count > 1 ? ((u64)st->stride_m2 / st->stride_count) : 0;
            bpf_ringbuf_submit(event, 0);
        }
#endif

        st->current_window_id++;
        st->seq_access_count = 0;
        st->hot_access_count = 0;
        st->new_page_count = 0;
        // Welford 变量在长期观察下更为稳定，根据需要决定是否在这里清零
        // st->stride_count = 0; st->stride_mean = 0; st->stride_m2 = 0;
    }

#if DATA_COLLECT
    // 4. 物理级重用距离 (仅在采集模式下开启，保护 DEPLOY 时的内存开销)
    u64 page_id = mapping ^ (index << 12);
    u32 win_id = st->current_window_id;
    u64 current_time_us = raw_tick / 1000;

    struct page_track_info *info = bpf_map_lookup_elem(&page_tracking_map, &page_id);
    if (info) {
        if (current_time_us > info->last_access_tick) {
            u64 irr = current_time_us - info->last_access_tick;
            if (irr < 50000) st->hot_access_count++;
        }
        info->last_access_tick = current_time_us;
        info->window_id = win_id;
    } else {
        st->new_page_count++;
        struct page_track_info new_info = {
            .last_access_tick = current_time_us,
            .window_id = win_id
        };
        bpf_map_update_elem(&page_tracking_map, &page_id, &new_info, BPF_ANY);
    }
#endif
}

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    u64 raw_tick = bpf_ktime_get_ns();
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    
    // 仅针对特征采集进行采样，降低计算开销
    if ((raw_tick & SAMPLING_MASK) == 0) {
        record_access((u64)mapping, index, raw_tick);
    }

    // 🌟 动作全量执行：得益于底层的 Batched 接口，这里的并发锁开销已经被抹平
    if (get_thread_policy() == POLICY_MRU) {
        bpf_cache_ext_list_add_batched(main_list, folio);
    }
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    u64 raw_tick = bpf_ktime_get_ns();
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    
    if ((raw_tick & SAMPLING_MASK) == 0) {
        record_access((u64)mapping, index, raw_tick);
    }

    if (get_thread_policy() == POLICY_MRU) {
        bpf_cache_ext_list_move_batched(main_list, folio, false); 
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
    
    // bpf_folio_check_referenced(a->folio); 

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