#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

// ==========================================
// 运行模式开关 (互斥！每次编译前选择 1 个置为 1)
// ==========================================
#define DATA_COLLECT 0 // 阶段一：收集模式 (往 RingBuffer 发数据给 Python)
#define DEPLOY       1 // 阶段二：实战部署模式 (极速查表，零用户态通信)

// 调试与基础特性开关
#define CML_DEBUG 0
#define ENABLE_LFU 1
#define ENABLE_PATTERN_REC 1
#define WINDOW_SIZE 10000

// 引入自动生成的策略网格 (仅 DEPLOY 模式需要)
#if DEPLOY
#include "policy_lut.h"

// 极速对数计算
static __always_inline __u32 fast_log2(__u32 v) {
    __u32 r = 0;
    if (v >= 0x10000) { v >>= 16; r |= 16; }
    if (v >= 0x100)   { v >>= 8;  r |= 8;  }
    if (v >= 0x10)    { v >>= 4;  r |= 4;  }
    if (v >= 0x4)     { v >>= 2;  r |= 2;  }
    if (v >= 0x2)     { r |= 1; }
    return r;
}
#endif

enum policy_type {
    POLICY_LRU = 0,
    POLICY_MRU = 1,
#if ENABLE_LFU
    POLICY_LFU = 2,
#endif
};

struct rl_params { __u32 active_policy; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_params);
} cml_params_map SEC(".maps");

// 宏观统计Map (保留)
struct macro_stats {
    __s64 wss;             
    __s64 score_counts[11]; 
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct macro_stats);
} cml_stats_map SEC(".maps");

static u64 main_list; 

#if ENABLE_LFU
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 200000); 
    __type(key, __u64);          
    __type(value, u8);           
} lfu_freq_map SEC(".maps");
#endif

#if ENABLE_PATTERN_REC

// ==========================================
// 【隔离区】DATA_COLLECT 专属 Map 与结构体
// ==========================================
#if DATA_COLLECT
struct feature_event {
    u32 window_id;
    u32 seq_ratio_10000;    
    u32 avg_irr;            
    u32 unique_ratio_10000; 
    u32 irr_0_1k_ratio;     
    u32 irr_1k_10k_ratio;   
    u32 irr_10k_plus_ratio; 
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
struct cpu_stat {
    u64 tick;
    u64 seq_access_count;
    u64 total_irr;
    u64 irr_event_count;
    u64 last_mapping;
    u64 last_index;
    u32 current_window_id;
#if DATA_COLLECT
    // 这些高阶特征只在收集训练数据时才占用内存和计算资源
    u64 unique_pages_count;
    u64 irr_0_1k_count;
    u64 irr_1k_10k_count;
    u64 irr_10k_plus_count;
#endif
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_stat);
} cpu_stats_map SEC(".maps");

#define SAMPLING_MASK 0x3F 

static inline void record_access(u64 mapping, u64 index) {
    u32 key = 0;
    struct cpu_stat *st = bpf_map_lookup_elem(&cpu_stats_map, &key);
    if (!st) return;

    st->tick++;
    
    // 1. 连续性计算 (Fast Path)
    if (mapping == st->last_mapping) {
        u64 diff = index - st->last_index;
        if (diff > 0 && diff <= 512) {
            st->seq_access_count++;
        }
    }
    st->last_mapping = mapping;
    st->last_index = index;

    // 2. 窗口结算与决策
    if (st->tick > 0 && (st->tick % WINDOW_SIZE) == 0) {
        u64 events = st->irr_event_count; 
        u64 total = st->total_irr;
        
        u32 cur_seq_ratio_10000 = (st->seq_access_count * 10000) / WINDOW_SIZE;
        u32 cur_avg_irr = events > 0 ? (total / events) : 0;

#if DATA_COLLECT
        // [收集模式] 打包所有特征，推入 RingBuffer 喂给 Python
        struct feature_event *event = bpf_ringbuf_reserve(&feature_events, sizeof(*event), 0);
        if (event) {
            event->window_id = st->current_window_id;
            event->seq_ratio_10000 = cur_seq_ratio_10000;
            event->avg_irr = cur_avg_irr;
            event->unique_ratio_10000 = (st->unique_pages_count * 10000) / (WINDOW_SIZE >> 6);
            event->irr_0_1k_ratio = events > 0 ? (st->irr_0_1k_count * 10000) / events : 0;
            event->irr_1k_10k_ratio = events > 0 ? (st->irr_1k_10k_count * 10000) / events : 0;
            event->irr_10k_plus_ratio = events > 0 ? (st->irr_10k_plus_count * 10000) / events : 0;
            bpf_ringbuf_submit(event, 0);
        }
#elif DEPLOY
        // [部署模式] ⚡ 零通讯查表，立刻篡改内核页替换控制参数！
        u32 seq_percent = cur_seq_ratio_10000 / 100;
        u32 irr_log_idx = fast_log2(cur_avg_irr);
        
        if (seq_percent > 100) seq_percent = 100;
        if (irr_log_idx > 32) irr_log_idx = 32;

        __u8 next_policy = policy_lut[seq_percent][irr_log_idx];

        __u32 map_key = 0;
        struct rl_params new_params = { .active_policy = next_policy };
        bpf_map_update_elem(&cml_params_map, &map_key, &new_params, BPF_ANY);
#endif

        // 窗口清零重置
        st->current_window_id++;
        st->seq_access_count = 0;
        st->total_irr = 0;
        st->irr_event_count = 0;
#if DATA_COLLECT
        st->unique_pages_count = 0;
        st->irr_0_1k_count = 0;
        st->irr_1k_10k_count = 0;
        st->irr_10k_plus_count = 0;
#endif
    }

    // 3. 采样拦截器
    if ((st->tick & SAMPLING_MASK) != 0) return; 

    // 4. 重访计算 (Slow Path)
    u64 page_id = mapping ^ (index << 12);
    u32 win_id = st->current_window_id;
    struct page_track_info *info = bpf_map_lookup_elem(&page_tracking_map, &page_id);
    
    if (info) {
        u64 irr = (st->tick - info->last_access_tick);
        st->total_irr += irr;
        st->irr_event_count++;

#if DATA_COLLECT
        // DEPLOY模式下直接剪除这些耗时的 if-else 分支
        if (irr < 1000) st->irr_0_1k_count++;
        else if (irr < 10000) st->irr_1k_10k_count++;
        else st->irr_10k_plus_count++;

        if (info->window_id != win_id) st->unique_pages_count++;
#endif
        
        info->last_access_tick = st->tick;
        info->window_id = win_id;
    } else {
#if DATA_COLLECT
        st->unique_pages_count++;
#endif
        struct page_track_info new_info = {
            .last_access_tick = st->tick,
            .window_id = win_id
        };
        bpf_map_update_elem(&page_tracking_map, &page_id, &new_info, BPF_ANY);
    }
}
#endif

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
#if CML_DEBUG
    if (__sync_fetch_and_add(&init_cnt, 1) < 5) {
        bpf_printk("[CML-RADAR] INIT called!\n");
    }
#endif
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    
    // 初始化时给一个默认的 Policy
    __u32 key = 0;
    struct rl_params init_params = {};
    init_params.active_policy = POLICY_LRU;
    bpf_map_update_elem(&cml_params_map, &key, &init_params, BPF_ANY);

    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
#if CML_DEBUG
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    if ((__sync_fetch_and_add(&add_cnt, 1) % 100) == 0) {
        bpf_printk("[CML-ADD] pid:%u folio:%llx\n", pid, (u64)folio);
    }
#endif

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    u32 policy = params ? params->active_policy : POLICY_LRU;

#if ENABLE_PATTERN_REC
    // 获取绝对唯一的逻辑页 ID，防止跨文件哈希碰撞
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    record_access((u64)mapping, index);
#endif

    // 无脑执行当前下发的 policy
    if (policy == POLICY_LRU) bpf_cache_ext_list_add_tail(main_list, folio);
    else bpf_cache_ext_list_add(main_list, folio);

#if ENABLE_LFU
    if (policy == POLICY_LFU) {
        u64 addr = (u64)folio;
        u8 init_freq = 1; 
        bpf_map_update_elem(&lfu_freq_map, &addr, &init_freq, BPF_ANY);
    }
#endif
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
#if CML_DEBUG
    if (__sync_fetch_and_add(&acc_cnt, 1) < 5) {
        bpf_printk("[CML-RADAR] ACCESSED called!\n");
    }
#endif

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return;

#if ENABLE_PATTERN_REC
    // [修改] 获取绝对唯一的逻辑页 ID，防止跨文件哈希碰撞
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    record_access((u64)mapping, index);
#endif

    switch (params->active_policy) {
        case POLICY_LRU:
            // bpf_cache_ext_list_move(main_list, folio, true);  
            break;
        case POLICY_MRU:
            bpf_cache_ext_list_move(main_list, folio, false); 
            break;
#if ENABLE_LFU
        case POLICY_LFU: {
            u64 addr = (u64)folio;
            u8 *freq = bpf_map_lookup_elem(&lfu_freq_map, &addr);
            if (freq) {
                if (*freq < 255) (*freq)++;
            } else {
                u8 val = 1;
                bpf_map_update_elem(&lfu_freq_map, &addr, &val, BPF_ANY);
            }
            bpf_cache_ext_list_move(main_list, folio, true); 
            break;
        }
#endif
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
#if CML_DEBUG
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if ((__sync_fetch_and_add(&evict_cnt, 1) % 100) == 0) {
        bpf_printk("[CML-EVICT-NOTIFY] folio:%llx (by pid:%d)\n", (u64)folio, pid);
    }
#endif

    // 不再记录后悔事件，因为模式识别是从全局时空视角判断的，而非微观试错。

#if ENABLE_LFU
    u64 addr = (u64)folio;
    bpf_map_delete_elem(&lfu_freq_map, &addr);
#endif
    // Warning!!!
    // bpf_cache_ext_list_del(folio);
}

// ==========================================
// 核心驱逐逻辑 
// ==========================================
static int evict_lru_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio) || folio_test_locked(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (bpf_folio_check_referenced(a->folio) > 0) return CACHE_EXT_CONTINUE_ITER;
    return CACHE_EXT_EVICT_NODE;
}

static int evict_mru_cb(int idx, struct cache_ext_list_node *a) {
    if (!a || !a->folio) return CACHE_EXT_CONTINUE_ITER;

    bool uptodate = folio_test_uptodate(a->folio);
    bool lru = folio_test_lru(a->folio);
    bool dirty = folio_test_dirty(a->folio);
    bool writeback = folio_test_writeback(a->folio);
    bool locked = folio_test_locked(a->folio);
    
#if CML_DEBUG
    int refs = bpf_folio_check_referenced(a->folio);
#else
    bpf_folio_check_referenced(a->folio); 
#endif

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

#if CML_DEBUG
    if (__sync_fetch_and_add(&mru_debug_count, 1) < 20) {
        bpf_printk("[MRU-DBG] idx:%d up:%d lru:%d dir:%d wb:%d lck:%d\n",
                   idx, uptodate, lru, dirty, writeback, locked);
        bpf_printk("[MRU-DBG-2] refs:%d action:%d reason:%d\n",
                   refs, action, reason);
    }
#endif

    return action;
}

#if ENABLE_LFU
static int evict_lfu_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio) || folio_test_locked(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    
    u64 addr = (u64)a->folio;
    u8 *freq = bpf_map_lookup_elem(&lfu_freq_map, &addr);

    if (bpf_folio_check_referenced(a->folio) > 0) {
        if (freq && *freq < 255) (*freq)++;
        return CACHE_EXT_CONTINUE_ITER;
    }

    u8 val = freq ? *freq : 0;

    if (val <= 1) {
        return CACHE_EXT_EVICT_NODE;
    } 
    else {
        *freq = val >> 1;
        return CACHE_EXT_CONTINUE_ITER;
    }
}
#endif

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    __u32 param_key = 0;

    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    u32 policy = params ? params->active_policy : POLICY_LRU;

#if CML_DEBUG
    if (__sync_fetch_and_add(&evict_trigger_cnt, 1) < 50) {
        bpf_printk("[CML-RADAR] EVICT TRIGGERED! Policy: %d, Req: %d\n", 
                   policy, eviction_ctx->request_nr_folios_to_evict);
    }
    mru_debug_count = 0;
#endif

    if (policy == POLICY_LRU) {
        bpf_cache_ext_list_iterate(memcg, main_list, evict_lru_cb, eviction_ctx);
    } 
    else if (policy == POLICY_MRU) {
        bpf_cache_ext_list_iterate(memcg, main_list, evict_mru_cb, eviction_ctx);
        
#if CML_DEBUG
        bpf_printk("[MRU-RESULT] req:%d evicted:%d\n", 
                   eviction_ctx->request_nr_folios_to_evict, 
                   eviction_ctx->nr_folios_to_evict);
#endif
    }
#if ENABLE_LFU
    else if (policy == POLICY_LFU) {
        bpf_cache_ext_list_iterate(memcg, main_list, evict_lfu_cb, eviction_ctx);
    }
#endif
}

SEC(".struct_ops.link")
struct cache_ext_ops chameleon_ops = {
    .init = (void *)chameleon_init,
    .evict_folios = (void *)chameleon_evict_folios,
    .folio_accessed = (void *)chameleon_folio_accessed,
    .folio_evicted = (void *)chameleon_folio_evicted,
    .folio_added = (void *)chameleon_folio_added,
};