#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

// ==========================================
// 调试开关：设为 1 开启详细日志与计数器，设为 0 关闭
// ==========================================
#define CML_DEBUG 0

// ==========================================
// 特性开关
// ==========================================
#define ENABLE_LFU 1
#define ENABLE_PATTERN_REC 1 // 开启基于模式识别的宏观特征提取 (Pattern Recognition)

// 模式识别的时间窗口大小：每 10000 次访存提取一次特征向量
#define WINDOW_SIZE 10000

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
    __uint(type, BPF_MAP_TYPE_LRU_HASH); // 👈 核心优化：自带容量自净能力的哈希表
    __uint(max_entries, 200000); 
    __type(key, __u64);          
    __type(value, u8);           
} lfu_freq_map SEC(".maps");
#endif

#if ENABLE_PATTERN_REC
// ==========================================
// 数据面输出：向 Python/C++ Agent 汇报的宏观特征向量
// ==========================================
struct feature_event {
    u32 window_id;
    u32 seq_ratio_10000;    // 连续步长比例 (放大 10000 倍的定点数)
    u32 avg_irr;            // 平均重访距离
    u32 unique_ratio_10000; // 独有页面率 (放大 10000 倍的定点数)
    
    // [新增] 用于 GMM 聚类的 IRR 直方图分布特征 (放大 10000 倍的比例)
    u32 irr_0_1k_ratio;     
    u32 irr_1k_10k_ratio;   
    u32 irr_10k_plus_ratio; 
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); 
} feature_events SEC(".maps");

// 内部状态跟踪：用于计算重访距离和独有页面
struct page_track_info {
    u64 last_access_tick;
    u32 window_id; // 记录页面最后一次被访问是在哪个窗口期
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH); 
    __uint(max_entries, 200000); 
    __type(key, __u64); 
    __type(value, struct page_track_info); 
} page_tracking_map SEC(".maps");

// ==========================================
// 🚀 核心优化：Per-CPU 状态统计，彻底消灭全局原子锁！
// ==========================================
struct cpu_stat {
    u64 tick;
    u64 seq_access_count;
    u64 total_irr;
    u64 irr_event_count;
    u64 unique_pages_count;
    u64 irr_0_1k_count;
    u64 irr_1k_10k_count;
    u64 irr_10k_plus_count;
    u64 last_mapping;
    u64 last_index;
    u32 current_window_id;
};

// 为每个 CPU 核心独立分配一份上述结构体
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct cpu_stat);
} cpu_stats_map SEC(".maps");


// 设定采样掩码为 0x3F (即 64)，实现 1/64 的采样率
#define SAMPLING_MASK 0x3F 

// O(1) 核心特征提取辅助函数 (大数定律采样版)
static inline void record_access(u64 mapping, u64 index) {
    u32 key = 0;
    struct cpu_stat *st = bpf_map_lookup_elem(&cpu_stats_map, &key);
    if (!st) return;

    st->tick++;
    
    // ==========================================
    // ⚡ Fast Path (极速路径)：所有请求都会执行，开销 < 5纳秒
    // ==========================================
    
    // 1. 统计连续步长 (兼容 Large Folio 和内核预读批处理)
    if (mapping == st->last_mapping) {
        u64 diff = index - st->last_index;
        // 允许的跳跃范围: 正向跳跃，且步长在 1 到 512 页 (即 2MB) 以内
        // 这完美覆盖了普通页和所有常见的大页 (Large Folio) 分配
        if (diff > 0 && diff <= 512) {
            st->seq_access_count++;
        }
    }
    st->last_mapping = mapping;
    st->last_index = index;

    // 2. 窗口结算：依然严格按照物理真实访存次数 (WINDOW_SIZE) 触发
    if (st->tick > 0 && (st->tick % WINDOW_SIZE) == 0) {
        struct feature_event *event = bpf_ringbuf_reserve(&feature_events, sizeof(*event), 0);
        if (event) {
            u64 events = st->irr_event_count; 
            u64 total = st->total_irr;
            
            event->window_id = st->current_window_id;
            event->seq_ratio_10000 = (st->seq_access_count * 10000) / WINDOW_SIZE;
            // 注意：因为采样率是 1/64，真实的 unique 页面需要等比例放大，但为了喂给 GMM，保持采样尺度即可
            event->unique_ratio_10000 = (st->unique_pages_count * 10000) / (WINDOW_SIZE >> 6);
            
            event->avg_irr = events > 0 ? (total / events) : 0;
            event->irr_0_1k_ratio = events > 0 ? (st->irr_0_1k_count * 10000) / events : 0;
            event->irr_1k_10k_ratio = events > 0 ? (st->irr_1k_10k_count * 10000) / events : 0;
            event->irr_10k_plus_ratio = events > 0 ? (st->irr_10k_plus_count * 10000) / events : 0;

            bpf_ringbuf_submit(event, 0);
        }
        
        st->current_window_id++;
        st->seq_access_count = 0;
        st->total_irr = 0;
        st->irr_event_count = 0;
        st->unique_pages_count = 0;
        st->irr_0_1k_count = 0;
        st->irr_1k_10k_count = 0;
        st->irr_10k_plus_count = 0;
    }

    // 3. 🛡️ 采样拦截器：98.4% 的请求在这里被无情丢弃！
    if ((st->tick & SAMPLING_MASK) != 0) {
        return; 
    }

    // ==========================================
    // 🐢 Slow Path (慢速路径)：只有 1/64 的样本进入哈希表
    // ==========================================
    u64 page_id = mapping ^ (index << 12);
    u32 win_id = st->current_window_id;
    struct page_track_info *info = bpf_map_lookup_elem(&page_tracking_map, &page_id);
    
    if (info) {
        // 缩放真实的时间跨度 (真实物理 IRR = 采样 IRR * 64)
        u64 irr = (st->tick - info->last_access_tick);
        st->total_irr += irr;
        st->irr_event_count++;

        if (irr < 1000) {
            st->irr_0_1k_count++;
        } else if (irr < 10000) {
            st->irr_1k_10k_count++;
        } else {
            st->irr_10k_plus_count++;
        }

        if (info->window_id != win_id) {
            st->unique_pages_count++;
        }
        
        info->last_access_tick = st->tick;
        info->window_id = win_id;
    } else {
        st->unique_pages_count++;
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
            bpf_cache_ext_list_move(main_list, folio, true);  
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