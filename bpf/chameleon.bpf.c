#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

// ==========================================
// 调试开关：设为 1 开启详细日志与计数器，设为 0 关闭
// ==========================================
#define CML_DEBUG 0

// ==========================================
// 特性开关：设为 1 开启 LFU 编译，设为 0 彻底剔除 LFU 开销
// ==========================================
#define ENABLE_LFU 0

enum policy_type {
    POLICY_LRU = 0,
    POLICY_MRU = 1,
#if ENABLE_LFU
    POLICY_LFU = 2, // 替换了原本的 SIEVE
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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 200000); 
    __type(key, __u64);
    __type(value, u8); 
} ghost_map SEC(".maps"); // 保留声明，作 RL Regret 通信的占位符

#if ENABLE_LFU
// 专用于 LFU 策略的频次表 (仅在编译宏开启时存在)
struct {
    __uint(type, BPF_MAP_TYPE_HASH); 
    __uint(max_entries, 200000); // 根据实际环境调整，建议与缓存页数一致
    __type(key, __u64);          // folio 的内核地址
    __type(value, u8);           // 访问频次 0~255
} lfu_freq_map SEC(".maps");
#endif

#if CML_DEBUG
// 调试计数器仅在 DEBUG 模式下分配内存
static u32 mru_debug_count = 0;
static u32 init_cnt = 0;
static u32 add_cnt = 0;
static u32 acc_cnt = 0;
static u32 evict_trigger_cnt = 0;
static u32 evict_cnt = 0;
#endif

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
#if CML_DEBUG
    if (__sync_fetch_and_add(&init_cnt, 1) < 5) {
        bpf_printk("[CML-RADAR] INIT called!\n");
    }
#endif
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
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

    if (policy == POLICY_LRU) bpf_cache_ext_list_add_tail(main_list, folio);
    else bpf_cache_ext_list_add(main_list, folio);

#if ENABLE_LFU
    if (policy == POLICY_LFU) {
        u64 addr = (u64)folio;
        u8 init_freq = 1; // 新页面的初始频次为 1
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
                // 饱和累加，最高 255
                if (*freq < 255) (*freq)++;
            } else {
                // 容错处理：如果在 Map 中丢失，重新插入
                u8 val = 1;
                bpf_map_update_elem(&lfu_freq_map, &addr, &val, BPF_ANY);
            }
            // 发生访问后，将其视作较热状态，可以借用 LRU 的移动逻辑避免被过早扫描
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

#if ENABLE_LFU
    // 无脑清理：只要开启了宏，页面被驱逐时就尝试清理频率表，防止内存泄漏
    u64 addr = (u64)folio;
    bpf_map_delete_elem(&lfu_freq_map, &addr);
#endif

    bpf_cache_ext_list_del(folio);
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

    // 如果页面的硬件 Access 位被置起，说明极热，补充分数并保护
    if (bpf_folio_check_referenced(a->folio) > 0) {
        if (freq && *freq < 255) (*freq)++;
        return CACHE_EXT_CONTINUE_ITER;
    }

    u8 val = freq ? *freq : 0;

    // LFU-Clock 核心逻辑：
    // 如果频次极低 (<=1)，立刻执行驱逐
    if (val <= 1) {
        return CACHE_EXT_EVICT_NODE;
    } 
    // 搭车老化机制：频次减半，保留在内存中给它第二次机会
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