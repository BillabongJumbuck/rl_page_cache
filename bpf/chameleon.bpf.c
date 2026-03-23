#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

enum policy_type {
    POLICY_LRU   = 0,
    POLICY_SIEVE = 1,
    POLICY_MRU   = 2,
    POLICY_LFU   = 3,
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000); 
    __type(key, __u64); 
    __type(value, u32); 
} folio_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 200000); 
    __type(key, __u64);
    __type(value, u8); 
} ghost_map SEC(".maps");

// 调试计数器
static u32 mru_debug_count = 0;
static u32 init_cnt = 0;
static u32 add_cnt = 0;
static u32 acc_cnt = 0;
static u32 evict_trigger_cnt = 0; // 整个驱逐批次的触发雷达
static u32 evict_cnt = 0; // 被驱逐页面的雷达

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    if (__sync_fetch_and_add(&init_cnt, 1) < 5) {
        bpf_printk("[CML-RADAR] INIT called!\n");
    }
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = (u32)(pid_tgid >> 32);

    // 稍微降低频率，每 100 个页面打一次，带上 PID
    if ((__sync_fetch_and_add(&add_cnt, 1) % 100) == 0) {
        bpf_printk("[CML-ADD] pid:%u folio:%llx\n", pid, (u64)folio);
    }

    // 维持原有逻辑
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    u32 policy = params ? params->active_policy : POLICY_LRU;

    if (policy == POLICY_LRU) bpf_cache_ext_list_add_tail(main_list, folio);
    else bpf_cache_ext_list_add(main_list, folio);

    __u64 key = (__u64)folio;
    u32 initial_score = 0; 
    bpf_map_update_elem(&folio_meta_map, &key, &initial_score, BPF_ANY);
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    if (__sync_fetch_and_add(&acc_cnt, 1) < 5) {
        bpf_printk("[CML-RADAR] ACCESSED called!\n");
    }

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return;

    __u64 key = (__u64)folio;
    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!score) return; 

    // 【算法基石 2】：热数据复位
    switch (params->active_policy) {
        case POLICY_LRU:
            bpf_cache_ext_list_move(main_list, folio, true);  // 移到 Tail
            break;
        case POLICY_MRU:
            bpf_cache_ext_list_move(main_list, folio, false); // 移到 Head
            break;
        case POLICY_SIEVE:
            *score = 1; 
            break;
        case POLICY_LFU:
            if (*score < 10) __sync_fetch_and_add(score, 1); 
            break;
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u64 key = (__u64)folio;

    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!score) {
        return; // 静默忽略，保平安
    }
    
    // 如果有页面被回收（不论是被谁回收），看看能不能抓到
    if ((__sync_fetch_and_add(&evict_cnt, 1) % 100) == 0) {
        bpf_printk("[CML-EVICT-NOTIFY] folio:%llx (by pid:%d)\n", (u64)folio, pid);
    }

    bpf_cache_ext_list_del(folio);

    bpf_map_delete_elem(&folio_meta_map, &key);
}

static s64 lfu_score_cb(struct cache_ext_list_node *a) {
    __u64 key = (__u64)a->folio;
    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    int hw_refs = bpf_folio_check_referenced(a->folio);
    s64 total = hw_refs;
    if (score) {
        __sync_fetch_and_add(score, hw_refs); 
        total += *score;
    }
    return total;
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

// 深度调试版 MRU 驱逐
static int evict_mru_cb(int idx, struct cache_ext_list_node *a) {
    if (!a || !a->folio) return CACHE_EXT_CONTINUE_ITER;

    bool uptodate = folio_test_uptodate(a->folio);
    bool lru = folio_test_lru(a->folio);
    bool dirty = folio_test_dirty(a->folio);
    bool writeback = folio_test_writeback(a->folio);
    bool locked = folio_test_locked(a->folio);
    int refs = bpf_folio_check_referenced(a->folio);

    int action = CACHE_EXT_EVICT_NODE;
    int reason = 0; 

    // 记录被跳过的具体原因 (优先级从高到低)
    if (locked) reason = 1;
    else if (writeback) reason = 2;
    else if (dirty) reason = 3;
    else if (!uptodate) reason = 4;
    else if (!lru) reason = 5;

    if (reason > 0) {
        action = CACHE_EXT_CONTINUE_ITER;
    }

    // 只打印每次驱逐的前 20 个页面的详细状态
    if (__sync_fetch_and_add(&mru_debug_count, 1) < 20) {
        bpf_printk("[MRU-DBG] idx:%d up:%d lru:%d dir:%d wb:%d lck:%d\n",
                   idx, uptodate, lru, dirty, writeback, locked);
        bpf_printk("[MRU-DBG-2] refs:%d action:%d reason:%d\n",
                   refs, action, reason);
    }

    return action;
}

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    __u32 param_key = 0;

    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    u32 policy = params ? params->active_policy : POLICY_LRU;

    if (__sync_fetch_and_add(&evict_trigger_cnt, 1) < 50) {
        bpf_printk("[CML-RADAR] EVICT TRIGGERED! Policy: %d, Req: %d\n", 
                   policy, eviction_ctx->request_nr_folios_to_evict);
    }

    // 每次触发驱逐，重置 MRU 的节点级调试计数器，确保能看到最新的前 20 个页面
    mru_debug_count = 0;

    if (policy == POLICY_LRU) {
        bpf_cache_ext_list_iterate(memcg, main_list, evict_lru_cb, eviction_ctx);
    } 
    else if (policy == POLICY_MRU) {
        bpf_cache_ext_list_iterate(memcg, main_list, evict_mru_cb, eviction_ctx);
        
        // 打印单次驱逐的最终战果
        bpf_printk("[MRU-RESULT] req:%d evicted:%d\n", 
                   eviction_ctx->request_nr_folios_to_evict, 
                   eviction_ctx->nr_folios_to_evict);
    }
    else if (policy == POLICY_SIEVE) {
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            if (eviction_ctx->nr_folios_to_evict >= eviction_ctx->request_nr_folios_to_evict) break;
            struct folio *victim = bpf_cache_ext_sieve_get_victim(memcg, main_list);
            if (!victim) break; 
            eviction_ctx->folios_to_evict[i] = victim;
            eviction_ctx->nr_folios_to_evict = i + 1;
        }
    }
    else if (policy == POLICY_LFU) {
        struct sampling_options opts = { .sample_size = 32 };
        bpf_cache_ext_list_sample(memcg, main_list, lfu_score_cb, &opts, eviction_ctx);
    }
}

SEC(".struct_ops.link")
struct cache_ext_ops chameleon_ops = {
    .init = (void *)chameleon_init,
    .evict_folios = (void *)chameleon_evict_folios,
    .folio_accessed = (void *)chameleon_folio_accessed,
    .folio_evicted = (void *)chameleon_folio_evicted,
    .folio_added = (void *)chameleon_folio_added,
};