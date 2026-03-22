#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

// ==========================================
// 🌟 1. 动作空间与策略定义
// ==========================================
enum policy_type {
    POLICY_LRU   = 0,
    POLICY_SIEVE = 1,
    POLICY_MRU   = 2,
    POLICY_LFU   = 3,
};

struct rl_params {
    __u32 active_policy; // 当前由 RL 智能体激活的专家策略
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_params);
} cml_params_map SEC(".maps");

// ==========================================
// 🌟 2. 宏观统计与“追责账本”
// ==========================================
struct macro_stats {
    __s64 wss;             // 总工作集大小
    __s64 score_counts[11]; // 【精妙复用】：前 4 个槽位被复用为 4 个策略的遗憾惩罚 (Regret) 计数器
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct macro_stats);
} cml_stats_map SEC(".maps");

// 废弃双子星，回归统一的单链表
static u64 main_list; 

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 200000); 
    __type(key, __u64); 
    __type(value, u32); // 记录页面分数 (SIEVE=1, LFU=1~10)
} folio_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 200000); 
    __type(key, __u64);
    __type(value, u8); // 记录是被哪个 policy_id 杀死的 (0~3)
} ghost_map SEC(".maps");


s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    bpf_cache_ext_list_add(main_list, folio); 

    __u64 key = (__u64)folio;
    u32 initial_score = 0; // 无论是哪个策略，这个 0 必须写进去！

    u8 *killer_policy = bpf_map_lookup_elem(&ghost_map, &key);
    if (killer_policy) {
        u32 stat_key = 0;
        struct macro_stats *stats = bpf_map_lookup_elem(&cml_stats_map, &stat_key);
        if (stats && *killer_policy <= POLICY_LFU) {
            __sync_fetch_and_add(&stats->score_counts[*killer_policy], 1);
        }
        bpf_map_delete_elem(&ghost_map, &key);
    }

    // 【关键】：强制在 folio_meta_map 注册身份，代表它正式加入了缓存链表
    bpf_map_update_elem(&folio_meta_map, &key, &initial_score, BPF_ANY);

    u32 stat_key = 0;
    struct macro_stats *stats = bpf_map_lookup_elem(&cml_stats_map, &stat_key);
    if (stats) {
        __sync_fetch_and_add(&stats->wss, 1);
    }
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return;

    __u64 key = (__u64)folio;
    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    
    // 【生死防线】：如果没有 score，说明这个 folio 根本不在我们的 main_list 里！
    // 此时绝对不能执行后面的 bpf_cache_ext_list_move，必须立刻 return！
    if (!score) return; 

    // 安全通过防线，开始策略路由
    switch (params->active_policy) {
        case POLICY_LRU:
        case POLICY_MRU:
            bpf_cache_ext_list_move(main_list, folio, false); // 移到表头
            break;

        case POLICY_SIEVE:
            *score = 1; // 仅标记已访问过 (Visited)
            break;

        case POLICY_LFU:
            if (*score < 10) {
                __sync_fetch_and_add(score, 1); // 原子累加频次
            }
            break;
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    __u64 key = (__u64)folio;
    bpf_map_delete_elem(&folio_meta_map, &key);

    // 【凶手印记】：页面真正死亡时，记录当前是谁执政的
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (params) {
        u8 policy = params->active_policy;
        bpf_map_update_elem(&ghost_map, &key, &policy, BPF_ANY);
    }

    u32 stat_key = 0;
    struct macro_stats *stats = bpf_map_lookup_elem(&cml_stats_map, &stat_key);
    if (stats) {
        __sync_fetch_and_add(&stats->wss, -1);
    }
}

// 评分回调：用于 LFU 近似采样
static s64 lfu_score_cb(struct cache_ext_list_node *a) {
    __u64 key = (__u64)a->folio;
    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    int hw_refs = bpf_folio_check_referenced(a->folio);
    
    s64 total = hw_refs;
    if (score) {
        __sync_fetch_and_add(score, hw_refs); // 把底层偷偷访问的次数补充分数
        total += *score;
    }
    return total;
}

// LRU 专用：仁慈，给第二次机会
static int evict_lru_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;

    int hw_refs = bpf_folio_check_referenced(a->folio); 
    if (hw_refs > 0) return CACHE_EXT_CONTINUE_ITER; 
    
    return CACHE_EXT_EVICT_NODE;
}

// MRU 专用：冷血，只要干净就直接杀
static int evict_mru_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;

    // 【关键】：MRU 不检查硬件访问位，强行清空硬件状态并驱逐！
    bpf_folio_check_referenced(a->folio); // 只是调用一下以清除 PTE 上的硬件 A 位，防止残留
    
    return CACHE_EXT_EVICT_NODE;
}


void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    u32 policy = params ? params->active_policy : POLICY_LRU;

    // 【数据面分流】：调度对应的底层 C 执行器
    if (policy == POLICY_LRU) {
        bpf_cache_ext_list_iterate(memcg, main_list, evict_lru_cb, eviction_ctx);
    } 
    else if (policy == POLICY_MRU) {
        bpf_cache_ext_list_iterate_reverse(memcg, main_list, evict_mru_cb, eviction_ctx);
    }
    else if (policy == POLICY_SIEVE) {
        // 使用预处理宏，强制编译器展开循环。数字 32 是内核数组的最大容量。
        #pragma unroll
        for (int i = 0; i < 32; i++) {
            // 如果已经满足了内核的需求，提前结束展开后的执行流
            if (eviction_ctx->nr_folios_to_evict >= eviction_ctx->request_nr_folios_to_evict) {
                break;
            }

            struct folio *victim = bpf_cache_ext_sieve_get_victim(memcg, main_list);
            if (!victim) {
                break; // 找不到冷数据了，赶紧撤
            }

            // 此时的 i 在编译后是一个绝对常数，Verifier 不会再抱怨了
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