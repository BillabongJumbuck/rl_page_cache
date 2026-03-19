#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

// 【重定义动作空间】与 Python 端 5 维动作保持物理结构对齐
struct rl_params {
    __u32 p_access;         // 0=关闭, 1=二元, 2=累加计分
    __u32 p_protected_pct;  // 热链表占比百分比 (原 p_direction，0~100)
    __u32 p_promote_thresh; // 晋升门槛 (原 p_threshold)
    __u32 p_ghost;          // 幽灵表开关 (0=关闭, 1=开启)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_params);
} cml_params_map SEC(".maps");

// ==========================================
// 🌟 终极优化：内核态就地聚合的宏观直方图
// ==========================================
struct macro_stats {
    __s64 wss;             // 总工作集大小 (页数)
    __s64 score_counts[11]; // 分数直方图 (0 分 到 10 分)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct macro_stats);
} cml_stats_map SEC(".maps");


// 【双子星架构】
static u64 probation_list; // 冷链表 (考察期，新页面的出生地)
static u64 protected_list; // 热链表 (保护区，神圣不可侵犯)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4000000); 
    __type(key, __u64); 
    __type(value, u32); // 支持内核原子操作
} folio_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 1000000); 
    __type(key, __u64);
    __type(value, u8);
} ghost_map SEC(".maps");


s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    probation_list = bpf_cache_ext_ds_registry_new_list(memcg);
    protected_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (probation_list == 0 || protected_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    // 1. 所有新数据，无脑进入冷链表 (Probation List)
    bpf_cache_ext_list_add(probation_list, folio); 

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return;

    __u64 key = (__u64)folio;
    u32 initial_score = 0;

    // 2. 幽灵判定
    if (params->p_ghost == 1) {
        u8 *ghost = bpf_map_lookup_elem(&ghost_map, &key);
        if (ghost) {
            initial_score = params->p_promote_thresh ? params->p_promote_thresh : 1; 
            bpf_map_delete_elem(&ghost_map, &key); 
        }
    }
    bpf_map_update_elem(&folio_meta_map, &key, &initial_score, BPF_ANY);

    // 3. 【聚合更新】账本记录：总页数+1，对应分数桶+1
    u32 stat_key = 0;
    struct macro_stats *stats = bpf_map_lookup_elem(&cml_stats_map, &stat_key);
    if (stats) {
        __sync_fetch_and_add(&stats->wss, 1);
        u32 safe_idx = initial_score > 10 ? 10 : initial_score;
        __sync_fetch_and_add(&stats->score_counts[safe_idx], 1);
    }
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params || params->p_access == 0) return;

    __u64 key = (__u64)folio;
    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!score) return; 

    u32 old_score = 0;
    u32 new_score = 0;

    // 1. 带有安全钳制（Clamp）的原子加分
    if (params->p_access > 0) {
        old_score = __sync_fetch_and_add(score, 1);
        if (old_score >= 10) {
            // 如果本来就已经满了，加完之后把它拉回 10
            __sync_fetch_and_add(score, -1);
            old_score = 10;
            new_score = 10;
        } else {
            new_score = old_score + 1;
        }
    } else {
        old_score = *score;
        new_score = old_score;
    }

    // 2. 【聚合更新】账本记录：老分数桶-1，新分数桶+1
    if (old_score != new_score) {
        u32 stat_key = 0;
        struct macro_stats *stats = bpf_map_lookup_elem(&cml_stats_map, &stat_key);
        if (stats) {
            __sync_fetch_and_add(&stats->score_counts[old_score], -1);
            __sync_fetch_and_add(&stats->score_counts[new_score], 1);
        }
    }

    // 3. 绝对并发安全的晋升判定！
    if (new_score == params->p_promote_thresh && old_score < new_score) {
        bpf_cache_ext_list_move(protected_list, folio, false);
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    __u64 key = (__u64)folio;
    u32 *score_ptr = bpf_map_lookup_elem(&folio_meta_map, &key);
    u32 final_score = score_ptr ? *score_ptr : 0;
    
    bpf_map_delete_elem(&folio_meta_map, &key);

    // 【聚合更新】账本记录：页面死亡，销户
    u32 stat_key = 0;
    struct macro_stats *stats = bpf_map_lookup_elem(&cml_stats_map, &stat_key);
    if (stats) {
        __sync_fetch_and_add(&stats->wss, -1);
        u32 safe_idx = final_score > 10 ? 10 : final_score;
        __sync_fetch_and_add(&stats->score_counts[safe_idx], -1);
    }
}

static int bpf_chameleon_evict_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return CACHE_EXT_EVICT_NODE;

    __u64 key = (__u64)a->folio;
    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);

    // 【上帝之眼降临】：主动去查硬件 PTE 是否被偷偷访问过
    // 注意：如果是降级方案，这里应该是 hw_refs = 0; 或者是你之前修复的带局部变量的版本
    int hw_refs = bpf_folio_check_referenced(a->folio); 
    
    if (hw_refs > 0) {
        u32 old_score = 0;
        u32 new_score = 0;

        if (score) {
            old_score = *score;
            __sync_fetch_and_add(score, hw_refs); 
            new_score = old_score + hw_refs;
            if (new_score > 10) {
                *score = 10; 
                new_score = 10;
            }
        } else {
            u32 init_score = hw_refs > 10 ? 10 : hw_refs;
            bpf_map_update_elem(&folio_meta_map, &key, &init_score, BPF_ANY);
            new_score = init_score;
        }

        // 【聚合同步】处理扫描时的跨桶跳跃
        u32 stat_key = 0;
        struct macro_stats *stats = bpf_map_lookup_elem(&cml_stats_map, &stat_key);
        if (stats) {
            u32 safe_old = old_score > 10 ? 10 : old_score;
            u32 safe_new = new_score > 10 ? 10 : new_score;
            if (score && safe_old != new_score) {
                __sync_fetch_and_add(&stats->score_counts[safe_old], -1);
                __sync_fetch_and_add(&stats->score_counts[safe_new], 1);
            } else if (!score) {
                // 原来不存在，被 PTE 访问抓回来了，算作新生页面
                __sync_fetch_and_add(&stats->wss, 1);
                __sync_fetch_and_add(&stats->score_counts[safe_new], 1);
            }
        }
        return CACHE_EXT_CONTINUE_ITER; 
    }

    if (params->p_ghost == 1) {
        u8 dummy = 1;
        bpf_map_update_elem(&ghost_map, &key, &dummy, BPF_ANY);
    }
    return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    
    if (params) {
        u64 ratio = params->p_protected_pct;
        if (ratio == 0) ratio = 30;
        else if (ratio == 1) ratio = 70;
        else if (ratio > 100) ratio = 50; 

        u64 prob_len = bpf_cache_ext_list_length(memcg, probation_list);
        u64 prot_len = bpf_cache_ext_list_length(memcg, protected_list);
        u64 total = prob_len + prot_len;

        if (total > 0) {
            u64 max_prot = (total * ratio) / 100;
            if (prot_len > max_prot) {
                u32 batch = prot_len - max_prot;
                if (batch > 1024) batch = 1024;
                bpf_cache_ext_list_demote_batch(memcg, protected_list, probation_list, batch);
            }
        }
    }

    bpf_cache_ext_list_iterate(memcg, probation_list, bpf_chameleon_evict_cb, eviction_ctx);
    
    if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
        bpf_cache_ext_list_iterate(memcg, protected_list, bpf_chameleon_evict_cb, eviction_ctx);
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