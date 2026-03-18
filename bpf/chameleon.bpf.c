// chameleon.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

struct rl_params {
    __u32 p_access;    
    __u32 p_direction; 
    __u32 p_threshold; 
    __u32 p_survival;  
    __u32 p_ghost;     
};

// 【恢复】使用 Array Map，供 Python 大脑跨进程写入策略
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_params);
} cml_params_map SEC(".maps");

static u64 main_list;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4000000); 
    __type(key, __u64); 
    __type(value, u8);  
} folio_meta_map SEC(".maps");

// 【优化保留】使用 LRU HASH 防止幽灵表写满崩溃
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 1000000); 
    __type(key, __u64);
    __type(value, u8);
} ghost_map SEC(".maps");

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    bpf_cache_ext_list_add(main_list, folio); 

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return;

    __u64 key = (__u64)folio;
    u8 initial_score = 0;

    if (params->p_ghost == 1) {
        u8 *ghost = bpf_map_lookup_elem(&ghost_map, &key);
        if (ghost) {
            initial_score = 2; 
            bpf_map_delete_elem(&ghost_map, &key); 
        }
    }
    bpf_map_update_elem(&folio_meta_map, &key, &initial_score, BPF_ANY);
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params || params->p_access == 0) return;

    __u64 key = (__u64)folio;
    // 【优化保留：短路查表】如果 folio_meta_map 里没有，说明不是我们监控的文件，直接滚！省去极其耗时的底层指针查找！
    u8 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!score) return; 

    if (params->p_access == 1) {
        *score = 1; 
    } else if (params->p_access == 2 && *score < 250) {
        *score += 1; 
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    __u64 key = (__u64)folio;
    bpf_map_delete_elem(&folio_meta_map, &key);
}

static int bpf_chameleon_evict_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return CACHE_EXT_EVICT_NODE;

    __u64 key = (__u64)a->folio;
    u8 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    u8 current_score = score ? *score : 0;

    if (current_score > params->p_threshold) {
        if (score) {
            if (params->p_access == 1) *score = 0;
            else if (params->p_access == 2 && *score > 0) *score -= 1;
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
    bpf_cache_ext_list_iterate(memcg, main_list, bpf_chameleon_evict_cb, eviction_ctx);
    if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
        bpf_cache_ext_list_iterate(memcg, main_list, bpf_chameleon_evict_cb, eviction_ctx);
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