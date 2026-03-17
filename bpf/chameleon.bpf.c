#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// ==========================================
// 【优化 1】直接使用 BPF 全局变量，彻底干掉 cml_params_map！
// 用户态直接修改 skel->bss->current_params 即可，0 查表开销！
// ==========================================
struct rl_params {
    __u32 p_access;    
    __u32 p_direction; 
    __u32 p_threshold; 
    __u32 p_survival;  
    __u32 p_ghost;     
};
struct rl_params current_params = {0, 0, 0, 0, 0}; // 存放在 .bss 段

static u64 main_list;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4000000); 
    __type(key, __u64); 
    __type(value, u8);  
} folio_meta_map SEC(".maps");

// 【优化 2】幽灵表改为 LRU_HASH，防写满崩溃，无需手动管理淘汰
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 1000000); 
    __type(key, __u64);
    __type(value, u8);
} ghost_map SEC(".maps");

static inline bool is_folio_relevant(struct folio *folio) {
    if (!folio || !folio->mapping || !folio->mapping->host) return false;
    return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    if (!is_folio_relevant(folio)) return;
    bpf_cache_ext_list_add(main_list, folio); 

    __u64 key = (__u64)folio;
    u8 initial_score = 0;

    // 全局变量就像本地变量一样直接读！
    if (current_params.p_ghost == 1) {
        u8 *ghost = bpf_map_lookup_elem(&ghost_map, &key);
        if (ghost) {
            initial_score = 2; 
            // LRU HASH 其实不删也行，但删掉能腾位置
            bpf_map_delete_elem(&ghost_map, &key); 
        }
    }
    bpf_map_update_elem(&folio_meta_map, &key, &initial_score, BPF_ANY);
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    // 【优化 3：短路防御】直接读全局配置，如果是瞎子，直接滚！0 开销。
    if (current_params.p_access == 0) return; 

    __u64 key = (__u64)folio;
    // 【极致优化】：先查元数据！元数据里没有，就说明绝对不是我们要管的目录，直接 return！
    // 这样完美省去了 folio_mapping_host 的指针追逐和 inode_in_watchlist 的查表开销！
    u8 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!score) return; 

    if (current_params.p_access == 1) {
        *score = 1; 
    } else if (current_params.p_access == 2 && *score < 250) {
        *score += 1; 
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    // 同样的短路优化，直接删，内核会自动忽略不存在的 key，极其省事！
    __u64 key = (__u64)folio;
    bpf_map_delete_elem(&folio_meta_map, &key);
}

static int bpf_chameleon_evict_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;

    __u64 key = (__u64)a->folio;
    u8 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    u8 current_score = score ? *score : 0;

    // 直接使用 current_params，零查表开销
    if (current_score > current_params.p_threshold) {
        if (score) {
            if (current_params.p_access == 1) *score = 0;
            else if (current_params.p_access == 2 && *score > 0) *score -= 1;
        }
        return CACHE_EXT_CONTINUE_ITER; 
    }

    if (current_params.p_ghost == 1) {
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