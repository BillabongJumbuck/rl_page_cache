#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// ==========================================
// 强化学习 Agent 控制通道 (5维动作空间)
// ==========================================
struct rl_params {
    __u32 p_access;    // 0:瞎子, 1:布尔, 2:计数
    __u32 p_direction; // 0:尾部(最老)开始, 1:头部(最新)开始
    __u32 p_threshold; // 免死阈值
    __u32 p_survival;  // 0:降级, 1:重排 (在cache_ext中通过留存实现)
    __u32 p_ghost;     // 0:无幽灵, 1:开启幽灵表
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_params);
} cml_params_map SEC(".maps");

// ==========================================
// 物理数据结构
// ==========================================
static u64 main_list;

// 页面元数据得分 (代替 p_access 记录)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4000000); 
    __type(key, __u64); // folio 地址
    __type(value, u8);  // 得分
} folio_meta_map SEC(".maps");

// 幽灵表 (Ghost Map)
// 注意：为了严格防碰撞，这里最好用 inode+index，但作为原型验证我们暂用 folio 地址
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000); 
    __type(key, __u64);
    __type(value, u8);
} ghost_map SEC(".maps");

static inline bool is_folio_relevant(struct folio *folio) {
    if (!folio || !folio->mapping || !folio->mapping->host) return false;
    return inode_in_watchlist(folio->mapping->host->i_ino);
}

// ------------------------------------------------------------------
// 钩子函数
// ------------------------------------------------------------------
s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    if (!is_folio_relevant(folio)) return;
    bpf_cache_ext_list_add(main_list, folio); 

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return;

    __u64 key = (__u64)folio;
    u8 initial_score = 0;

    // 如果开启幽灵表，且在幽灵表中找到，触发 Refault (高初始分)
    if (params->p_ghost == 1) {
        u8 *ghost = bpf_map_lookup_elem(&ghost_map, &key);
        if (ghost) {
            initial_score = 2; // 幽灵归来，给予 2 分特权
            bpf_map_delete_elem(&ghost_map, &key);
        }
    }
    bpf_map_update_elem(&folio_meta_map, &key, &initial_score, BPF_ANY);
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    if (!is_folio_relevant(folio)) return;

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params || params->p_access == 0) return; // 瞎子模式，直接返回

    __u64 key = (__u64)folio;
    u8 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (score) {
        if (params->p_access == 1) {
            *score = 1; // 布尔模式
        } else if (params->p_access == 2 && *score < 250) {
            *score += 1; // 计数模式
        }
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    if (!is_folio_relevant(folio)) return;
    __u64 key = (__u64)folio;
    bpf_map_delete_elem(&folio_meta_map, &key);
}

// ------------------------------------------------------------------
// 驱逐扫描迭代器
// ------------------------------------------------------------------
static int bpf_chameleon_evict_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return CACHE_EXT_EVICT_NODE;

    __u64 key = (__u64)a->folio;
    u8 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    u8 current_score = score ? *score : 0;

    // 【判断免死】
    if (current_score > params->p_threshold) {
        // 降级
        if (score) {
            if (params->p_access == 1) *score = 0;
            else if (params->p_access == 2 && *score > 0) *score -= 1;
        }
        return CACHE_EXT_CONTINUE_ITER; // 留存 (近似 p_survival = 1 / Requeue)
    }

    // 【斩杀】
    if (params->p_ghost == 1) {
        u8 dummy = 1;
        bpf_map_update_elem(&ghost_map, &key, &dummy, BPF_ANY);
    }
    return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    // __u32 param_key = 0;
    // struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    // 无论 p_direction 是什么，受限于底层框架，我们目前只能从最老的一端 (Tail) 开始扫描

    // 第一遍尽力扫描驱逐
    bpf_cache_ext_list_iterate(memcg, main_list, bpf_chameleon_evict_cb, eviction_ctx);
    
    // 防活锁兜底扫描
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