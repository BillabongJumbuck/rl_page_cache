#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

static __u64 mru_list;
#define MRU_PROTECTED_HEAD_FOLIOS 8

// =======================
// INIT
// =======================
s32 BPF_STRUCT_OPS_SLEEPABLE(mru_init, struct mem_cgroup *memcg)
{
    mru_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (mru_list == 0)
        return -1;

    return 0;
}

// =======================
// ADD
// =======================
void BPF_STRUCT_OPS(mru_folio_added, struct folio *folio)
{
    // 新页视为“最近使用”
    bpf_cache_ext_list_add(mru_list, folio);
}

// =======================
// ACCESS
// =======================
void BPF_STRUCT_OPS(mru_folio_accessed, struct folio *folio)
{
    // In single-thread mode, accurate recency tracking is more important than callback overhead.
    bpf_cache_ext_list_move(mru_list, folio, false);
}

// =======================
// REMOVE
// =======================
void BPF_STRUCT_OPS(mru_folio_evicted, struct folio *folio)
{
    bpf_cache_ext_list_del(folio);
}

// =======================
// MRU EVICTION LOGIC
// =======================
static int evict_mru_cb(int idx, struct cache_ext_list_node *node)
{
    if (!node || !node->folio)
        return CACHE_EXT_CONTINUE_ITER;

    struct folio *f = node->folio;

    // 基本安全检查（必须）
    if (!folio_test_uptodate(f))
        return CACHE_EXT_CONTINUE_ITER;

    if (!folio_test_lru(f))
        return CACHE_EXT_CONTINUE_ITER;

    if (folio_test_dirty(f) ||
        folio_test_writeback(f) ||
        folio_test_locked(f))
        return CACHE_EXT_CONTINUE_ITER;

    // Keep a small head protection zone to avoid evicting just-touched pages.
    if (idx < MRU_PROTECTED_HEAD_FOLIOS) {
        return CACHE_EXT_CONTINUE_ITER;
    }

    // 过了保护区，才是真正安全的 MRU 淘汰候选者
    return CACHE_EXT_EVICT_NODE;
}

// =======================
// EVICT ENTRY
// =======================
void BPF_STRUCT_OPS(mru_evict_folios,
                   struct cache_ext_eviction_ctx *eviction_ctx,
                   struct mem_cgroup *memcg)
{
    bpf_cache_ext_list_iterate(memcg, mru_list,
                              evict_mru_cb, eviction_ctx);
}

// =======================
// OPS REGISTER
// =======================
SEC(".struct_ops.link")
struct cache_ext_ops mru_ops = {
    .init = (void *)mru_init,
    .evict_folios = (void *)mru_evict_folios,
    .folio_accessed = (void *)mru_folio_accessed,
    .folio_evicted = (void *)mru_folio_evicted,
    .folio_added = (void *)mru_folio_added,
};