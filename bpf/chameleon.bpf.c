#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 main_list;

// 必须保留 init，否则框架无法运行
s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    return main_list == 0 ? -1 : 0;
}

// 极其关键：所有数据路径函数直接 return
void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    // 仅仅保持 list 运转，不做任何逻辑判断和 Map 操作
    bpf_cache_ext_list_add(main_list, folio); 
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    return; // 空钩子
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    return; // 空钩子
}

// 模拟最原始的 FIFO/LRU 行为，不做分值判断
static int bpf_chameleon_evict_cb(int idx, struct cache_ext_list_node *a) {
    // 基础检查还是需要的，防止把还没写完的页面踢掉导致系统崩溃
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;

    return CACHE_EXT_EVICT_NODE; // 直接踢出
}

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    // 只跑一轮纯粹的迭代
    bpf_cache_ext_list_iterate(memcg, main_list, bpf_chameleon_evict_cb, eviction_ctx);
}

SEC(".struct_ops.link")
struct cache_ext_ops chameleon_ops = {
    .init = (void *)chameleon_init,
    .evict_folios = (void *)chameleon_evict_folios,
    .folio_accessed = (void *)chameleon_folio_accessed,
    .folio_evicted = (void *)chameleon_folio_evicted,
    .folio_added = (void *)chameleon_folio_added,
};