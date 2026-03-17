#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// 拦截页面访问：空操作
SEC("fentry/folio_mark_accessed")
int BPF_PROG(on_folio_accessed, struct folio *folio)
{
    // 直接返回，不查 Map，不加锁，不自增
    return 0;
}

// 拦截页面驱逐：空操作
SEC("fentry/filemap_remove_folio") 
int BPF_PROG(on_folio_removed, struct folio *folio)
{
    return 0;
}