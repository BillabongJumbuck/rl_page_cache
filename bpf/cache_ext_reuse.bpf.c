// cache_ext_reuse.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// 由用户态注入的目标 cgroup ID
const volatile __u64 target_cgroup_id = 0;

struct reuse_stats {
    __u64 count;
    __u64 sum;
    __u64 sum_sq;
    __u64 global_seq;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2000000);
    __type(key, __u64);
    __type(value, __u64);
} folio_history_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct reuse_stats);
} global_stats_map SEC(".maps");

SEC("fentry/folio_mark_accessed")
int BPF_PROG(on_folio_accessed, struct folio *folio)
{
    // 基于当前进程的 cgroup ID 进行过滤
    if (bpf_get_current_cgroup_id() != target_cgroup_id) {
        return 0;
    }

    __u64 folio_ptr = (__u64)folio;
    __u32 stat_key = 0;
    
    struct reuse_stats *stats = bpf_map_lookup_elem(&global_stats_map, &stat_key);
    if (!stats) return 0;

    __u64 current_seq = __sync_fetch_and_add(&stats->global_seq, 1);
    __u64 *last_seq_ptr = bpf_map_lookup_elem(&folio_history_map, &folio_ptr);
    
    if (last_seq_ptr) {
        __u64 distance = current_seq - *last_seq_ptr;
        *last_seq_ptr = current_seq;

        __sync_fetch_and_add(&stats->count, 1);
        __sync_fetch_and_add(&stats->sum, distance);
        __sync_fetch_and_add(&stats->sum_sq, distance * distance); 
    } else {
        bpf_map_update_elem(&folio_history_map, &folio_ptr, &current_seq, BPF_ANY);
    }
    return 0;
}

SEC("fentry/filemap_remove_folio") 
int BPF_PROG(on_folio_removed, struct folio *folio)
{
    // 注意：驱逐时不要检查 cgroup_id！因为 kswapd 回收时 cgroup 不匹配
    // 直接尝试删除，反正 Hash Map 删除不存在的 Key 是安全的 O(1) 操作
    __u64 folio_ptr = (__u64)folio;
    bpf_map_delete_elem(&folio_history_map, &folio_ptr);
    return 0;
}