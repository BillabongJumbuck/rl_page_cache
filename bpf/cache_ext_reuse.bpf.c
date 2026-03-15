#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

// 传给用户态的统计数据
struct reuse_stats {
    __u64 count;
    __u64 sum;
    __u64 sum_sq;
    __u64 global_seq;
};

// 记录页面上次访问序号
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 2000000);
    __type(key, __u64);
    __type(value, __u64);
} folio_history_map SEC(".maps");

// 全局统计结果
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct reuse_stats);
} global_stats_map SEC(".maps");

static inline bool is_folio_relevant(struct folio *folio) {
    if (!folio || !folio->mapping || !folio->mapping->host)
        return false;
    return inode_in_watchlist(folio->mapping->host->i_ino);
}

// 拦截页面访问
SEC("fentry/folio_mark_accessed")
int BPF_PROG(on_folio_accessed, struct folio *folio)
{
    if (!is_folio_relevant(folio)) return 0;

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

// 拦截页面驱逐 (防止内存泄漏)
SEC("fentry/filemap_remove_folio") 
int BPF_PROG(on_folio_removed, struct folio *folio)
{
    if (!is_folio_relevant(folio)) return 0;

    __u64 folio_ptr = (__u64)folio;
    bpf_map_delete_elem(&folio_history_map, &folio_ptr);
    return 0;
}