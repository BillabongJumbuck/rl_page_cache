// chameleon.bpf.c - 基于访问流隔离 streaming cache pollution 的 BPF 实现
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

#define DATA_COLLECT 1
#define DEPLOY       1

#define WINDOW_SIZE 64
#define SAMPLING_MASK 0x1F

#define STREAM_SEQ_ENTER 8200
#define STREAM_SEQ_KEEP 6800
#define STREAM_REVISIT_ENTER 600
#define STREAM_REVISIT_KEEP 1200
#define STREAM_REVISIT_BACKOFF 2200
#define STREAM_DIRTY_ENTER 150
#define STREAM_DIRTY_KEEP 400
#define STREAM_DIRTY_HARD 900
#define DIRTY_COOLDOWN_WINDOWS 6
#define HOT_BACKOFF_STREAK 2
#define WEAK_POLLUTION_STREAK 3
#define STREAM_BACKOFF_WINDOWS 8
#define MIN_STREAM_FILE_PAGES 512
#define POLLUTION_MOVE_SAMPLE_MASK 0x3f
#define POLLUTION_PROTECTED_HEAD_FOLIOS 8

#define S_IFMT 00170000
#define S_IFREG 0100000

enum stream_state {
    STREAM_NORMAL = 0,
    STREAM_POLLUTION = 1,
};

static u64 main_list;

struct debug_stats {
    u64 sampled_accesses;
    u64 stream_windows;
    u64 pollution_windows;
    u64 normal_windows;
    u64 switch_to_pollution;
    u64 switch_to_normal;

    u64 list_adds;
    u64 list_moves;
    u64 list_dels;
    u64 bypass_non_file;
    u64 bypass_small_file;
    u64 bypass_dirty_state;
    u64 bypass_not_readmostly;
    u64 bypass_hot;
    u64 backoff_hot_reuse;
    u64 backoff_weak_pollution;

    u64 evict_rounds;
    u64 evict_cb_calls;
    u64 evict_candidates;
    u64 skip_locked;
    u64 skip_writeback;
    u64 skip_dirty;
    u64 skip_not_uptodate;
    u64 skip_not_lru;
    u64 skip_unevictable;

    u64 ref_checks;
    u64 ref_positive;

    u64 list_len_last;
    u64 list_len_max;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct debug_stats);
} debug_stats_map SEC(".maps");

static __always_inline struct debug_stats *get_dbg_stats(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&debug_stats_map, &key);
}

#if DATA_COLLECT
struct feature_event {
    u64 timestamp_ns;
    u64 mapping;
    u64 last_index;
    u64 mapping_nrpages;
    u32 tgid;
    u32 window_id;
    u32 sample_count;
    u32 seq_ratio_10000;
    u32 revisit_ratio_10000;
    u32 dirty_ratio_10000;
    u32 smoothed_seq_10000;
    u32 smoothed_revisit_10000;
    u32 smoothed_dirty_10000;
    u32 old_state;
    u32 new_state;
    u32 cooldown_windows;
    u32 hot_streak;
    u32 weak_pollution_streak;
    u32 stream_candidate;
    u32 hot_backoff;
    u32 weak_backoff;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} feature_events SEC(".maps");
#endif

struct page_key {
    u64 mapping;
    u64 index;
};

struct page_track_info {
    u64 last_access_tick;
    u32 window_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 400000);
    __type(key, struct page_key);
    __type(value, struct page_track_info);
} page_tracking_map SEC(".maps");

struct stream_key {
    u64 mapping;
    u32 tgid;
    u32 pad;
};

struct stream_stat {
    u64 samples;
    u64 seq_access_count;
    u64 revisit_count;
    u64 dirty_count;
    u64 last_index;
    u32 current_window_id;
    u32 smoothed_seq;
    u32 smoothed_revisit;
    u32 smoothed_dirty;
    u32 current_state;
    u32 cooldown_windows;
    u32 hot_streak;
    u32 weak_pollution_streak;
    u32 move_sample_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct stream_key);
    __type(value, struct stream_stat);
} stream_stats_map SEC(".maps");

static __always_inline bool is_regular_file_mapping(struct address_space *mapping)
{
    struct inode *inode;
    umode_t mode;

    if (!mapping)
        return false;

    inode = BPF_CORE_READ(mapping, host);
    if (!inode)
        return false;

    mode = BPF_CORE_READ(inode, i_mode);
    return (mode & S_IFMT) == S_IFREG;
}

static __always_inline bool mapping_is_stream_candidate(struct address_space *mapping)
{
    unsigned long nrpages;

    if (!is_regular_file_mapping(mapping))
        return false;

    nrpages = BPF_CORE_READ(mapping, nrpages);
    return nrpages >= MIN_STREAM_FILE_PAGES;
}

static __always_inline bool folio_is_clean_file_cache(struct folio *folio,
                                                      struct address_space *mapping)
{
    if (!is_regular_file_mapping(mapping))
        return false;
    if (!folio_test_uptodate(folio))
        return false;
    if (!folio_test_lru(folio))
        return false;
    if (folio_test_dirty(folio))
        return false;
    if (folio_test_writeback(folio))
        return false;
    if (folio_test_locked(folio))
        return false;
    if (folio_test_unevictable(folio))
        return false;
    if (folio_test_hugetlb(folio))
        return false;
    return true;
}

static __always_inline bool stream_is_pollution(struct stream_stat *st)
{
    if (!st)
        return false;

    if (st->cooldown_windows > 0)
        return false;

    if (st->current_state == STREAM_POLLUTION) {
        return st->smoothed_seq >= STREAM_SEQ_KEEP &&
               st->smoothed_revisit <= STREAM_REVISIT_KEEP &&
               st->smoothed_dirty <= STREAM_DIRTY_KEEP;
    }

    return st->smoothed_seq >= STREAM_SEQ_ENTER &&
           st->smoothed_revisit <= STREAM_REVISIT_ENTER &&
           st->smoothed_dirty <= STREAM_DIRTY_ENTER;
}

static __always_inline bool stream_should_backoff_hot(struct stream_stat *st)
{
    return st && st->smoothed_revisit >= STREAM_REVISIT_BACKOFF;
}

static __always_inline bool stream_should_backoff_weak(struct stream_stat *st)
{
    return st && st->smoothed_seq < STREAM_SEQ_KEEP &&
           st->smoothed_revisit > STREAM_REVISIT_KEEP;
}

static __always_inline void finalize_stream_window(struct stream_stat *st,
                                                   struct address_space *mapping,
                                                   u32 tgid)
{
    struct debug_stats *dbg;
    unsigned long nrpages = 0;
    u32 seq_ratio;
    u32 revisit_ratio;
    u32 dirty_ratio;
    u32 old_state;
    bool hot_backoff;
    bool weak_backoff;

    if (!st || st->samples == 0)
        return;

    seq_ratio = (u32)((st->seq_access_count * 10000) / st->samples);
    revisit_ratio = (u32)((st->revisit_count * 10000) / st->samples);
    dirty_ratio = (u32)((st->dirty_count * 10000) / st->samples);

    st->smoothed_seq = (st->smoothed_seq * 3 + seq_ratio) >> 2;
    st->smoothed_revisit = (st->smoothed_revisit * 3 + revisit_ratio) >> 2;
    st->smoothed_dirty = (st->smoothed_dirty * 3 + dirty_ratio) >> 2;

    if (dirty_ratio >= STREAM_DIRTY_HARD || st->smoothed_dirty >= STREAM_DIRTY_KEEP)
        st->cooldown_windows = DIRTY_COOLDOWN_WINDOWS;
    else if (st->cooldown_windows > 0)
        st->cooldown_windows--;

    old_state = st->current_state;
    if (old_state == STREAM_POLLUTION && stream_should_backoff_hot(st))
        st->hot_streak++;
    else
        st->hot_streak = 0;

    if (old_state == STREAM_POLLUTION && stream_should_backoff_weak(st))
        st->weak_pollution_streak++;
    else
        st->weak_pollution_streak = 0;

    hot_backoff = st->hot_streak >= HOT_BACKOFF_STREAK;
    weak_backoff = st->weak_pollution_streak >= WEAK_POLLUTION_STREAK;

    if (hot_backoff || weak_backoff) {
        st->cooldown_windows = STREAM_BACKOFF_WINDOWS;
        st->hot_streak = 0;
        st->weak_pollution_streak = 0;
    }

    if (mapping)
        nrpages = BPF_CORE_READ(mapping, nrpages);

    if (!is_regular_file_mapping(mapping))
        st->current_state = STREAM_NORMAL;
    else if (!mapping_is_stream_candidate(mapping))
        st->current_state = STREAM_NORMAL;
    else if (hot_backoff || weak_backoff)
        st->current_state = STREAM_NORMAL;
    else if (stream_is_pollution(st))
        st->current_state = STREAM_POLLUTION;
    else
        st->current_state = STREAM_NORMAL;

    dbg = get_dbg_stats();
    if (dbg) {
        dbg->stream_windows++;
        if (st->current_state == STREAM_POLLUTION)
            dbg->pollution_windows++;
        else
            dbg->normal_windows++;

        if (old_state != st->current_state) {
            if (st->current_state == STREAM_POLLUTION)
                dbg->switch_to_pollution++;
            else
                dbg->switch_to_normal++;
        }

        if (hot_backoff)
            dbg->backoff_hot_reuse++;
        if (weak_backoff)
            dbg->backoff_weak_pollution++;
    }

#if DATA_COLLECT
    struct feature_event *event = bpf_ringbuf_reserve(&feature_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns = bpf_ktime_get_ns();
        event->mapping = (u64)mapping;
        event->last_index = st->last_index;
        event->mapping_nrpages = nrpages;
        event->tgid = tgid;
        event->window_id = st->current_window_id;
        event->sample_count = st->samples;
        event->seq_ratio_10000 = seq_ratio;
        event->revisit_ratio_10000 = revisit_ratio;
        event->dirty_ratio_10000 = dirty_ratio;
        event->smoothed_seq_10000 = st->smoothed_seq;
        event->smoothed_revisit_10000 = st->smoothed_revisit;
        event->smoothed_dirty_10000 = st->smoothed_dirty;
        event->old_state = old_state;
        event->new_state = st->current_state;
        event->cooldown_windows = st->cooldown_windows;
        event->hot_streak = st->hot_streak;
        event->weak_pollution_streak = st->weak_pollution_streak;
        event->stream_candidate = mapping_is_stream_candidate(mapping);
        event->hot_backoff = hot_backoff;
        event->weak_backoff = weak_backoff;
        bpf_ringbuf_submit(event, 0);
    }
#endif

    st->current_window_id++;
    st->samples = 0;
    st->seq_access_count = 0;
    st->revisit_count = 0;
    st->dirty_count = 0;
}

static __always_inline bool observe_stream(struct folio *folio,
                                           struct address_space *mapping,
                                           u64 index)
{
    u64 raw_tick;
    u64 pid_tgid;
    u32 tgid;
    struct stream_key stream_key = {};
    struct stream_stat *st;

    pid_tgid = bpf_get_current_pid_tgid();
    tgid = (u32)(pid_tgid >> 32);
    stream_key.mapping = (u64)mapping;
    stream_key.tgid = tgid;

    st = bpf_map_lookup_elem(&stream_stats_map, &stream_key);
    if (!st) {
        struct stream_stat new_st = {};

        new_st.last_index = index;
        bpf_map_update_elem(&stream_stats_map, &stream_key, &new_st, BPF_ANY);
        return false;
    }

    raw_tick = bpf_ktime_get_ns();
    if ((raw_tick & SAMPLING_MASK) != 0)
        return st->current_state == STREAM_POLLUTION;

    if (index > st->last_index && (index - st->last_index) <= 512)
        st->seq_access_count++;
    st->last_index = index;
    st->samples++;

    if (folio_test_dirty(folio) || folio_test_writeback(folio))
        st->dirty_count++;

    {
        struct page_key page_key = {
            .mapping = (u64)mapping,
            .index = index,
        };
        struct page_track_info *info;
        u64 current_time_us = raw_tick / 1000;

        info = bpf_map_lookup_elem(&page_tracking_map, &page_key);
        if (info) {
            if (current_time_us > info->last_access_tick)
                st->revisit_count++;
            info->last_access_tick = current_time_us;
            info->window_id = st->current_window_id;
        } else {
            struct page_track_info new_info = {
                .last_access_tick = current_time_us,
                .window_id = st->current_window_id,
            };
            bpf_map_update_elem(&page_tracking_map, &page_key, &new_info, BPF_ANY);
        }
    }

    {
        struct debug_stats *dbg = get_dbg_stats();
        if (dbg)
            dbg->sampled_accesses++;
    }

    if (st->samples >= WINDOW_SIZE)
        finalize_stream_window(st, mapping, tgid);

    return st->current_state == STREAM_POLLUTION;
}

static __always_inline void apply_stream_membership(struct folio *folio,
                                                    struct address_space *mapping,
                                                    bool stream_pollution,
                                                    bool is_add_event)
{
    struct debug_stats *dbg = get_dbg_stats();
    struct stream_key stream_key = {
        .mapping = (u64)mapping,
        .tgid = (u32)(bpf_get_current_pid_tgid() >> 32),
    };
    struct stream_stat *st = bpf_map_lookup_elem(&stream_stats_map, &stream_key);

    if (!is_regular_file_mapping(mapping)) {
        if (dbg)
            dbg->bypass_non_file++;
        if (!is_add_event) {
            if (dbg)
                dbg->list_dels++;
            bpf_cache_ext_list_del(folio);
        }
        return;
    }

    if (!mapping_is_stream_candidate(mapping)) {
        if (dbg)
            dbg->bypass_small_file++;
        if (!is_add_event) {
            if (dbg)
                dbg->list_dels++;
            bpf_cache_ext_list_del(folio);
        }
        return;
    }

    if (!folio_is_clean_file_cache(folio, mapping)) {
        if (dbg)
            dbg->bypass_dirty_state++;
        if (!is_add_event) {
            if (dbg)
                dbg->list_dels++;
            bpf_cache_ext_list_del(folio);
        }
        return;
    }

    if (!stream_pollution) {
        if (dbg) {
            if (st && st->smoothed_revisit > STREAM_REVISIT_ENTER)
                dbg->bypass_hot++;
            else
                dbg->bypass_not_readmostly++;
        }
        if (!is_add_event) {
            if (dbg)
                dbg->list_dels++;
            bpf_cache_ext_list_del(folio);
        }
        return;
    }

    if (is_add_event) {
        if (dbg)
            dbg->list_adds++;
        bpf_cache_ext_list_add_batched(main_list, folio);
        return;
    }

    if (st) {
        st->move_sample_count++;
        if ((st->move_sample_count & POLLUTION_MOVE_SAMPLE_MASK) != 0)
            return;
    }

    if (dbg)
        dbg->list_moves++;
    bpf_cache_ext_list_move_batched(main_list, folio, false);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg)
{
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0)
        return -1;

    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio)
{
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    bool stream_pollution = observe_stream(folio, mapping, index);

    apply_stream_membership(folio, mapping, stream_pollution, true);
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio)
{
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    bool stream_pollution = observe_stream(folio, mapping, index);

    apply_stream_membership(folio, mapping, stream_pollution, false);
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio)
{
    bpf_cache_ext_list_del(folio);
}

static int evict_mru_cb(int idx, struct cache_ext_list_node *a)
{
    struct debug_stats *dbg;
    bool uptodate;
    bool lru;
    bool dirty;
    bool writeback;
    bool locked;
    bool unevictable;
    int refs;
    int action = CACHE_EXT_EVICT_NODE;
    int reason = 0;

    if (!a || !a->folio)
        return CACHE_EXT_CONTINUE_ITER;

    if (idx < POLLUTION_PROTECTED_HEAD_FOLIOS)
        return CACHE_EXT_CONTINUE_ITER;

    dbg = get_dbg_stats();
    if (dbg)
        dbg->evict_cb_calls++;

    uptodate = folio_test_uptodate(a->folio);
    lru = folio_test_lru(a->folio);
    dirty = folio_test_dirty(a->folio);
    writeback = folio_test_writeback(a->folio);
    locked = folio_test_locked(a->folio);
    unevictable = folio_test_unevictable(a->folio);

    refs = bpf_folio_check_referenced(a->folio);
    if (dbg) {
        dbg->ref_checks++;
        if (refs > 0)
            dbg->ref_positive++;
    }

    if (locked)
        reason = 1;
    else if (writeback)
        reason = 2;
    else if (dirty)
        reason = 3;
    else if (!uptodate)
        reason = 4;
    else if (!lru)
        reason = 5;
    else if (unevictable)
        reason = 6;
    else if (refs > 0)
        reason = 7;

    if (reason > 0) {
        if (dbg) {
            if (reason == 1)
                dbg->skip_locked++;
            else if (reason == 2)
                dbg->skip_writeback++;
            else if (reason == 3)
                dbg->skip_dirty++;
            else if (reason == 4)
                dbg->skip_not_uptodate++;
            else if (reason == 5)
                dbg->skip_not_lru++;
            else if (reason == 6)
                dbg->skip_unevictable++;
        }
        action = CACHE_EXT_CONTINUE_ITER;
    } else if (dbg) {
        dbg->evict_candidates++;
    }

    return action;
}

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx,
                    struct mem_cgroup *memcg)
{
    struct debug_stats *dbg = get_dbg_stats();

    if (dbg) {
        u64 len = bpf_cache_ext_list_length(memcg, main_list);
        dbg->evict_rounds++;
        dbg->list_len_last = len;
        if (len > dbg->list_len_max)
            dbg->list_len_max = len;
    }

    bpf_cache_ext_list_iterate(memcg, main_list, evict_mru_cb, eviction_ctx);
}

SEC(".struct_ops.link")
struct cache_ext_ops chameleon_ops = {
    .init = (void *)chameleon_init,
    .evict_folios = (void *)chameleon_evict_folios,
    .folio_accessed = (void *)chameleon_folio_accessed,
    .folio_evicted = (void *)chameleon_folio_evicted,
    .folio_added = (void *)chameleon_folio_added,
};