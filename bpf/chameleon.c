// chameleon.c: eBPF userspace loader and feature collector
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

typedef uint64_t u64;
typedef uint32_t u32;

#define DATA_COLLECT 1

#include "chameleon.skel.h"

struct cmdline_args {
    char *cgroup_path;
    char *output_path;
};

static struct argp_option options[] = {
    { "cgroup_path", 'c', "PATH", 0, "Path to cgroup v2 directory" },
    { "output", 'o', "PATH", 0, "Path to write collected CSV features" },
    { 0 }
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct cmdline_args *args = state->input;

    if (key == 'c')
        args->cgroup_path = arg;
    else if (key == 'o')
        args->output_path = arg;
    else
        return ARGP_ERR_UNKNOWN;
    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = true;
}

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

struct collector_ctx {
    FILE *csv;
};

static void write_csv_header(FILE *csv)
{
    fprintf(csv,
            "timestamp_ns,mapping,last_index,mapping_nrpages,tgid,window_id,"
            "sample_count,seq_ratio_10000,revisit_ratio_10000,dirty_ratio_10000,"
            "smoothed_seq_10000,smoothed_revisit_10000,smoothed_dirty_10000,"
            "old_state,new_state,cooldown_windows,hot_streak,weak_pollution_streak,"
            "stream_candidate,hot_backoff,weak_backoff\n");
    fflush(csv);
}

static int handle_feature_event(void *ctx, void *data, size_t data_sz)
{
    struct collector_ctx *collector = ctx;
    const struct feature_event *event = data;

    if (!collector || !collector->csv || data_sz < sizeof(*event))
        return 0;

    fprintf(collector->csv,
            "%llu,%llu,%llu,%llu,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
            (unsigned long long)event->timestamp_ns,
            (unsigned long long)event->mapping,
            (unsigned long long)event->last_index,
            (unsigned long long)event->mapping_nrpages,
            event->tgid,
            event->window_id,
            event->sample_count,
            event->seq_ratio_10000,
            event->revisit_ratio_10000,
            event->dirty_ratio_10000,
            event->smoothed_seq_10000,
            event->smoothed_revisit_10000,
            event->smoothed_dirty_10000,
            event->old_state,
            event->new_state,
            event->cooldown_windows,
            event->hot_streak,
            event->weak_pollution_streak,
            event->stream_candidate,
            event->hot_backoff,
            event->weak_backoff);
    fflush(collector->csv);
    return 0;
}
#endif

static long long monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
}

static void print_debug_delta(const struct debug_stats *cur,
                              const struct debug_stats *prev)
{
    printf(
        "[DBG/s] samp=%" PRIu64 " win=%" PRIu64 "(poll=%" PRIu64 ",norm=%" PRIu64 ") "
        "sw(p=%" PRIu64 ",n=%" PRIu64 ") "
        "list(add=%" PRIu64 ",mv=%" PRIu64 ",del=%" PRIu64 ") "
        "bypass(file=%" PRIu64 ",small=%" PRIu64 ",dirty=%" PRIu64 ",rm=%" PRIu64 ",hot=%" PRIu64 ") "
        "backoff(hot=%" PRIu64 ",weak=%" PRIu64 ") "
        "evict(round=%" PRIu64 ",cb=%" PRIu64 ",cand=%" PRIu64 ") "
        "ref=%" PRIu64 "/%" PRIu64 " skip(l=%" PRIu64 ",wb=%" PRIu64 ",d=%" PRIu64 ",nu=%" PRIu64 ",nlru=%" PRIu64 ",ue=%" PRIu64 ") "
        "listlen(last=%" PRIu64 ",max=%" PRIu64 ")\n",
        cur->sampled_accesses - prev->sampled_accesses,
        cur->stream_windows - prev->stream_windows,
        cur->pollution_windows - prev->pollution_windows,
        cur->normal_windows - prev->normal_windows,
        cur->switch_to_pollution - prev->switch_to_pollution,
        cur->switch_to_normal - prev->switch_to_normal,
        cur->list_adds - prev->list_adds,
        cur->list_moves - prev->list_moves,
        cur->list_dels - prev->list_dels,
        cur->bypass_non_file - prev->bypass_non_file,
        cur->bypass_small_file - prev->bypass_small_file,
        cur->bypass_dirty_state - prev->bypass_dirty_state,
        cur->bypass_not_readmostly - prev->bypass_not_readmostly,
        cur->bypass_hot - prev->bypass_hot,
        cur->backoff_hot_reuse - prev->backoff_hot_reuse,
        cur->backoff_weak_pollution - prev->backoff_weak_pollution,
        cur->evict_rounds - prev->evict_rounds,
        cur->evict_cb_calls - prev->evict_cb_calls,
        cur->evict_candidates - prev->evict_candidates,
        cur->ref_positive - prev->ref_positive,
        cur->ref_checks - prev->ref_checks,
        cur->skip_locked - prev->skip_locked,
        cur->skip_writeback - prev->skip_writeback,
        cur->skip_dirty - prev->skip_dirty,
        cur->skip_not_uptodate - prev->skip_not_uptodate,
        cur->skip_not_lru - prev->skip_not_lru,
        cur->skip_unevictable - prev->skip_unevictable,
        cur->list_len_last,
        cur->list_len_max);
}

int main(int argc, char **argv)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    struct chameleon_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int cgroup_fd = -1;
    int err = 0;
    struct cmdline_args args = {
        .output_path = "feature_events.csv",
    };
    struct argp argp = { options, parse_opt, 0, 0 };
    int dbg_fd;
    struct debug_stats prev = {};
    bool have_prev = false;
    long long last_dbg_ms;
#if DATA_COLLECT
    struct ring_buffer *rb = NULL;
    struct collector_ctx collector = {};
#endif

    if (setrlimit(RLIMIT_MEMLOCK, &rlim))
        fprintf(stderr, "Warning: Failed to increase RLIMIT_MEMLOCK limit!\n");

    argp_parse(&argp, argc, argv, 0, 0, &args);
    if (!args.cgroup_path)
        return 1;

    cgroup_fd = open(args.cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Failed to open cgroup path");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skel = chameleon_bpf__open_and_load();
    if (!skel)
        goto cleanup;

#if DATA_COLLECT
    collector.csv = fopen(args.output_path, "w");
    if (!collector.csv) {
        perror("Failed to open feature output file");
        goto cleanup;
    }
    write_csv_header(collector.csv);

    rb = ring_buffer__new(bpf_map__fd(skel->maps.feature_events),
                          handle_feature_event, &collector, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Feature collection enabled, writing CSV to %s\n", args.output_path);
#endif

    link = bpf_map__attach_cache_ext_ops(skel->maps.chameleon_ops, cgroup_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach cache_ext_ops\n");
        goto cleanup;
    }

    printf("Chameleon Data Plane successfully attached to cgroup!\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    dbg_fd = bpf_map__fd(skel->maps.debug_stats_map);
    last_dbg_ms = monotonic_ms();

    while (!exiting) {
#if DATA_COLLECT
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll failed: %d\n", err);
            break;
        }
#else
        usleep(100000);
#endif

        if (dbg_fd >= 0 && monotonic_ms() - last_dbg_ms >= 1000) {
            u32 key = 0;
            struct debug_stats cur = {};

            if (!bpf_map_lookup_elem(dbg_fd, &key, &cur)) {
                if (have_prev)
                    print_debug_delta(&cur, &prev);
                prev = cur;
                have_prev = true;
            }

            last_dbg_ms = monotonic_ms();
        }
    }

cleanup:
#if DATA_COLLECT
    if (rb)
        ring_buffer__free(rb);
    if (collector.csv)
        fclose(collector.csv);
#endif
    if (cgroup_fd >= 0)
        close(cgroup_fd);
    if (link)
        bpf_link__destroy(link);
    if (skel)
        chameleon_bpf__destroy(skel);
    printf("\nChameleon Data Plane stopped and cleaned up.\n");
    return err < 0 ? 1 : 0;
}
