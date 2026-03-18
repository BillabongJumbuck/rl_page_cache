// cache_ext_reuse.c
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include "cache_ext_reuse.skel.h"

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

struct cmdline_args { char *cgroup_path; };

static struct argp_option options[] = { 
    { "cgroup_path", 'c', "PATH", 0, "Path to cgroup v2 directory" },
    { 0 } 
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct cmdline_args *args = state->input;
    if (key == 'c') args->cgroup_path = arg;
    else return ARGP_ERR_UNKNOWN;
    return 0;
}

// 结构体对齐
struct reuse_stats {
    __u64 count;
    __u64 sum;
    __u64 sum_sq;
    __u64 global_seq;
};

int main(int argc, char **argv) {
    struct cache_ext_reuse_bpf *skel = NULL;
    struct cmdline_args args = { 0 };
    struct argp argp = { options, parse_opt, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (!args.cgroup_path) {
        fprintf(stderr, "Usage: %s -c <cgroup_v2_path>\n", argv[0]);
        return 1;
    }

    // 获取 cgroup ID (通过 stat 获取目录 inode number)
    struct stat st;
    if (stat(args.cgroup_path, &st) < 0) {
        perror("Failed to stat cgroup path");
        return 1;
    }
    __u64 cgroup_id = st.st_ino;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skel = cache_ext_reuse_bpf__open();
    if (!skel) return 1;

    // 注入 cgroup ID 到 BPF rodata
    skel->rodata->target_cgroup_id = cgroup_id;

    if (cache_ext_reuse_bpf__load(skel)) goto cleanup;
    if (cache_ext_reuse_bpf__attach(skel)) goto cleanup;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int map_fd = bpf_map__fd(skel->maps.global_stats_map);
    __u32 key = 0;
    struct reuse_stats stats;

    fprintf(stderr, "Reuse Tracker attached to cgroup_id: %llu\n", cgroup_id);

    while (!exiting) {
        sleep(1);
        if (bpf_map_lookup_elem(map_fd, &key, &stats) == 0) {
            printf("{\"count\": %llu, \"sum\": %llu, \"sum_sq\": %llu, \"seq\": %llu}\n", 
                   stats.count, stats.sum, stats.sum_sq, stats.global_seq);
            fflush(stdout);
        }
    }

cleanup:
    cache_ext_reuse_bpf__destroy(skel);
    return 0;
}