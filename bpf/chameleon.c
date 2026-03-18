// chameleon.c
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "chameleon.skel.h"
// 完全移除 dir_watcher.h

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

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

int main(int argc, char **argv) {
    struct chameleon_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int cgroup_fd = -1;
    
    struct cmdline_args args = { 0 };
    struct argp argp = { options, parse_opt, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (!args.cgroup_path) return 1;

    cgroup_fd = open(args.cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Failed to open cgroup path");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skel = chameleon_bpf__open_and_load(); // 简化合并为一步
    if (!skel) goto cleanup;

    __u32 map_key = 0;
    struct { __u32 p1, p2, p3, p4, p5; } params = {0, 0, 0, 0, 0};
    bpf_map_update_elem(bpf_map__fd(skel->maps.cml_params_map), &map_key, &params, BPF_ANY);

    link = bpf_map__attach_cache_ext_ops(skel->maps.chameleon_ops, cgroup_fd);
    if (!link) goto cleanup;

    printf("Chameleon Policy successfully attached to cgroup!\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    while (!exiting) { pause(); }

cleanup:
    if (cgroup_fd >= 0) close(cgroup_fd);
    bpf_link__destroy(link);
    chameleon_bpf__destroy(skel);
    return 0;
}