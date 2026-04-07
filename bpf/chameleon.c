// chameleon.c: eBPF 程序的用户态加载器
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint64_t u64;
typedef uint32_t u32;

#define DATA_COLLECT 1 

#include "chameleon.skel.h"

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

#if DATA_COLLECT
const char *PIN_FEATURE_PATH = "/sys/fs/bpf/cml_feature_events"; 
#endif

int main(int argc, char **argv) {
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Warning: Failed to increase RLIMIT_MEMLOCK limit!\n");
    }

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
    skel = chameleon_bpf__open_and_load(); 
    if (!skel) goto cleanup;

#if DATA_COLLECT
    bpf_map__unpin(skel->maps.feature_events, PIN_FEATURE_PATH); 
    if (bpf_map__pin(skel->maps.feature_events, PIN_FEATURE_PATH)) goto cleanup; 
    printf("✅ Feature RingBuffer successfully pinned to /sys/fs/bpf/\n");
#endif

    link = bpf_map__attach_cache_ext_ops(skel->maps.chameleon_ops, cgroup_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach cache_ext_ops\n");
        goto cleanup;
    }

    printf("🚀 Chameleon Data Plane successfully attached to cgroup!\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    while (!exiting) {
        sleep(1); 
    }

cleanup:
    if (skel) {
#if DATA_COLLECT
        bpf_map__unpin(skel->maps.feature_events, PIN_FEATURE_PATH);
#endif
    }
if (cgroup_fd >= 0) close(cgroup_fd);
    if (link) bpf_link__destroy(link);
    if (skel) chameleon_bpf__destroy(skel);
    printf("\n🛑 Chameleon Data Plane stopped and cleaned up.\n");
    return 0;
}