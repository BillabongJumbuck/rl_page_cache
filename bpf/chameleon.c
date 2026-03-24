#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <stdint.h>
typedef uint64_t u64;
typedef uint32_t u32;
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

// ==============================================================
// 🌟 核心修改 1：重命名挂载路径，适配特征提取架构
// ==============================================================
const char *PIN_PARAMS_PATH  = "/sys/fs/bpf/cml_params_map";
const char *PIN_STATS_PATH   = "/sys/fs/bpf/cml_stats_map";
const char *PIN_FEATURE_PATH = "/sys/fs/bpf/cml_feature_events"; // 改为 Feature RingBuffer 路径

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

    // ==============================================================
    // 🌟 核心修改 2：把 feature_events Pin 到文件系统
    // ==============================================================
    bpf_map__unpin(skel->maps.cml_params_map, PIN_PARAMS_PATH);
    bpf_map__unpin(skel->maps.cml_stats_map, PIN_STATS_PATH);
    bpf_map__unpin(skel->maps.feature_events, PIN_FEATURE_PATH); 

    if (bpf_map__pin(skel->maps.cml_params_map, PIN_PARAMS_PATH)) goto cleanup;
    if (bpf_map__pin(skel->maps.cml_stats_map, PIN_STATS_PATH)) goto cleanup;
    if (bpf_map__pin(skel->maps.feature_events, PIN_FEATURE_PATH)) goto cleanup; 

    printf("✅ Maps & Feature RingBuffer successfully pinned to /sys/fs/bpf/\n");

    // 默认加载策略 0 (POLICY_LRU)
    __u32 map_key = 0;
    struct { __u32 active_policy; } params = {0};
    bpf_map_update_elem(bpf_map__fd(skel->maps.cml_params_map), &map_key, &params, BPF_ANY);

    link = bpf_map__attach_cache_ext_ops(skel->maps.chameleon_ops, cgroup_fd);
    if (!link) goto cleanup;

    printf("🚀 Chameleon Data Plane successfully attached to cgroup!\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // 数据面只负责站岗，不处理任何用户态逻辑
    while (!exiting) { pause(); }

cleanup:
    if (skel) {
        bpf_map__unpin(skel->maps.cml_params_map, PIN_PARAMS_PATH);
        bpf_map__unpin(skel->maps.cml_stats_map, PIN_STATS_PATH);
        // ==============================================================
        // 🌟 核心修改 3：退出时清理 feature_events
        // ==============================================================
        bpf_map__unpin(skel->maps.feature_events, PIN_FEATURE_PATH);
    }
    if (cgroup_fd >= 0) close(cgroup_fd);
    bpf_link__destroy(link);
    chameleon_bpf__destroy(skel);
    printf("\n🛑 Chameleon Data Plane stopped and cleaned up.\n");
    return 0;
}