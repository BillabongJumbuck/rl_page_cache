// chameleon.c - Chameleon (变色龙) BPF 用户空间加载器
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

struct rl_params {
    __u32 p_access;
    __u32 p_direction;
    __u32 p_threshold;
    __u32 p_survival;
    __u32 p_ghost;
};

#include "chameleon.skel.h"
#include "dir_watcher.h"

struct cmdline_args { char *watch_dir; char *cgroup_path; };
static struct argp_option options[] = { 
    { "watch_dir", 'w', "DIR", 0, "Directory to watch" },
    { "cgroup_path", 'c', "PATH", 0, "Path to cgroup" }, { 0 } 
};
static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct cmdline_args *args = state->input;
    if (key == 'w') args->watch_dir = arg; else if (key == 'c') args->cgroup_path = arg;
    else return ARGP_ERR_UNKNOWN;
    return 0;
}

static volatile bool exiting = false;
static void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char **argv) {
    struct chameleon_bpf *skel = NULL;
    struct bpf_link *link = NULL;
    int cgroup_fd = -1, ret = 1;
    struct cmdline_args args = { 0 };
    struct argp argp = { options, parse_opt, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (!args.watch_dir || !args.cgroup_path) return 1;

    char watch_dir_full_path[PATH_MAX];
    if (realpath(args.watch_dir, watch_dir_full_path) == NULL) return 1;

    cgroup_fd = open(args.cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) return 1;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    
    // 1. 打开骨架
    skel = chameleon_bpf__open();
    if (!skel) goto cleanup;

    // 2. 注入只读数据 (rodata 必须在 load 之前设置)
    skel->rodata->watch_dir_path_len = strlen(watch_dir_full_path);
    strcpy(skel->rodata->watch_dir_path, watch_dir_full_path);

    // 3. 加载到内核
    if (chameleon_bpf__load(skel)) goto cleanup;

    // 4. 【极致优化的参数下发】直接操作 mmap 映射的 BSS 段内存，0 查表开销！
    skel->bss->current_params.p_access = 0;
    skel->bss->current_params.p_direction = 0;
    skel->bss->current_params.p_threshold = 0;
    skel->bss->current_params.p_survival = 0;
    skel->bss->current_params.p_ghost = 0;

    // 5. 初始化目录监控
    initialize_watch_dir_map(args.watch_dir, bpf_map__fd(skel->maps.inode_watchlist), false);

    // 6. 挂载探针
    link = bpf_map__attach_cache_ext_ops(skel->maps.chameleon_ops, cgroup_fd);
    if (!link) goto cleanup;

    printf("Chameleon (变色龙) Policy successfully loaded!\n");
    printf("Initial mode: FIFO (0,0,0,0,0) with Zero-Copy BSS variables.\n");
    printf("Daemon is running in background. Send SIGTERM to exit...\n");
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    while (!exiting) {
        pause(); 
    }
    
    ret = 0;

cleanup:
    if (cgroup_fd >= 0) close(cgroup_fd);
    bpf_link__destroy(link);
    chameleon_bpf__destroy(skel);
    return ret;
}