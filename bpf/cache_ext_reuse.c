// cache_ext_reuse.c - 监控页面缓存扩展对象重用的用户空间程序
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

// 这个头文件是 Makefile 稍后会自动帮你生成的！
#include "cache_ext_reuse.skel.h"
#include "dir_watcher.h"

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

struct cmdline_args {
    char *watch_dir;
};

static struct argp_option options[] = { 
    { "watch_dir", 'w', "DIR", 0, "Directory to watch" },
    { 0 } 
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct cmdline_args *args = state->input;
    if (key == 'w') args->watch_dir = arg;
    else return ARGP_ERR_UNKNOWN;
    return 0;
}

// 必须和刚才内核里的结构体完全对齐
struct reuse_stats {
    __u64 count;
    __u64 sum;
    __u64 sum_sq;
    __u64 global_seq;
};

int main(int argc, char **argv) {
    struct cache_ext_reuse_bpf *skel = NULL;
    int ret = 1;

    struct cmdline_args args = { 0 };
    struct argp argp = { options, parse_opt, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (!args.watch_dir) {
        fprintf(stderr, "Usage: %s --watch_dir <DIR>\n", argv[0]);
        return 1;
    }

    char watch_dir_full_path[PATH_MAX];
    if (realpath(args.watch_dir, watch_dir_full_path) == NULL) {
        perror("realpath");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    // 1. 打开 eBPF 骨架
    skel = cache_ext_reuse_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        goto cleanup;
    }

    // 2. 注入目录白名单路径
    skel->rodata->watch_dir_path_len = strlen(watch_dir_full_path);
    strcpy(skel->rodata->watch_dir_path, watch_dir_full_path);

    // 3. 验证并加载字节码到内核
    if (cache_ext_reuse_bpf__load(skel)) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    // 4. 解析目录 Inode 并写入白名单 Map
    ret = initialize_watch_dir_map(args.watch_dir, 
                                   bpf_map__fd(skel->maps.inode_watchlist), false);
    if (ret) {
        fprintf(stderr, "Failed to initialize watch dir map\n");
        goto cleanup;
    }

    // 5. 挂载 fentry 探针到内核原生函数
    if (cache_ext_reuse_bpf__attach(skel)) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    int map_fd = bpf_map__fd(skel->maps.global_stats_map);
    __u32 key = 0;
    struct reuse_stats stats;

    fprintf(stderr, "Reuse Tracker started. Outputting JSON to stdout...\n");

    // 6. RL Agent 数据管道输出循环
    while (!exiting) {
        sleep(1);
        if (bpf_map_lookup_elem(map_fd, &key, &stats) == 0) {
            // 直接输出 JSON，供 Python 脚本的 subprocess 截获解析
            printf("{\"count\": %llu, \"sum\": %llu, \"sum_sq\": %llu, \"seq\": %llu}\n", 
                   stats.count, stats.sum, stats.sum_sq, stats.global_seq);
            fflush(stdout);
        }
    }

    ret = 0;
cleanup:
    cache_ext_reuse_bpf__destroy(skel);
    return ret;
}