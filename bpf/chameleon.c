// chameleon.c: eBPF 用户态 Agent (纯监控模式)
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

#include "chameleon.skel.h"

// 必须与 BPF 程序中的特征结构体绝对对齐
struct feature_event {
    u32 tid;
    u32 seq_count;
    u64 stride_sum;
};

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

// ==========================================
// 📊 遥测引擎 (仅做数据收集与展示，不干预内核决策)
// ==========================================
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct feature_event *e = data;

    // 此时此刻，内核已经做完决策并执行了！这里只负责事后诸葛亮的遥测
    float seq_ratio = (float)e->seq_count / 1000.0f; 
    float avg_stride = (float)e->stride_sum / 1000.0f;

    // 可视化输出，让你确认后台 Scan 线程确实在疯狂产生高 seq_ratio
    printf("[📊 Monitor] TID: %u | SeqRatio: %.2f | AvgStride: %.1f\n", 
           e->tid, seq_ratio, avg_stride);
    
    return 0;
}

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
    struct ring_buffer *rb = NULL;
    int cgroup_fd = -1;
    
    struct cmdline_args args = { 0 };
    struct argp argp = { options, parse_opt, 0, 0 };
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (!args.cgroup_path) {
        fprintf(stderr, "Error: Please specify cgroup path with -c\n");
        return 1;
    }

    cgroup_fd = open(args.cgroup_path, O_RDONLY);
    if (cgroup_fd < 0) {
        perror("Failed to open cgroup path");
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skel = chameleon_bpf__open_and_load(); 
    if (!skel) goto cleanup;

    // 挂载 BPF 到 Cgroup
    link = bpf_map__attach_cache_ext_ops(skel->maps.chameleon_ops, cgroup_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach cache_ext_ops\n");
        goto cleanup;
    }

    // 🌟 核心修改：去掉了 policy_fd，这里上下文 ctx 直接传 NULL
    rb = ring_buffer__new(bpf_map__fd(skel->maps.feature_ringbuf), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("🚀 Chameleon Telemetry Monitor started! Kernel is driving the logic...\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // 死循环：拉取遥测特征，同时防止 RingBuffer 堆积
    while (!exiting) {
        ring_buffer__poll(rb, 100); 
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    if (cgroup_fd >= 0) close(cgroup_fd);
    if (link) bpf_link__destroy(link);
    if (skel) chameleon_bpf__destroy(skel);
    printf("\n🛑 Chameleon Telemetry Monitor stopped and cleaned up.\n");
    return 0;
}