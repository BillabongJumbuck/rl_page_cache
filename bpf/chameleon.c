// chameleon.c: eBPF 用户态 Agent (Control Plane)
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
#include <sys/syscall.h>

typedef uint64_t u64;
typedef uint32_t u32;

#include "chameleon.skel.h"

// 适配系统的 pidfd_open 调用
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif

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

// static FILE *csv_log = NULL;

// ==========================================
// 🧠 核心推理引擎 (AI Agent 的雏形)
// ==========================================
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct feature_event *e = data;
    int policy_fd = *(int *)ctx; // 拿到 policy_storage 的 Map FD

    // if (!csv_log) {
    //     csv_log = fopen("ycsb_memory_features.csv", "w");
    //     fprintf(csv_log, "tid,seq_ratio,avg_stride\n"); 
    // }
    
    // 1. 用户态执行特征计算 (现在你可以毫无顾忌地用浮点数和除法了)
    // 这里的 1000 对应 BPF 里的 BATCH_SIZE
    float seq_ratio = (float)e->seq_count / 1000.0f; 
    float avg_stride = (float)e->stride_sum / 1000.0f;

    // fprintf(csv_log, "%u,%.3f,%.1f\n", e->tid, seq_ratio, avg_stride);
    // fflush(csv_log);

    // 2. 策略推断 (Ablation Study 阶段：先用静态规则复刻之前的行为)
    u32 policy = 0; // POLICY_LRU 默认保护前台业务
    
    // 规则：极高的顺序访问比率 -> 判定为 LevelDB Compaction 线程
    if (seq_ratio > 0.9f) {
        policy = 1; // POLICY_MRU (快速驱逐，不污染 Cache)
    }


    // 3. 反向注入：获取线程的 pidfd 并下发策略到 BPF Task Storage
    int pidfd = syscall(SYS_pidfd_open, e->tid, 0);
    if (pidfd >= 0) {
        // 使用 pidfd 作为 key 更新 task storage
        int err = bpf_map_update_elem(policy_fd, &pidfd, &policy, BPF_ANY);
        if (err == 0) {
            printf("[🧠 Agent] TID: %u | SeqRatio: %.2f | AvgStride: %.1f -> Policy: %s\n", 
                   e->tid, seq_ratio, avg_stride, policy == 1 ? "🔴 MRU (Evict)" : "🟢 LRU (Protect)");
        }
        close(pidfd);
    } else {
        // 线程可能已经死掉，忽略即可
    }
    
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

    // 获取 policy_storage 的 File Descriptor
    int policy_fd = bpf_map__fd(skel->maps.policy_storage);

    // 建立 RingBuffer 高速通道，绑定处理函数，并把 policy_fd 作为 ctx 传进去
    rb = ring_buffer__new(bpf_map__fd(skel->maps.feature_ringbuf), handle_event, &policy_fd, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("🚀 Chameleon Control Plane started! Monitoring memory access patterns...\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // 💀 死循环：高速拉取内核态特征并实时决策
    while (!exiting) {
        // 轮询 RingBuffer，超时时间 100ms
        ring_buffer__poll(rb, 100); 
    }

cleanup:
    if (rb) ring_buffer__free(rb);
    if (cgroup_fd >= 0) close(cgroup_fd);
    if (link) bpf_link__destroy(link);
    if (skel) chameleon_bpf__destroy(skel);
    printf("\n🛑 Chameleon Control Plane stopped and cleaned up.\n");
    return 0;
}