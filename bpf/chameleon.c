// chameleon.c: eBPF 用户态 Agent (支持数据收集与纯加载模式)
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

typedef uint64_t u64;
typedef uint32_t u32;

#include "chameleon.skel.h"

#define DATA_COLLECT // 🌟 开启数据收集功能，方便用户态训练和分析

// 定义 Pin 到文件系统的路径
#define PIN_BASE_DIR "/sys/fs/bpf/chameleon"
#define POLICY_MAP_PIN_PATH PIN_BASE_DIR "/ai_policy_map"
#define STATS_MAP_PIN_PATH PIN_BASE_DIR "/runtime_stats"

#ifdef DATA_COLLECT
#define RINGBUF_PIN_PATH PIN_BASE_DIR "/feature_ringbuf"

// 必须与 BPF 程序中的特征结构体绝对对齐
struct feature_event {
    u32 tid;
    u32 access_count;
    u32 seq_count;
    u32 unique_pages;
    u64 stride_sum;
    u64 duration_ns;
};

struct runtime_stats {
    u64 counters[6];
};

enum runtime_stat_idx {
    STAT_MRU_ADD = 0,
    STAT_MRU_MOVE = 1,
    STAT_MRU_EVICT = 2,
    STAT_TOTAL_EVICT = 3,
    STAT_POLICY_SYNC = 4,
    STAT_POLICY_MISS = 5,
};

static unsigned g_flush_every = 64;
static unsigned g_pending_lines = 0;
static int g_stats_interval_sec = 5;
static int g_enable_stats = 1;

// ==========================================
// 📊 遥测引擎 (CSV 输出模式) - 仅在收集数据时编译
// ==========================================
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct feature_event *e = data;

    float seq_ratio = (float)e->seq_count / (float)e->access_count; 
    float avg_stride = (float)e->stride_sum / (float)e->access_count;
    float unique_ratio = (float)e->unique_pages / (float)e->access_count;
    
    // 计算吞吐量 IOPS (次/秒)
    float iops = 0;
    if (e->duration_ns > 0) {
        iops = ((float)e->access_count / (float)e->duration_ns) * 1e9;
    }
    // 纯净的 CSV 格式输出
    printf("%u,%.1f,%.2f,%.1f,%.2f\n", 
           e->tid, iops, seq_ratio, avg_stride, unique_ratio);

    // 减少 flush 调用频率，降低用户态 IO 开销。
    g_pending_lines++;
    if (g_pending_lines >= g_flush_every) {
        fflush(stdout);
        g_pending_lines = 0;
    }
    
    return 0;
}
#endif // DATA_COLLECT

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

static int print_runtime_stats(struct chameleon_bpf *skel, struct runtime_stats *last) {
    u32 key = 0;
    struct runtime_stats cur = {};
    int stats_fd = bpf_map__fd(skel->maps.runtime_stats_map);
    if (stats_fd < 0) {
        return -1;
    }

    if (bpf_map_lookup_elem(stats_fd, &key, &cur) != 0) {
        return -1;
    }

    u64 d_add = cur.counters[STAT_MRU_ADD] - last->counters[STAT_MRU_ADD];
    u64 d_move = cur.counters[STAT_MRU_MOVE] - last->counters[STAT_MRU_MOVE];
    u64 d_mru_evict = cur.counters[STAT_MRU_EVICT] - last->counters[STAT_MRU_EVICT];
    u64 d_total_evict = cur.counters[STAT_TOTAL_EVICT] - last->counters[STAT_TOTAL_EVICT];
    u64 d_sync = cur.counters[STAT_POLICY_SYNC] - last->counters[STAT_POLICY_SYNC];
    u64 d_miss = cur.counters[STAT_POLICY_MISS] - last->counters[STAT_POLICY_MISS];

    fprintf(stderr,
            "[bpf-stats] add=%llu(+%llu) move=%llu(+%llu) mru_evict=%llu(+%llu) total_evict=%llu(+%llu) sync=%llu(+%llu) miss=%llu(+%llu)\n",
            (unsigned long long)cur.counters[STAT_MRU_ADD], (unsigned long long)d_add,
            (unsigned long long)cur.counters[STAT_MRU_MOVE], (unsigned long long)d_move,
            (unsigned long long)cur.counters[STAT_MRU_EVICT], (unsigned long long)d_mru_evict,
            (unsigned long long)cur.counters[STAT_TOTAL_EVICT], (unsigned long long)d_total_evict,
            (unsigned long long)cur.counters[STAT_POLICY_SYNC], (unsigned long long)d_sync,
            (unsigned long long)cur.counters[STAT_POLICY_MISS], (unsigned long long)d_miss);

    *last = cur;
    return 0;
}

// 辅助函数：确保目录存在
static int ensure_pin_dir(void) {
    if (access(PIN_BASE_DIR, F_OK) != 0) {
        if (mkdir(PIN_BASE_DIR, 0755) && errno != EEXIST) {
            perror("Failed to create pin directory");
            return -1;
        }
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
    int cgroup_fd = -1;
    
#ifdef DATA_COLLECT
    struct ring_buffer *rb = NULL;
#endif

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

    if (ensure_pin_dir() < 0) goto cleanup;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    skel = chameleon_bpf__open_and_load(); 
    if (!skel) goto cleanup;

    // ==========================================
    // 📌 将 Maps Pin 到文件系统
    // ==========================================
    
    // AI Policy Map 永远都需要 Pin，因为 Python 推理端要写入
    bpf_map__unpin(skel->maps.ai_policy_map, POLICY_MAP_PIN_PATH);
    if (bpf_map__pin(skel->maps.ai_policy_map, POLICY_MAP_PIN_PATH) < 0) {
        fprintf(stderr, "Failed to pin ai_policy_map\n");
        goto cleanup;
    }

#ifdef DATA_COLLECT
    bpf_map__unpin(skel->maps.runtime_stats_map, STATS_MAP_PIN_PATH);
    if (bpf_map__pin(skel->maps.runtime_stats_map, STATS_MAP_PIN_PATH) < 0) {
        fprintf(stderr, "Failed to pin runtime_stats_map\n");
        goto cleanup;
    }

    // RingBuffer 只有在收集数据模式下才 Pin
    bpf_map__unpin(skel->maps.feature_ringbuf, RINGBUF_PIN_PATH);
    if (bpf_map__pin(skel->maps.feature_ringbuf, RINGBUF_PIN_PATH) < 0) {
        fprintf(stderr, "Failed to pin feature_ringbuf\n");
        goto cleanup;
    }
    fprintf(stderr, "📌 Both Maps pinned to %s\n", PIN_BASE_DIR);
#else
    fprintf(stderr, "📌 AI Policy Map pinned to %s\n", PIN_BASE_DIR);
#endif

    // ==========================================
    // 🔗 挂载 BPF 程序到 Cgroup
    // ==========================================
    link = bpf_map__attach_cache_ext_ops(skel->maps.chameleon_ops, cgroup_fd);
    if (!link) {
        fprintf(stderr, "Failed to attach cache_ext_ops\n");
        goto cleanup;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

#ifdef DATA_COLLECT
    // 初始化 RingBuffer 进行监听
    rb = ring_buffer__new(bpf_map__fd(skel->maps.feature_ringbuf), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    fprintf(stderr, "🚀 Chameleon Data Collector started!\n");
    printf("TID,IOPS,SeqRatio,AvgStride,UniqRatio\n"); // 🖨️ 打印 CSV 表头到标准输出
    fflush(stdout);

    struct runtime_stats last_stats = {};
    time_t last_stats_ts = time(NULL);
    
    // 死循环：拉取遥测特征
    const char *flush_env = getenv("CHAMELEON_FLUSH_EVERY");
    if (flush_env) {
        int v = atoi(flush_env);
        if (v > 0 && v <= 4096) {
            g_flush_every = (unsigned)v;
        }
    }

    const char *stats_env = getenv("CHAMELEON_STATS_INTERVAL");
    if (stats_env) {
        int v = atoi(stats_env);
        if (v >= 1 && v <= 60) {
            g_stats_interval_sec = v;
        }
    }

    const char *enable_stats_env = getenv("CHAMELEON_ENABLE_STATS");
    if (enable_stats_env && atoi(enable_stats_env) == 0) {
        g_enable_stats = 0;
    }
    while (!exiting) {
        ring_buffer__poll(rb, 100);
        time_t now = time(NULL);
        if (g_enable_stats && now - last_stats_ts >= g_stats_interval_sec) {
            print_runtime_stats(skel, &last_stats);
            last_stats_ts = now;
        }
    }
#else
    fprintf(stderr, "🚀 Chameleon Loader started in INFERENCE MODE. Waiting for Python AI Agent...\n");
    // 在纯推理模式下，C 程序无事可做，只需保持运行不退出即可（防止 link 销毁）
    while (!exiting) {
        sleep(1); 
    }
#endif

cleanup:
#ifdef DATA_COLLECT
    if (rb) ring_buffer__free(rb);
    fflush(stdout);
#endif
    
    // 退出时清理 pinned files
    if (skel) {
        bpf_map__unpin(skel->maps.ai_policy_map, POLICY_MAP_PIN_PATH);
#ifdef DATA_COLLECT
        bpf_map__unpin(skel->maps.feature_ringbuf, RINGBUF_PIN_PATH);
    bpf_map__unpin(skel->maps.runtime_stats_map, STATS_MAP_PIN_PATH);
#endif
        fprintf(stderr, "🧹 Pinned maps unpinned.\n");
    }

    if (cgroup_fd >= 0) close(cgroup_fd);
    if (link) bpf_link__destroy(link);
    if (skel) chameleon_bpf__destroy(skel);
    fprintf(stderr, "\n🛑 Chameleon stopped and cleaned up.\n");
    return 0;
}