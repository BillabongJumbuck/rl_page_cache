#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>

struct feature_event {
    uint32_t window_id;
    uint32_t seq_ratio_10000;
    uint32_t avg_irr;
    uint32_t unique_ratio_10000;
    uint32_t irr_0_1k_ratio;
    uint32_t irr_1k_10k_ratio;
    uint32_t irr_10k_plus_ratio;
};

const char *PIN_FEATURE_PATH = "/sys/fs/bpf/cml_feature_events";
static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

// RingBuffer 回调函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct feature_event *e = (const struct feature_event *)data;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    // 核心修改 1：将特征流极其干净地打向 stdout，并立即 fflush 强制刷新管道
    fprintf(stdout, "%ld.%09ld,%u,%u,%u,%u,%u,%u,%u\n",
            ts.tv_sec, ts.tv_nsec,
            e->window_id,
            e->seq_ratio_10000, e->avg_irr, e->unique_ratio_10000,
            e->irr_0_1k_ratio, e->irr_1k_10k_ratio, e->irr_10k_plus_ratio);
    
    fflush(stdout); 
    return 0;
}

int main() {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 核心修改 2：把表头也打向 stdout，Python 端接收后会主动丢弃这一行
    fprintf(stdout, "timestamp,window_id,seq_ratio,avg_irr,unique_ratio,irr_0_1k,irr_1k_10k,irr_10k_plus\n");
    fflush(stdout);

    int map_fd = bpf_obj_get(PIN_FEATURE_PATH);
    if (map_fd < 0) {
        // 核心修改 3：所有的报错和日志，一律走 stderr
        fprintf(stderr, "❌ Failed to open pinned RingBuffer at %s\n", PIN_FEATURE_PATH);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer!\n");
        close(map_fd);
        return 1;
    }

    // 走 stderr，确保不会污染 Python 的数据管道
    fprintf(stderr, "📡 [Data Streamer] Live! Pumping eBPF feature stream to stdout...\n");

    while (!exiting) {
        int err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "⚠️ Error polling ring buffer: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    close(map_fd);
    fprintf(stderr, "\n🛑 [Data Streamer] Stopped.\n");
    return 0;
}