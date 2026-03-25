#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <time.h>

// 保持和 eBPF 中完全一致的结构体定义
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
FILE *csv_file = NULL;
static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

// RingBuffer 回调函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct feature_event *e = (const struct feature_event *)data;
    
    // 获取当前时间戳
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    // 写入 CSV
    fprintf(csv_file, "%ld.%09ld,%u,%u,%u,%u,%u,%u,%u\n",
            ts.tv_sec, ts.tv_nsec,
            e->window_id,
            e->seq_ratio_10000, e->avg_irr, e->unique_ratio_10000,
            e->irr_0_1k_ratio, e->irr_1k_10k_ratio, e->irr_10k_plus_ratio);
    
    fflush(csv_file); // 确保数据实时落盘
    return 0;
}

int main() {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 1. 打开 CSV 文件并写入表头
    csv_file = fopen("memory_features.csv", "w");
    if (!csv_file) {
        perror("Failed to open CSV file");
        return 1;
    }
    fprintf(csv_file, "timestamp,window_id,seq_ratio,avg_irr,unique_ratio,irr_0_1k,irr_1k_10k,irr_10k_plus\n");
    fflush(csv_file);

    // 2. 从虚拟文件系统获取 Pinned RingBuffer 的文件描述符
    int map_fd = bpf_obj_get(PIN_FEATURE_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open pinned RingBuffer at %s\n", PIN_FEATURE_PATH);
        fclose(csv_file);
        return 1;
    }

    // 3. 配置并启动 RingBuffer 轮询
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer!\n");
        close(map_fd);
        fclose(csv_file);
        return 1;
    }

    printf("📡 [Data Collector] Listening to eBPF RingBuffer. Writing to memory_features.csv...\n");

    // 4. 持续轮询，直到接收到 Ctrl+C
    while (!exiting) {
        int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // 5. 优雅清理
    ring_buffer__free(rb);
    close(map_fd);
    fclose(csv_file);
    printf("\n🛑 [Data Collector] Stopped. CSV file saved.\n");
    return 0;
}