// data_collector.c: 负责从 eBPF 程序收集特征数据并写入 CSV 文件，供后续模型训练使用。
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>

// 保持和 eBPF 中完全一致的结构体定义
struct feature_event {
    uint32_t tid;
    uint32_t window_id;
    uint32_t seq_ratio_10000;    
    uint32_t hot_ratio_10000;
    uint32_t new_ratio_10000;   
};

const char *PIN_FEATURE_PATH = "/sys/fs/bpf/cml_feature_events";
FILE *csv_file = NULL;
static volatile bool exiting = false;

static void sig_handler(int sig) { exiting = true; }

// RingBuffer 回调函数
static int handle_event(void *ctx, void *data, size_t data_sz) {
    // 🛡️ 安全防御：防止 BPF 侧结构体变更导致的内存越界
    if (data_sz < sizeof(struct feature_event)) {
        fprintf(stderr, "[Warn] Dropping malformed event (size %zu < expected %zu)\n", 
                data_sz, sizeof(struct feature_event));
        return 0;
    }

    const struct feature_event *e = (const struct feature_event *)data;
    
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    
    // ⚡ 核心修改：精简 CSV 字段输出
    fprintf(csv_file, "%ld.%09ld,%u,%u,%u,%u,%u\n",
            ts.tv_sec, ts.tv_nsec,
            e->tid,
            e->window_id,
            e->seq_ratio_10000, 
            e->hot_ratio_10000,
            e->new_ratio_10000);
    
    // 强制刷新，防止程序异常退出时数据丢失
    fflush(csv_file);
    return 0;
}

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 默认路径
    const char *csv_path = "./memory_features.csv";

    // 如果用户提供了参数，则使用该路径
    if (argc > 1) {
        csv_path = argv[1];
    }

    // 1. 打开 CSV 文件并写入表头
    csv_file = fopen(csv_path, "w");
    if (!csv_file) {
        perror("Failed to open CSV file");
        return 1;
    }

    fprintf(csv_file, "timestamp,tid,window_id,seq_ratio,hot_ratio,new_ratio\n");
    fflush(csv_file);

    // 2. 获取 pinned RingBuffer
    int map_fd = bpf_obj_get(PIN_FEATURE_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open pinned RingBuffer at %s\n", PIN_FEATURE_PATH);
        fclose(csv_file);
        return 1;
    }

    // 3. 创建 RingBuffer
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer!\n");
        close(map_fd);
        fclose(csv_file);
        return 1;
    }

    printf("📡 [Data Collector] Writing to %s\n", csv_path);

    // 4. 轮询
    while (!exiting) {
        int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    // 5. 清理
    ring_buffer__free(rb);
    close(map_fd);
    fclose(csv_file);

    printf("\n🛑 [Data Collector] Stopped. CSV file saved.\n");
    return 0;
}