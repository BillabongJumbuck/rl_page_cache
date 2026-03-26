#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>

// 引入上一步导出的 AI 大脑参数
#include "gmm_weights.h"

#define POLICY_LRU 0
#define POLICY_MRU 1
#define POLICY_LFU 2

#define REQUIRED_VOTES 5
#define MATH_PI 3.14159265358979323846

const char *PIN_FEATURE_PATH = "/sys/fs/bpf/cml_feature_events";
const char *PIN_PARAMS_PATH = "/sys/fs/bpf/cml_params_map";

static volatile bool exiting = false;
static int params_map_fd = -1;

static int current_policy = -1;
static int candidate_policy = -1;
static int votes = 0;

// 1. 策略映射表 (C++ 版)
static int policy_map[N_CLUSTERS] = {
    POLICY_MRU, // Cluster 0: 纯大扫表阅后即焚
    POLICY_LFU, // Cluster 1: Zipfian 核心死保
    POLICY_MRU, // Cluster 2: 冷启动幽灵
    POLICY_LRU  // Cluster 3: 经典退避防守
};

static const char* policy_names[] = {"LRU", "MRU", "LFU"};

struct feature_event {
    uint32_t window_id;
    uint32_t seq_ratio_10000;
    uint32_t avg_irr;
    uint32_t unique_ratio_10000;
    uint32_t irr_0_1k_ratio;
    uint32_t irr_1k_10k_ratio;
    uint32_t irr_10k_plus_ratio;
};

// ==========================================
// 🧠 核心：GMM 前向推理引擎 (纯 C++ 实现，0 依赖)
// ==========================================
double clip(double v, double min_v, double max_v) {
    return fmax(min_v, fmin(v, max_v));
}

int predict_gmm(const double features[N_FEATURES]) {
    double scaled[N_FEATURES];
    // 1. StandardScaler
    for (int i = 0; i < N_FEATURES; i++) {
        scaled[i] = (features[i] - scaler_mean[i]) / scaler_scale[i];
    }

    int best_cluster = -1;
    double max_log_prob = -INFINITY;

    // 2. GMM Log-Likelihood 计算
    for (int k = 0; k < N_CLUSTERS; k++) {
        double y[N_FEATURES] = {0};
        
        // 矩阵乘法：y = (X - mu) * Precisions_Chol
        for (int j = 0; j < N_FEATURES; j++) {
            double diff = scaled[j] - gmm_means[k][j];
            for (int m = 0; m < N_FEATURES; m++) {
                y[m] += diff * gmm_precisions_chol[k][j][m];
            }
        }

        double sum_y2 = 0;
        double log_det_chol = 0;
        for (int m = 0; m < N_FEATURES; m++) {
            sum_y2 += y[m] * y[m];
            log_det_chol += log(gmm_precisions_chol[k][m][m]);
        }

        double log_prob = log(gmm_weights[k]) + log_det_chol - 0.5 * (N_FEATURES * log(2 * MATH_PI) + sum_y2);

        if (log_prob > max_log_prob) {
            max_log_prob = log_prob;
            best_cluster = k;
        }
    }
    return best_cluster;
}

static void sig_handler(int sig) { exiting = true; }

// ==========================================
// ⚡ 事件回调：直连 eBPF，内存操作
// ==========================================
static int handle_event(void *ctx, void *data, size_t data_sz) {
    const struct feature_event *e = (const struct feature_event *)data;
    
    // 1. 特征提取与预处理
    double raw_avg_irr = (double)e->avg_irr;
    double features[N_FEATURES] = {
        clip((double)e->seq_ratio_10000, 0, 10000),
        log1p(raw_avg_irr),
        clip((double)e->unique_ratio_10000, 0, 10000),
        clip((double)e->irr_0_1k_ratio, 0, 10000),
        clip((double)e->irr_1k_10k_ratio, 0, 10000),
        clip((double)e->irr_10k_plus_ratio, 0, 10000)
    };

    // 2. 纳秒级推理
    int cluster = predict_gmm(features);
    int target_policy = policy_map[cluster];

    // 3. 打印心电图
    double seq_pct = features[0] / 100.0;
    double uniq_pct = features[2] / 100.0;
    printf("📊 [W: %4u] Seq: %5.1f%% | IRR: %8u | Uniq: %5.1f%% ➡️  🧠 判定为 C%d (%s)\n",
           e->window_id, seq_pct, e->avg_irr, uniq_pct, cluster, policy_names[target_policy]);

    // 4. 状态机防抖 & 直接内存写 Map 下发策略
    if (target_policy == current_policy) {
        votes = 0;
        candidate_policy = -1;
    } else {
        if (target_policy == candidate_policy) {
            votes++;
        } else {
            candidate_policy = target_policy;
            votes = 1;
        }

        if (votes >= REQUIRED_VOTES) {
            printf("------------------------------------------------------------\n");
            printf("🚨🚨 确诊相位突变！已连续 %d 票命中 Cluster %d -> 稳健下发内核策略: %s\n", 
                   REQUIRED_VOTES, cluster, policy_names[target_policy]);
            printf("------------------------------------------------------------\n");

            // 🚀 终极杀器：绕过 bpftool，直接用 bpf_map_update_elem 修改内核状态！开销 < 1 微秒！
            if (params_map_fd >= 0) {
                uint32_t key = 0;
                struct { uint32_t active_policy; } val = { (uint32_t)target_policy };
                bpf_map_update_elem(params_map_fd, &key, &val, BPF_ANY);
            }

            current_policy = target_policy;
            candidate_policy = -1;
            votes = 0;
        }
    }
    return 0;
}

int main() {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("🤖 [Agent] 正在加载 C++ 原生大脑 (GMM & Scaler)...\n");

    // 1. 获取控制面 Map 的文件描述符 (替代底层的 bpftool)
    params_map_fd = bpf_obj_get(PIN_PARAMS_PATH);
    if (params_map_fd < 0) {
        fprintf(stderr, "❌ Failed to open params map at %s\n", PIN_PARAMS_PATH);
        return 1;
    }

    // 2. 获取数据面 RingBuffer
    int map_fd = bpf_obj_get(PIN_FEATURE_PATH);
    if (map_fd < 0) {
        fprintf(stderr, "❌ Failed to open pinned RingBuffer at %s\n", PIN_FEATURE_PATH);
        close(params_map_fd);
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "❌ Failed to create ring buffer!\n");
        close(map_fd);
        close(params_map_fd);
        return 1;
    }

    printf("🚀 [Agent] C++ 控制面全速上线！直接挂载 eBPF 内存，无管线延迟！\n");
    printf("============================================================\n");

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
    close(params_map_fd);
    printf("\n🛑 [Agent] 退出完成。\n");
    return 0;
}