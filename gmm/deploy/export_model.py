#!/usr/bin/env python3
import joblib
import numpy as np
import os

ROOT_DIR = "/home/messidor/rl_page_cache/gmm/"
scaler = joblib.load(os.path.join(ROOT_DIR, 'model', 'scaler.pkl'))
gmm = joblib.load(os.path.join(ROOT_DIR, 'model', 'gmm_model.pkl'))

n_features = gmm.means_.shape[1]
n_clusters = gmm.n_components

with open('gmm_weights.h', 'w') as f:
    f.write("// ==========================================\n")
    f.write("// AI 大脑权重 (Auto-generated)\n")
    f.write("// ==========================================\n\n")
    f.write(f"#define N_FEATURES {n_features}\n")
    f.write(f"#define N_CLUSTERS {n_clusters}\n\n")

    # Scaler 权重
    f.write(f"const double scaler_mean[N_FEATURES] = {{{', '.join(map(str, scaler.mean_))}}};\n")
    f.write(f"const double scaler_scale[N_FEATURES] = {{{', '.join(map(str, scaler.scale_))}}};\n\n")

    # GMM 权重
    f.write(f"const double gmm_weights[N_CLUSTERS] = {{{', '.join(map(str, gmm.weights_))}}};\n\n")

    f.write("const double gmm_means[N_CLUSTERS][N_FEATURES] = {\n")
    for row in gmm.means_:
        f.write(f"    {{{', '.join(map(str, row))}}},\n")
    f.write("};\n\n")

    # Full Covariance 的 Cholesky 精度矩阵
    f.write("const double gmm_precisions_chol[N_CLUSTERS][N_FEATURES][N_FEATURES] = {\n")
    for mat in gmm.precisions_cholesky_:
        f.write("    {\n")
        for row in mat:
            f.write(f"        {{{', '.join(map(str, row))}}},\n")
        f.write("    },\n")
    f.write("};\n")

print("✅ 大脑权重已成功切片并导出为 gmm_weights.h！")