#!/usr/bin/env python3
import pandas as pd
import numpy as np
import os

# 1. 加载数据
filepath = './memory_features.csv' # 根据你的实际路径调整
if not os.path.exists(filepath):
    filepath = 'memory_features.csv'

print(f"📥 正在加载数据集: {filepath}")
df = pd.read_csv(filepath)
total_samples = len(df)
print(f"✅ 成功加载 {total_samples} 个采样窗口 (约 {total_samples * 10000} 次物理访存).\n")

# 丢弃非特征列
feature_cols = ['seq_ratio', 'avg_irr', 'unique_ratio', 'irr_0_1k', 'irr_1k_10k', 'irr_10k_plus']
X = df[feature_cols]

# ==========================================
# 📊 1. 基础健康度体检 (Sanity Checks)
# ==========================================
print("🩺 --- 基础健康度体检 ---")
# 检查是否有 NaN
if X.isnull().sum().sum() > 0:
    print("❌ 警告：数据中包含 NaN 空值！探针可能存在内存越界或除零错误。")
else:
    print("✔️ 数据完整性：100% (无缺失值)")

# 检查 Ratio 是否越界 (由于放大了 10000 倍，理论上必须在 0 ~ 10000 之间)
ratio_cols = ['seq_ratio', 'unique_ratio', 'irr_0_1k', 'irr_1k_10k', 'irr_10k_plus']
out_of_bounds = (X[ratio_cols] > 10000).sum().sum() + (X[ratio_cols] < 0).sum().sum()
if out_of_bounds > 0:
    print(f"❌ 警告：发现 {out_of_bounds} 个 Ratio 数据越界 (>10000 或 <0)，请检查探针数学运算！")
else:
    print("✔️ 特征边界：所有比例特征均严格限制在 [0, 10000] 范围内。")


# ==========================================
# 🔬 2. 核心物理语义校验 (Physics Validation)
# ==========================================
print("\n🔬 --- 核心物理语义校验 ---")

# A. 大页修复校验：Seq Ratio 是否突破了之前的 2.1% 魔咒？
max_seq = X['seq_ratio'].max() / 100.0
mean_seq = X['seq_ratio'].mean() / 100.0
print(f"👉 连续性 (Seq Ratio):")
print(f"   - 全局平均: {mean_seq:.1f}%")
print(f"   - 峰值连续: {max_seq:.1f}% ", end="")
if max_seq > 80.0:
    print("✅ (太棒了！探针已成功识别出大页和预读扫表！)")
else:
    print("❌ (警告：峰值依然很低，1MB 大页修复可能未生效或 FIO 并发太高打碎了连续性！)")

# B. IRR 极化校验：重访距离是否跨越了数量级？
max_irr = X['avg_irr'].max()
median_irr = X['avg_irr'].median()
print(f"👉 重访距离 (Avg IRR):")
print(f"   - 中位数: {median_irr:.0f} 次")
print(f"   - 峰值重访: {max_irr:,.0f} 次 ", end="")
if max_irr > 1000000:
    print("✅ (成功捕捉到跨越整个物理内存周期的宏观大扫表！)")
else:
    print("⚠️ (峰值未破百万，内存压力可能不足，或运行时长不够)")


# ==========================================
# 🌪️ 3. 负载多态性分析 (Multimodality Analysis)
# ==========================================
print("\n🌪️ --- 负载多态性分析 (衡量靶场质量) ---")
# 完美的靶场数据应该呈现明显的“两极分化”：要么极高，要么极低，而不是全都挤在中间
high_seq_ratio = (X['seq_ratio'] > 8000).mean() * 100
low_seq_ratio  = (X['seq_ratio'] < 1000).mean() * 100
print(f"   - 纯顺序扫表 (Seq > 80%) 占比: {high_seq_ratio:.1f}%")
print(f"   - 纯随机乱序 (Seq < 10%) 占比: {low_seq_ratio:.1f}%")

high_uniq = (X['unique_ratio'] > 9000).mean() * 100
low_uniq  = (X['unique_ratio'] < 6000).mean() * 100
print(f"   - 全新冷数据 (Uniq > 90%) 占比: {high_uniq:.1f}%")
print(f"   - 强热点重访 (Uniq < 60%) 占比: {low_uniq:.1f}%")

if high_seq_ratio > 5 and low_seq_ratio > 5 and high_uniq > 5 and low_uniq > 5:
    print("\n🏆 结论：这真是一份极品靶场数据！时空特征极度丰富且撕裂，GMM 绝对能切出极美的 4 聚类！")
else:
    print("\n⚠️ 结论：数据缺乏两极分化。如果你看到某个极端情况占比为 0%，说明靶场的那个 Phase 没有成功在 eBPF 中留下印记。")