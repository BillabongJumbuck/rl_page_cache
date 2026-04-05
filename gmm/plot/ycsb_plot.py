#!/usr/bin/env python3
import os
import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. 配置参数
# ==========================================
ROOT_DIR = "/home/messidor/rl_page_cache/gmm/"  # 日志文件所在目录
LOG_DIR = os.path.join(ROOT_DIR, "log", "ycsb_eval")  # 存放 YCSB 日志的子目录
OUTPUT_IMG = os.path.join(ROOT_DIR, "eval", "leveldb","ycsb_full_results.png")

STRATEGY_MAP = {
    "standard_lru": "Linux LRU",
    "mglru": "MGLRU",
    "ai_agent": "AI Agent"
}

# ==========================================
# 2. 解析日志文件
# ==========================================
data = []
filename_pattern = re.compile(r"ycsb_(.*)_([a-f])_run(\d)\.log")
ops_pattern = re.compile(r"Run throughput\(ops/sec\):\s+([\d\.]+)")

print("📥 正在解析并提取 54 份原始日志数据...")

for filename in os.listdir(LOG_DIR):
    match = filename_pattern.match(filename)
    if not match:
        continue
        
    strategy_raw = match.group(1)
    workload = match.group(2).upper()
    run_id = int(match.group(3))
    
    filepath = os.path.join(LOG_DIR, filename)
    with open(filepath, "r") as f:
        content = f.read()
        ops_match = ops_pattern.search(content)
        if ops_match:
            data.append({
                "Workload": workload,
                "Strategy": STRATEGY_MAP.get(strategy_raw, strategy_raw),
                "Run": run_id,
                "OPS": float(ops_match.group(1))
            })

df = pd.DataFrame(data)

if df.empty:
    print("❌ 提取失败，请检查目录和文件格式！")
    exit(1)

# ==========================================
# 3. 数据透视与排序 (构建 54 根柱子的数据结构)
# ==========================================
# 将数据透视为: 行是 Workload，列是 (Strategy, Run) 的多级索引
pivot_df = df.pivot_table(index='Workload', columns=['Strategy', 'Run'], values='OPS')

# 强制规定柱子的从左到右排列顺序
# strategies = ["Linux LRU", "MGLRU", "AI Agent"]
strategies = ["Linux LRU", "AI Agent"]
col_order = [(s, r) for s in strategies for r in [1, 2, 3]]

# 过滤出实际存在的列并重新排序
existing_cols = [c for c in col_order if c in pivot_df.columns]
pivot_df = pivot_df[existing_cols]

# 保存为 CSV 以备后续分析（可选）
pivot_df.to_csv(os.path.join(ROOT_DIR, "eval", "leveldb", "ycsb_full_results.csv"))
print("✅ 数据提取与透视完成，已保存为 CSV 文件。")

# ==========================================
# 4. 同色系渐变填色 (区分 3 次不同 Run)
# ==========================================
colors = []
for s, r in existing_cols:
    if s == "Linux LRU":
        colors.append(['#a1c9f4', '#7ca8e0', '#5688c7'][r-1]) # 蓝色系
    elif s == "MGLRU":
        colors.append(['#ffb482', '#f2955a', '#e37533'][r-1]) # 橙色系
    elif s == "AI Agent":
        colors.append(['#8de5a1', '#5cc977', '#2eab4e'][r-1]) # 绿色系

# ==========================================
# 5. 绘制超宽直方图
# ==========================================
print("🎨 正在绘制 54 柱直方图...")
# 稍微加宽画布以容纳 54 根柱子
ax = pivot_df.plot(kind='bar', figsize=(18, 7), color=colors, edgecolor='black', width=0.85)

plt.title("YCSB Benchmarks: Absolute Throughput across All Runs", fontsize=16, fontweight="bold", pad=20)
plt.xlabel("YCSB Workload Type", fontsize=14, fontweight="bold")
plt.ylabel("Throughput (OPS)", fontsize=14, fontweight="bold")
plt.xticks(rotation=0, fontsize=14)

# 定制图例 (放在图表右侧外围，防止挡住柱子)
handles, _ = ax.get_legend_handles_labels()
new_labels = [f"{s} (Run {r})" for s, r in existing_cols]
plt.legend(handles, new_labels, title="Strategy & Run Number", bbox_to_anchor=(1.01, 1), loc='upper left', fontsize=11)

plt.tight_layout()
plt.savefig(OUTPUT_IMG, dpi=300)
print(f"✅ 大功告成！无均值版 54 柱图已保存至: {OUTPUT_IMG}")