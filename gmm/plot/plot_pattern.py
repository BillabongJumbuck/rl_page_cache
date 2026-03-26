#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import os
import sys

# 配置你的日志路径 (请确保与收集脚本里的路径一致)
CSV_FILE = '/home/messidor/rl_page_cache/gmm/eval/ripgrep/memory_features.csv'
OUTPUT_IMG = '/home/messidor/rl_page_cache/gmm/eval/ripgrep/rg_access_pattern.png'

print(f"🔍 正在解析底层探针数据: {CSV_FILE}")

if not os.path.exists(CSV_FILE):
    print(f"❌ 找不到日志文件: {CSV_FILE}")
    sys.exit(1)

# 1. 健壮地读取数据 (跳过可能存在的报错信息或 eBPF 启动日志)
data_rows = []
with open(CSV_FILE, 'r') as f:
    for line in f:
        line = line.strip()
        # 识别特征流的标配格式 (包含至少7个逗号，且不是表头)
        if line and line.count(',') >= 7 and not line.startswith('timestamp'):
            try:
                parts = line.split(',')
                data_rows.append({
                    'window_id': int(parts[1]),
                    'seq_ratio': float(parts[2]) / 100.0,   # C++ 端传来的是万分比，除以 100 变成百分比
                    'avg_irr': float(parts[3]),             # 重访间隔
                    'unique_ratio': float(parts[4]) / 100.0 # 唯一率百分比
                })
            except ValueError:
                continue

if not data_rows:
    print("⚠️ 日志文件中没有提取到有效的特征数据，请检查探针是否正常抓取。")
    sys.exit(1)

df = pd.DataFrame(data_rows)

# 2. 开始绘制高逼格学术图表
print(f"📊 成功提取 {len(df)} 个观测窗口，正在生成心电图...")

# 设置全局字体和清晰度
plt.style.use('seaborn-v0_8-darkgrid')
fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(14, 10), sharex=True)
fig.suptitle('Ripgrep Scan-Once Workload vs 800MB Cgroup Limit\nMemory Access Pattern Analysis', fontsize=16, fontweight='bold')

# --- 子图 1: 连续性 (Sequential Ratio) ---
ax1.plot(df['window_id'], df['seq_ratio'], color='#1f77b4', linewidth=1.5, alpha=0.9)
ax1.set_ylabel('Sequential Ratio (%)', fontsize=12, fontweight='bold')
ax1.set_ylim(-5, 105)
ax1.axhline(y=50, color='r', linestyle='--', alpha=0.3) # 标注 50% 的防守阈值

# --- 子图 2: 唯一性 (Unique Ratio) ---
# 扫表最典型的特征就是极高的唯一性（几乎不回头看）
ax2.plot(df['window_id'], df['unique_ratio'], color='#2ca02c', linewidth=1.5, alpha=0.9)
ax2.set_ylabel('Unique Ratio (%)', fontsize=12, fontweight='bold')
ax2.set_ylim(-5, 105)

# --- 子图 3: 平均重访间隔 (Average IRR) ---
# IRR 的跨度可能极大，使用对数坐标系 (Log Scale) 才能看清全貌
ax3.plot(df['window_id'], df['avg_irr'], color='#d62728', linewidth=1.5, alpha=0.8)
ax3.set_ylabel('Avg IRR (Log Scale)', fontsize=12, fontweight='bold')
ax3.set_yscale('symlog', linthresh=10) # 0附近使用线性，大数值使用对数
ax3.set_xlabel('Time (Window ID)', fontsize=12, fontweight='bold')

# 美化布局并保存
plt.tight_layout()
plt.subplots_adjust(top=0.92) # 给标题留点空间
plt.savefig(OUTPUT_IMG, dpi=300, bbox_inches='tight')

print(f"✅ 绘图完成！图片已保存至: {OUTPUT_IMG}")
print("👉 请在 VS Code 中直接点击打开该图片。")