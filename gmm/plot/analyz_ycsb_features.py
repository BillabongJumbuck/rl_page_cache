import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import glob
import os

ROOT_DIR = "/home/messidor/rl_page_cache/gmm/"  # 日志文件所在目录
CSV_DIR = os.path.join(ROOT_DIR, "feature_data")  # 存放 YCSB 日志的子目录
OUTPUT_IMG = os.path.join(ROOT_DIR, "plot","ycsb_full_results.png")

# 设置图表风格
sns.set_theme(style="whitegrid")
plt.rcParams['figure.figsize'] = (15, 10)

# 读取所有收集到的 CSV 文件
csv_files = glob.glob(os.path.join(CSV_DIR, "ycsb_workload_*.csv"))

fig, axes = plt.subplots(2, 3, figsize=(20, 12))
axes = axes.flatten()

for i, file in enumerate(csv_files):
    # 解析 workload 名称 (假设文件名如 ycsb_workload_a.csv)
    wl_name = os.path.basename(file).split('_')[2].split('.')[0].upper()
    
    df = pd.read_csv(file)
    
    # 过滤掉刚启动时的噪音数据 (前几个 window)
    # df = df[df['window_id'] > 10]
    
    # 绘制散点图: X轴是顺序比例, Y轴是平均重用距离
    # 用 TID 区分颜色，观察多线程的聚类现象
    sns.scatterplot(
        data=df, 
        x='seq_ratio', 
        y='avg_stride', 
        hue='tid', 
        palette='tab10',
        alpha=0.6,
        ax=axes[i],
        legend=False # 线程太多的话关掉图例避免遮挡
    )
    
    axes[i].set_title(f"YCSB Workload {wl_name}")
    axes[i].set_xlim(0, 1.1)
    axes[i].set_ylabel('Average Stride (0-100000)')
    axes[i].set_xlabel('Sequential Ratio (0-1)')

plt.tight_layout()
plt.savefig(OUTPUT_IMG, dpi=300)