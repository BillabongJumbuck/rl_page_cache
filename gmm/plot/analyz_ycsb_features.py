import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import glob
import os

ROOT_DIR = "/home/messidor/rl_page_cache/gmm/"  # 日志文件所在目录
CSV_DIR = os.path.join(ROOT_DIR, "feature_data")  # 存放 YCSB 日志的子目录
OUTPUT_IMG = os.path.join(ROOT_DIR, "plot", "ycsb_3d_features.png")

# 确保输出目录存在
os.makedirs(os.path.dirname(OUTPUT_IMG), exist_ok=True)

# 设置图表风格
sns.set_theme(style="whitegrid")
plt.rcParams['figure.figsize'] = (24, 14) # 稍微调大一点适应 6 个图和三维信息的密度

# 读取所有收集到的 CSV 文件
csv_files = glob.glob(os.path.join(CSV_DIR, "ycsb_workload_*.csv"))

fig, axes = plt.subplots(2, 3, figsize=(24, 14))
axes = axes.flatten()

for i, file in enumerate(csv_files):
    # 解析 workload 名称 (假设文件名如 ycsb_workload_a.csv)
    wl_name = os.path.basename(file).split('_')[2].split('.')[0].upper()
    
    df = pd.read_csv(file)
    
    # 过滤掉刚启动时的噪音数据 (前几个 window)
    df = df[df['window_id'] > 10]
    
    # 绘制散点图
    # 巧妙利用 size 属性，在 2D 平面上展示 3D 特征！
    sns.scatterplot(
        data=df, 
        x='seq_ratio', 
        y='new_ratio', 
        hue='tid', 
        size='hot_ratio',
        sizes=(10, 300), # 控制散点大小的范围：越热的点越大
        palette='tab10',
        alpha=0.7,
        ax=axes[i],
        legend=False # 依然关掉图例避免遮挡
    )
    
    axes[i].set_title(f"YCSB Workload {wl_name}", fontsize=16, fontweight='bold')
    
    # 🌟 革命性的变化：三个特征现在全都是 0-10000 的纯线性比例！
    axes[i].set_xlim(0, 10500)
    axes[i].set_ylim(0, 10500)
    
    axes[i].set_xlabel('Sequential Ratio (0-10000)')
    axes[i].set_ylabel('New Page Exploration Ratio (0-10000)')

plt.tight_layout()
plt.savefig(OUTPUT_IMG, dpi=300)
print(f"✅ 3D 特征映射图表已保存至: {OUTPUT_IMG}")