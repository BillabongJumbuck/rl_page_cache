import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# 设置学术论文风格的绘图参数
plt.style.use('seaborn-v0_8-paper')
plt.rcParams.update({
    'font.size': 12,
    'axes.labelsize': 12,
    'axes.titlesize': 14,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.dpi': 300
})

def load_and_preprocess():
    # 假设 CSV 没有表头，且格式为: TID, IOPS, SeqRatio, AvgStride, UniqRatio
    cols = ['TID', 'IOPS', 'SeqRatio', 'AvgStride', 'UniqRatio']

    def read_and_clean_csv(path, label):
        # 先以字符串读取，避免混合类型导致的推断错误，再统一转数值。
        df = pd.read_csv(path, header=None, names=cols, dtype=str, low_memory=False)
        for col in cols:
            df[col] = pd.to_numeric(df[col], errors='coerce')

        before = len(df)
        df = df.dropna(subset=['SeqRatio', 'AvgStride', 'UniqRatio']).copy()
        # log1p 仅支持 x >= -1，这里步长理论上应非负，直接过滤异常值。
        df = df[df['AvgStride'] >= 0]
        dropped = before - len(df)

        df['Label'] = label
        return df, dropped
    
    try:
        df_mru, dropped_mru = read_and_clean_csv('scan_mru.csv', 'MRU (Scan)')
        
        df_lru, dropped_lru = read_and_clean_csv('rand_lru.csv', 'LRU (Zipfian)')
        
        df = pd.concat([df_mru, df_lru], ignore_index=True)
        # 对 Stride 使用对数变换，方便在图表中展示（加 1 避免 log(0)）
        df['Log_AvgStride'] = np.log1p(df['AvgStride'])

        if dropped_mru > 0 or dropped_lru > 0:
            print(f"[Data Clean] Dropped invalid rows -> MRU: {dropped_mru}, LRU: {dropped_lru}")

        return df
    except FileNotFoundError as e:
        print(f"Error: 找不到数据文件。请确保 CSV 文件在当前目录。\n{e}")
        return None

def generate_statistics_table(df):
    print("\n" + "="*50)
    print("表 4.1 访存特征统计学分布 (可复制至论文)")
    print("="*50)
    
    features = ['SeqRatio', 'AvgStride', 'UniqRatio']
    grouped = df.groupby('Label')[features].agg(['mean', 'std', 'median'])
    
    # 格式化输出
    print(f"{'特征':<15} | {'负载类型':<15} | {'均值 (Mean)':<12} | {'标准差 (Std)':<12} | {'中位数 (Median)'}")
    print("-" * 75)
    for feat in features:
        for label in ['MRU (Scan)', 'LRU (Zipfian)']:
            mean = grouped.loc[label, (feat, 'mean')]
            std = grouped.loc[label, (feat, 'std')]
            median = grouped.loc[label, (feat, 'median')]
            
            # 对步长使用大数格式化，其余使用小数
            if feat == 'AvgStride':
                print(f"{feat:<15} | {label:<15} | {mean:<12.1f} | {std:<12.1f} | {median:.1f}")
            else:
                print(f"{feat:<15} | {label:<15} | {mean:<12.3f} | {std:<12.3f} | {median:.3f}")
    print("="*75 + "\n")

def plot_feature_distributions(df):
    fig, axes = plt.subplots(2, 3, figsize=(15, 8))
    fig.suptitle('Feature Distributions: MRU (Scan) vs LRU (Zipfian)', fontsize=16)
    
    features = [('SeqRatio', 'Sequential Access Ratio'), 
                ('Log_AvgStride', 'Log(Avg Stride)'), 
                ('UniqRatio', 'Unique Pages Ratio')]
    
    palette = {'MRU (Scan)': '#d9534f', 'LRU (Zipfian)': '#5bc0de'}

    for i, (feat, title) in enumerate(features):
        # 上排：核密度估计图 (KDE)
        sns.kdeplot(data=df, x=feat, hue='Label', fill=True, ax=axes[0, i], palette=palette, common_norm=False)
        axes[0, i].set_title(title)
        axes[0, i].set_xlabel('')
        if i > 0: axes[0, i].set_ylabel('')
        
        # 下排：箱线图 (Boxplot)
        sns.boxplot(data=df, x='Label', y=feat, ax=axes[1, i], palette=palette)
        axes[1, i].set_title('')
        axes[1, i].set_xlabel('')
        axes[1, i].set_ylabel(title)

    plt.tight_layout()
    # 自动保存为论文用的高清 PDF 和 PNG
    plt.savefig('feature_distribution.pdf', bbox_inches='tight')
    plt.savefig('feature_distribution.png', bbox_inches='tight', dpi=300)
    print("📊 图表已生成并保存为 'feature_distribution.pdf' 和 'feature_distribution.png'")

if __name__ == "__main__":
    df = load_and_preprocess()
    if df is not None:
        generate_statistics_table(df)
        plot_feature_distributions(df)