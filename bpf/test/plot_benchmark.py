import pandas as pd
import matplotlib.pyplot as plt

def parse_elapsed_time(t_str):
    """
    处理时间字符串，将其统一转换为秒 (float)
    例如："mm:ss or m:ss): 3:08.58" -> 188.58
    """
    t_str = str(t_str).split('):')[-1].strip()  # 提取真正的时长部分
    parts = t_str.split(':')
    if len(parts) == 3:  # h:mm:ss
        return float(parts[0]) * 3600 + float(parts[1]) * 60 + float(parts[2])
    elif len(parts) == 2:  # m:ss
        return float(parts[0]) * 60 + float(parts[1])
    else:
        return float(t_str)

def plot_benchmarks(csv_file):
    # 读取数据
    df = pd.read_csv(csv_file)

    # 1. 预处理：提取 CPU 使用率数字
    df['Percent of CPU this job got'] = df['Percent of CPU this job got'].astype(str).str.replace('%', '').astype(float)

    # 2. 预处理：找到耗时列，并将其转换为秒
    time_col = [c for c in df.columns if 'Elapsed' in c][0]
    df['Elapsed Time (s)'] = df[time_col].apply(parse_elapsed_time)

    # 需要绘制的 6 个指标
    metrics = [
        'Percent of CPU this job got',
        'Elapsed Time (s)',
        'Maximum resident set size (kbytes)',
        'Major (requiring I/O) page faults',
        'Minor (reclaiming a frame) page faults',
        'File system inputs',
        'Voluntary context switches',
        'Involuntary context switches'
    ]

    # 将其他列转为数值类型，防止字符串导致绘图失败
    for m in metrics:
        if m != 'Elapsed Time (s)' and m != 'Percent of CPU this job got':
            df[m] = pd.to_numeric(df[m], errors='coerce')

    # 按 Workload 和 Policy 分组求平均值（自动将 3 次 Run 的结果平均）
    df_grouped = df.groupby(['Workload', 'Policy'])[metrics].mean().reset_index()

    # 设置 Matplotlib 画布，3行2列，共6幅图
    fig, axes = plt.subplots(4, 2, figsize=(16, 18))
    axes = axes.flatten()

    for i, metric in enumerate(metrics):
        ax = axes[i]
        # 使用 pivot 转换数据格式以方便 Pandas 画分组柱状图
        pivot_df = df_grouped.pivot(index='Workload', columns='Policy', values=metric)
        pivot_df.plot(kind='bar', ax=ax, rot=0, alpha=0.85)
        
        ax.set_title(metric, fontsize=14, fontweight='bold')
        ax.set_ylabel('Value')
        ax.set_xlabel('Workload')
        ax.grid(axis='y', linestyle='--', alpha=0.7)
        ax.legend(title='Policy')

    # 调整布局并保存
    plt.tight_layout()
    plt.savefig('benchmark_charts.png', dpi=300)
    print("分析完毕！图表已生成并保存为当前目录下的 benchmark_charts.png")

if __name__ == "__main__":
    plot_benchmarks("result.csv")
