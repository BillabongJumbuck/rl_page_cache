import os
import json
import glob
import matplotlib.pyplot as plt
import numpy as np

def main():
    data_dir = "/home/messidor/rl_page_cache/agent/eval/output"
    results = {}

    file_pattern = os.path.join(data_dir, "*.json")
    files = sorted(glob.glob(file_pattern))
    
    if not files:
        print(f"没有在 {data_dir} 下找到任何 JSON 文件，请检查路径！")
        return

    for filepath in files:
        with open(filepath, 'r') as f:
            data = json.load(f)
            
            policy = data['metadata']['policy'].upper()
            workload = data['metadata']['workload'].upper()
            
            tput = data['metrics']['total_throughput']
            p99_lat_ns = data['metrics']['read_latency_p99_ns']
            p99_lat_ms = p99_lat_ns / 1_000_000.0  # 转为毫秒

            if workload not in results:
                results[workload] = {'LRU': [], 'CML': []}
                
            results[workload][policy].append({'tput': tput, 'lat': p99_lat_ms})

    workloads = sorted(results.keys())
    x_base = np.arange(len(workloads))
    
    bar_width = 0.12     
    gap_between_bars = 0.02 
    colors = {'LRU': '#1f77b4', 'CML': '#ff7f0e'} 

    # 🚀 核心修改：将 figsize 从 (16, 6) 暴增到 (24, 10)，提供超大画幅！
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(24, 10))
    
    labels_added_ax1 = {'LRU': False, 'CML': False}
    labels_added_ax2 = {'LRU': False, 'CML': False}

    for i, wl in enumerate(workloads):
        lru_runs = results[wl].get('LRU', [])
        cml_runs = results[wl].get('CML', [])
        
        all_runs = [('LRU', metrics) for metrics in lru_runs] + \
                   [('CML', metrics) for metrics in cml_runs]
        
        n_bars = len(all_runs)
        
        for j, (policy, metrics) in enumerate(all_runs):
            offset = (j - (n_bars - 1) / 2) * (bar_width + gap_between_bars)
            x_pos = i + offset
            
            label1 = policy if not labels_added_ax1[policy] else ""
            ax1.bar(x_pos, metrics['tput'], width=bar_width, color=colors[policy], alpha=0.9, label=label1)
            if label1: labels_added_ax1[policy] = True
            
            label2 = policy if not labels_added_ax2[policy] else ""
            ax2.bar(x_pos, metrics['lat'], width=bar_width, color=colors[policy], alpha=0.9, label=label2)
            if label2: labels_added_ax2[policy] = True

    # ---------------------------------------------------------
    # 细节修饰：全面放大字体以匹配超大画幅
    # ---------------------------------------------------------
    ax1.set_xticks(x_base)
    ax1.set_xticklabels(workloads, fontsize=14)
    ax1.set_xlabel('YCSB Workload', fontsize=16, labelpad=10)
    ax1.set_ylabel('Total Throughput (ops/sec)', fontsize=16, labelpad=10)
    ax1.set_title('Throughput Comparison (Individual Runs)', fontsize=20, pad=20)
    ax1.tick_params(axis='y', labelsize=14)
    ax1.legend(fontsize=14)
    ax1.grid(True, axis='y', linestyle='--', alpha=0.6)

    ax2.set_xticks(x_base)
    ax2.set_xticklabels(workloads, fontsize=14)
    ax2.set_xlabel('YCSB Workload', fontsize=16, labelpad=10)
    ax2.set_ylabel('Read P99 Latency (ms)', fontsize=16, labelpad=10)
    ax2.set_title('P99 Latency Comparison (Individual Runs)', fontsize=20, pad=20)
    ax2.tick_params(axis='y', labelsize=14)
    ax2.legend(fontsize=14)
    ax2.grid(True, axis='y', linestyle='--', alpha=0.6)

    plt.tight_layout()
    output_img = "/home/messidor/rl_page_cache/agent/plot/lru_vs_cml_bar_chart_large.png"
    plt.savefig(output_img, dpi=300, bbox_inches='tight')
    print(f"📊 超大尺寸柱状图已生成并保存为: {output_img}")

if __name__ == "__main__":
    main()