#!/usr/bin/env python3
import subprocess
import os
import joblib
import numpy as np
import warnings

# 忽略 scikit-learn 关于 feature names 的烦人警告
warnings.filterwarnings("ignore", category=UserWarning)

ROOT_DIR = os.path.dirname('/home/messidor/rl_page_cache/gmm/')

# 1. 策略映射表 (基于你 K=4 的完美聚类结果)
POLICY_LRU = 0
POLICY_MRU = 1
POLICY_LFU = 2

policy_map = {
    0: POLICY_LFU, # 蓝色：纯热点区 -> 死保高频
    1: POLICY_MRU, # 橙色：混合扫描区 -> 阅后即焚
    2: POLICY_LRU, # 绿色：过渡/模糊区 -> 经典退避
    3: POLICY_MRU  # 红色：纯大扫表区 -> 阅后即焚
}

print("🤖 [Agent] 正在加载大脑 (GMM & Scaler)...")
scaler = joblib.load(os.path.join(ROOT_DIR, 'model', 'scaler.pkl'))
gmm = joblib.load(os.path.join(ROOT_DIR, 'model', 'gmm_model.pkl'))

print("🚀 [Agent] 上线！正在接管内核 BPF 数据流...")

# 启动原来的 C 收集器作为子进程
cmd = ["sudo", "./data_collector.out"]
process = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)

current_policy = -1

# 持续监听内存特征流
for line in process.stdout:
    line = line.strip()
    # 过滤表头和空行
    if not line or line.startswith('timestamp') or line.startswith('['):
        continue
        
    parts = line.split(',')
    if len(parts) < 8:
        continue
        
    # 提取 6 维核心特征
    try:
        features = np.array([[
            float(parts[2]), float(parts[3]), float(parts[4]), 
            float(parts[5]), float(parts[6]), float(parts[7])
        ]])
    except ValueError:
        continue
    
    # 2. AI 大脑推理
    scaled_features = scaler.transform(features)
    cluster = gmm.predict(scaled_features)[0]
    
    new_policy = policy_map.get(cluster, POLICY_LRU)
    
    # 3. 动态策略下发 (仅在发生相位突变时下发，极大降低开销)
    if new_policy != current_policy:
        policy_names = {0: "LRU", 1: "MRU", 2: "LFU"}
        print(f"🔄 相位突变！进入 Cluster {cluster} -> 下发内核策略: {policy_names[new_policy]}")
        
        # 使用小端十六进制格式通过 bpftool 更新 eBPF Pinned Map
        # 键 0 (00 00 00 00), 值 new_policy (0x 00 00 00)
        hex_policy = f"{new_policy:02x} 00 00 00"
        bpftool_cmd = f"sudo bpftool map update pinned /sys/fs/bpf/cml_params_map key hex 00 00 00 00 value hex {hex_policy}"
        
        os.system(bpftool_cmd)
        current_policy = new_policy