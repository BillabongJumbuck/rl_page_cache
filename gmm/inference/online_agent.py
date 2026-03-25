#!/usr/bin/env python3
import time
import subprocess
import os
import joblib
import numpy as np
import warnings

# 忽略 scikit-learn 关于 feature names 的烦人警告
warnings.filterwarnings("ignore", category=UserWarning)

ROOT_DIR = os.path.dirname('/home/messidor/rl_page_cache/gmm/')

# 1. 策略映射表 (基于最新训练的 4 聚类物理语义)
POLICY_LRU = 0
POLICY_MRU = 1
POLICY_LFU = 2

policy_map = {
    0: POLICY_MRU, # 强顺序、全冷页 -> MRU 纯大扫表阅后即焚
    1: POLICY_LFU, # 极低顺序、高极热重访 -> LFU Zipfian 核心死保
    2: POLICY_MRU, # 极高顺序、零重访 -> MRU 冷启动幽灵
    3: POLICY_LRU  # 中等顺序、混合态 -> LRU 经典退避防守
}

print("🤖 [Agent] 正在加载大脑 (GMM & Scaler)...")
scaler = joblib.load(os.path.join(ROOT_DIR, 'model', 'scaler.pkl'))
gmm = joblib.load(os.path.join(ROOT_DIR, 'model', 'gmm_model.pkl'))

print("🚀 [Agent] 上线！正在启动底层 eBPF 数据泵...")

streamer_cmd = ["sudo", os.path.join(ROOT_DIR, "inference", "data_streamer.out")]
process = subprocess.Popen(streamer_cmd, stdout=subprocess.PIPE, text=True)

print("📡 [Agent] 成功挂接内存管道，开始实施 AI 实时监控...")

current_policy = -1

# 🛡️ 状态机防抖/投票机制变量
REQUIRED_VOTES = 5  # 必须连续 5 个窗口判定为同一新策略，才执行内核下发
candidate_policy = -1
votes = 0

try:
    for line in process.stdout:
        line = line.strip()
        
        if not line or line.startswith('timestamp'):
            continue
            
        parts = line.split(',')
        if len(parts) < 8:
            continue
            
        # 4. 提取 6 维核心特征 (🛡️ 核心修复：加入 clip 限幅，防止采样截断导致的 >10000 溢出)
        try:
            raw_avg_irr = float(parts[3])
            seq_ratio = np.clip(float(parts[2]), 0, 10000)
            unique_ratio = np.clip(float(parts[4]), 0, 10000)
            irr_0_1k = np.clip(float(parts[5]), 0, 10000)
            irr_1k_10k = np.clip(float(parts[6]), 0, 10000)
            irr_10k_plus = np.clip(float(parts[7]), 0, 10000)
            
            features = np.array([[
                seq_ratio, 
                np.log1p(raw_avg_irr), # 对数平滑
                unique_ratio, 
                irr_0_1k, irr_1k_10k, irr_10k_plus
            ]])
        except ValueError:
            continue
        
        # 5. AI 大脑推理
        scaled_features = scaler.transform(features)
        cluster = gmm.predict(scaled_features)[0]
        
        target_policy = policy_map.get(cluster, POLICY_LRU)
        policy_names = {0: "LRU", 1: "MRU", 2: "LFU"}
        window_id = parts[1]
        
        # 为了让打印好看，依然用原始 parts 里的数据展示比例
        seq_pct = float(parts[2]) / 100.0
        uniq_pct = float(parts[4]) / 100.0
        print(f"📊 [W: {window_id:>4}] Seq: {seq_pct:>5.1f}% | IRR: {int(raw_avg_irr):>8d} | Uniq: {uniq_pct:>5.1f}% ➡️  🧠 判定为 C{cluster} ({policy_names[target_policy]})")
        
        # 6. 🛡️ 动态策略下发 (引入投票防抖)
        if target_policy == current_policy:
            votes = 0
            candidate_policy = -1
        else:
            if target_policy == candidate_policy:
                votes += 1
            else:
                candidate_policy = target_policy
                votes = 1
                
            if votes >= REQUIRED_VOTES:
                print("-" * 60)
                print(f"🚨🚨 确诊相位突变！已连续 {REQUIRED_VOTES} 票命中 Cluster {cluster} -> 稳健下发内核策略: {policy_names[target_policy]}")
                print("-" * 60)
                
                hex_policy = f"{target_policy:02x} 00 00 00"
                bpftool_cmd = f"sudo bpftool map update pinned /sys/fs/bpf/cml_params_map key hex 00 00 00 00 value hex {hex_policy} > /dev/null 2>&1"
                
                os.system(bpftool_cmd)
                
                current_policy = target_policy
                candidate_policy = -1
                votes = 0

except KeyboardInterrupt:
    print("\n🛑 [Agent] 收到中止信号。正在关闭底层数据泵...")
finally:
    process.terminate()
    process.wait()
    print("✅ [Agent] 退出完成。")