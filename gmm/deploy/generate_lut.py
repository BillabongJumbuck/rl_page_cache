#!/usr/bin/env python3
# generate_lut.py
import os

import numpy as np

# 这里假设你已经有了训练好的 GMM 模型 (比如保存在 model.pkl)
import joblib
ROOT_DIR = "/home/messidor/rl_page_cache/gmm/"
scaler = joblib.load(os.path.join(ROOT_DIR, 'model', 'scaler.pkl'))
gmm = joblib.load(os.path.join(ROOT_DIR, 'model', 'gmm_model.pkl'))

OUTPUT_FILE = os.path.join(ROOT_DIR, 'deploy', 'policy_lut.h')

# 策略枚举 (与你内核代码里的定义对齐)
POLICY_MRU = 0
POLICY_LFU = 1
POLICY_LRU = 3

print("🧠 正在离线生成 GMM 决策网格...")

with open(OUTPUT_FILE, "w") as f:
    f.write("/* 自动生成的 GMM 决策网格 (Lookup Table) */\n")
    f.write("/* 维度: [Seq Ratio 0-100][Log2(IRR) 0-32] */\n")
    f.write("static const __u8 policy_lut[101][33] = {\n")
    
    for seq in range(101):
        f.write("    { ")
        row_policies = []
        for irr_log in range(33):
            # 将索引还原为真实物理值喂给你的 GMM
            real_seq = seq / 100.0
            real_irr = 2 ** irr_log if irr_log > 0 else 0
            
            # ==========================================
            # ⚠️ 在这里替换成你真实的 GMM 预测逻辑！
            # 示例: cluster = gmm.predict([[real_seq, real_irr]])[0]
            # 这里我用一个简单的启发式规则模拟你的 GMM 边界：
            if real_seq > 0.90:
                policy = POLICY_MRU  # 纯扫表 -> MRU
            elif real_seq < 0.60 and real_irr > 1000:
                policy = POLICY_LFU  # 混合热点 -> LFU
            else:
                policy = POLICY_LRU  # 默认兜底 -> LRU
            # ==========================================
            
            row_policies.append(str(policy))
            
        f.write(", ".join(row_policies))
        f.write(" },\n")
        
    f.write("};\n")

print(f"✅ 查表头文件生成完毕: {OUTPUT_FILE} (体积约 3.3KB)")
print("👉 请将它 #include 到你的 eBPF C 代码中！")