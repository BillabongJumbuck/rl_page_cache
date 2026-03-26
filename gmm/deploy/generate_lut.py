#!/usr/bin/env python3
# generate_lut.py
import os
import numpy as np
import joblib
import warnings

# 忽略 scikit-learn 的版本警告
warnings.filterwarnings("ignore", category=UserWarning)

ROOT_DIR = "/home/messidor/rl_page_cache/gmm/"
scaler = joblib.load(os.path.join(ROOT_DIR, 'model', 'scaler.pkl'))
gmm = joblib.load(os.path.join(ROOT_DIR, 'model', 'gmm_model.pkl'))

OUTPUT_FILE = os.path.join(ROOT_DIR, 'deploy', 'policy_lut.h')

POLICY_MRU = 0
POLICY_LFU = 1
POLICY_LRU = 3

print("🧠 正在使用 6D 真 GMM 模型，降维渲染 2D 决策网格...")

with open(OUTPUT_FILE, "w") as f:
    f.write("/* 自动生成的 GMM 决策网格 (Lookup Table) */\n")
    f.write("/* 维度: [Seq Ratio 0-100][Log2(IRR) 0-32] */\n")
    f.write("static const __u8 policy_lut[101][33] = {\n")
    
    for seq in range(101):
        f.write("    { ")
        row_policies = []
        for irr_log in range(33):
            # 1. 还原底层的物理真实特征
            # 注意！训练代码里 seq_ratio 是放大 10000 倍的！所以 seq(0-100) 要乘 100
            real_seq_ratio = seq * 100.0 
            real_irr = 2 ** irr_log if irr_log > 0 else 0
            
            # ==========================================
            # 🌟 6D 空间特征补全与预处理对齐
            # ==========================================
            
            # A. 核心平滑：必须与训练代码完全一致，应用 log1p！
            log_irr = np.log1p(real_irr)
            
            # B. 逻辑推演其他 4 个缺失维度 (构建 2D 截面)
            # 连续性越高，独有页通常也越多，这里做一个粗略的正相关映射
            simulated_unique_ratio = real_seq_ratio 
            
            # 根据当前的 real_irr 落在哪个区间，给三大直方图分配权重 (放大 10000 倍)
            irr_0_1k = 10000.0 if real_irr < 1000 else 0.0
            irr_1k_10k = 10000.0 if 1000 <= real_irr < 10000 else 0.0
            irr_10k_plus = 10000.0 if real_irr >= 10000 else 0.0
            
            # C. 严格按照训练时的 6 列顺序组装：
            # ['seq_ratio', 'avg_irr', 'unique_ratio', 'irr_0_1k', 'irr_1k_10k', 'irr_10k_plus']
            feature_vector = [[
                real_seq_ratio, 
                log_irr, 
                simulated_unique_ratio, 
                irr_0_1k, 
                irr_1k_10k, 
                irr_10k_plus
            ]]
            
            # 2. 经过你训练好的 Scaler 进行标准化
            scaled_features = scaler.transform(feature_vector)
            
            # 3. GMM 模型预测集群
            cluster = gmm.predict(scaled_features)[0]
            
            # 4. 集群映射底层 Policy (请根据你打印出来的 Cluster 物理含义微调)
            if cluster == 0 or cluster == 2:
                policy = POLICY_MRU
            elif cluster == 1:
                policy = POLICY_LFU
            else:
                policy = POLICY_LRU
                
            row_policies.append(str(policy))
            
        f.write(", ".join(row_policies))
        f.write(" },\n")
        
    f.write("};\n")

print(f"✅ 真 AI (6D 降维版) 查表头文件生成完毕: {OUTPUT_FILE}")