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

POLICY_LFU = 0
POLICY_MRU = 1
POLICY_LRU = 2

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
            real_seq_ratio = seq * 100.0 
            real_irr = 2 ** irr_log if irr_log > 0 else 0
            
            # A. 核心平滑：应用 log1p
            log_irr = np.log1p(real_irr)
            
            # B. 🚀 核心修改：完全抛弃伪造特征，只用真实的 2D 向量
            feature_vector = [[real_seq_ratio, log_irr]]
            
            # 2. 经过你训练好的 Scaler 进行标准化
            scaled_features = scaler.transform(feature_vector)
            
            # 3. GMM 模型预测集群
            cluster = gmm.predict(scaled_features)[0]
            
            # 4. 根据你刚才终端打印的映射关系分配策略 (需与你 train_gmm 的输出对应)
            if cluster == 2:
                policy = POLICY_MRU
            elif cluster == 3:
                policy = POLICY_LFU
            else:
                policy = POLICY_LRU
                
            row_policies.append(str(policy))
            
        f.write(", ".join(row_policies))
        f.write(" },\n")
        
    f.write("};\n")

print(f"✅ 真 AI (6D 降维版) 查表头文件生成完毕: {OUTPUT_FILE}")