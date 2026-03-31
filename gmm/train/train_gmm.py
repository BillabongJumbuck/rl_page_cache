#!/usr/bin/env python3
import pandas as pd
import numpy as np
import joblib
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import RobustScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns
import os

# ROOT_DIR = os.path.dirname('/home/messidor/rl_page_cache/gmm/')

# 1. 加载数据
print("📥 Loading data from memory_features.csv...")
df = pd.read_csv('memory_features.csv')

# 🚀 核心修改：只使用内核态实际提取的两个特征
feature_cols = ['seq_ratio', 'avg_irr']
X = df[feature_cols].copy()

# 限制 seq_ratio 范围
X['seq_ratio'] = X['seq_ratio'].clip(lower=0, upper=10000)

# 保持你原有的优秀设计：对数平滑
print("🛠️ Applying Log Transform to avg_irr to tame extreme variance...")
X['avg_irr'] = np.log1p(X['avg_irr'])

# 2. 数据标准化 (Standardization)
print("⚖️ Standardizing features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 保存 Scaler
joblib.dump(scaler,  'scaler.pkl')

# 3. 训练高斯混合模型 (GMM)
n_clusters = 4
print(f"🧠 Training GMM with {n_clusters} clusters (covariance_type='full')...")
gmm = GaussianMixture(n_components=n_clusters, covariance_type='full', random_state=42, max_iter=200)
gmm.fit(X_scaled)

labels = gmm.predict(X_scaled)
df['cluster'] = labels

# 4. 保存模型供在线 Agent 使用
joblib.dump(gmm,  'gmm_model.pkl')
print("💾 Model saved to 'gmm_model.pkl' and 'scaler.pkl'.")

# 5. 分析簇的物理含义 (打印每个簇的特征均值)
print("\n📊 Cluster Centers (Original Scale) - 用于分析物理语义:")
centers_processed = gmm.means_
centers_original = scaler.inverse_transform(centers_processed)

# ==========================================
# 🚀 核心修改 2：逆向还原对数转换，输出人类可读数据
# ==========================================
centers_processed = gmm.means_
centers_original = scaler.inverse_transform(centers_processed)
centers_original[:, 1] = np.expm1(centers_original[:, 1]) # 还原 avg_irr

# 构建 DataFrame 方便排序
centers_df = pd.DataFrame(centers_original, columns=feature_cols)

# 🚀 核心修改：基于物理语义动态映射 Policy
policy_mapping = {}

# 逻辑1：找出 seq_ratio 最高的类，标记为 MRU (顺序扫描多，抗颠簸)
mru_cluster = centers_df['seq_ratio'].idxmax()
policy_mapping[mru_cluster] = "POLICY_MRU"

# 逻辑2：找出 avg_irr 最小的类（重访最频繁），标记为 LFU (热点数据)
lfu_cluster = centers_df['avg_irr'].idxmin()
if lfu_cluster == mru_cluster:
    # 冲突处理：如果重访频繁且顺序性强，优先 MRU，找次小的作为 LFU
    lfu_cluster = centers_df['avg_irr'].drop(mru_cluster).idxmin()
policy_mapping[lfu_cluster] = "POLICY_LFU"

# 逻辑3：剩下的类，默认退化为 LRU 或其他策略
for i in range(n_clusters):
    if i not in policy_mapping:
        policy_mapping[i] = "POLICY_LRU"

print("\n🎯 Dynamic Policy Mapping:")
for i in range(n_clusters):
    print(f"Cluster {i} -> {policy_mapping[i]}")

# 🚀 修正：只打印保留的 2D 特征
for i in range(n_clusters):
    print(f"\n--- Cluster {i} ({policy_mapping[i]}) ---")
    print(f"  Seq Ratio (连续性) : {centers_df.loc[i, 'seq_ratio']:.0f} / 10000")
    print(f"  Avg IRR   (平均重访): {centers_df.loc[i, 'avg_irr']:.0f}")

# 6. 可视化：直接绘制 2D 散点图，无需 PCA
print("\n🎨 Generating 2D Visualization...")

plt.figure(figsize=(10, 8))
sns.scatterplot(
    x=X['seq_ratio'], 
    y=X['avg_irr'],  # 这里画的是 log平滑后的值，更直观
    hue=df['cluster'], 
    palette='tab10', 
    alpha=0.6, 
    s=20
)
plt.title('Memory Access Patterns Clustering (2D Feature Space)')
plt.xlabel('Sequential Ratio (0-10000)')
plt.ylabel('Log(Avg IRR)')
plt.legend(title='Cluster ID')

# 🚀 修正：把图片保存下来以便查看
vis_path = 'cluster_2d_visualization.png'
plt.savefig(vis_path, dpi=300, bbox_inches='tight')
print(f"📸 Visualization saved to '{vis_path}'.")