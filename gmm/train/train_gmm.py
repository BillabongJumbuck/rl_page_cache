#!/usr/bin/env python3
import pandas as pd
import numpy as np
import joblib
from sklearn.mixture import GaussianMixture
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns

# 1. 加载数据
print("📥 Loading data from memory_features.csv...")
df = pd.read_csv('../data/memory_features.csv')

# 丢弃非特征列 (timestamp, window_id)
# 实际特征: seq_ratio, avg_irr, unique_ratio, irr_0_1k, irr_1k_10k, irr_10k_plus
feature_cols = ['seq_ratio', 'avg_irr', 'unique_ratio', 'irr_0_1k', 'irr_1k_10k', 'irr_10k_plus']
X = df[feature_cols]

print(f"✅ Loaded {len(X)} data points.")

# 2. 数据标准化 (Standardization) - 极其重要！
# 因为 avg_irr 的量级可能上万，而 ratio 都在 0-10000，GMM 的协方差矩阵对尺度极其敏感
print("⚖️ Standardizing features...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 保存 Scaler，在线推理 Agent 必须用完全相同的参数进行缩放
joblib.dump(scaler, '../model/scaler.pkl')

# 3. 训练高斯混合模型 (GMM)
# 我们已知靶场有 5 个 phase，所以 n_components 设为 5
n_clusters = 4
print(f"🧠 Training GMM with {n_clusters} clusters (covariance_type='full')...")
gmm = GaussianMixture(n_components=n_clusters, covariance_type='full', random_state=42, max_iter=200)
gmm.fit(X_scaled)

# 获取聚类标签
labels = gmm.predict(X_scaled)
df['cluster'] = labels

# 4. 保存模型供在线 Agent 使用
joblib.dump(gmm, '../model/gmm_model.pkl')
print("💾 Model saved to 'gmm_model.pkl' and 'scaler.pkl'.")

# 5. 分析簇的物理含义 (打印每个簇的特征均值)
print("\n📊 Cluster Centers (Original Scale) - 用于分析物理语义:")
# 逆向转换回原始尺度，方便人类阅读
centers_original = scaler.inverse_transform(gmm.means_)
centers_df = pd.DataFrame(centers_original, columns=feature_cols)
centers_df.index.name = 'Cluster ID'

for i in range(n_clusters):
    print(f"\n--- Cluster {i} ---")
    print(f"  Seq Ratio (连续性) : {centers_df.loc[i, 'seq_ratio']:.0f} / 10000")
    print(f"  Avg IRR   (平均重访): {centers_df.loc[i, 'avg_irr']:.0f}")
    print(f"  Unique    (新页率) : {centers_df.loc[i, 'unique_ratio']:.0f} / 10000")
    print(f"  IRR < 1k  (极热)   : {centers_df.loc[i, 'irr_0_1k']:.0f} / 10000")
    print(f"  IRR > 10k (长尾)   : {centers_df.loc[i, 'irr_10k_plus']:.0f} / 10000")

# 6. 可视化：使用 PCA 降维到 2D 并绘制散点图
print("\n🎨 Generating PCA Visualization...")
pca = PCA(n_components=2)
X_pca = pca.fit_transform(X_scaled)
df['PCA1'] = X_pca[:, 0]
df['PCA2'] = X_pca[:, 1]

plt.figure(figsize=(10, 8))
sns.scatterplot(
    x='PCA1', y='PCA2', 
    hue='cluster', 
    palette='tab10', 
    data=df, 
    alpha=0.6, 
    s=20
)
plt.title('Memory Access Patterns Clustering (GMM via PCA projection)')
plt.xlabel(f'Principal Component 1 ({pca.explained_variance_ratio_[0]*100:.1f}% variance)')
plt.ylabel(f'Principal Component 2 ({pca.explained_variance_ratio_[1]*100:.1f}% variance)')
plt.legend(title='Cluster ID')

# 考虑到 WSL 环境可能没有配置 X11 转发，直接保存为图片最稳妥
plt.savefig('cluster_visualization.png', dpi=300, bbox_inches='tight')
print("📸 Visualization saved to 'cluster_visualization.png'.")