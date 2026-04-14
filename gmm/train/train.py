import pandas as pd
import lightgbm as lgb
import pathlib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

ROOT_DIR = '/home/messidor/rl_page_cache/gmm/'
DATA_DIR = pathlib.Path(ROOT_DIR) / 'data_collect'
MRU_CSV = pathlib.Path(DATA_DIR) / 'scan_mru.csv'
LRU_CSV = pathlib.Path(DATA_DIR) / 'rand_lru.csv'

print("🚀 [1/5] Loading datasets...")
df_mru = pd.read_csv(MRU_CSV)
df_lru = pd.read_csv(LRU_CSV)

# ==========================================
# 🌟 关键预处理：切除预热期噪音与打标
# ==========================================
# 丢弃文件开头的数据，让模型只学习稳态 (Steady State) 特征
# 假设每个 Batch=128 次访问，丢弃前 5000 行相当于跳过最初的一小段缓存预热期
df_mru = df_mru.iloc[1000:].copy()
df_lru = df_lru.iloc[5000:].copy()

# 目标编码：1 代表切换为 MRU，0 代表保持 LRU
df_mru['label'] = 1
df_lru['label'] = 0

# 合并为一个大数据集
df = pd.concat([df_mru, df_lru], ignore_index=True)

# ==========================================
# 🌟 特征选择：绝对禁止引入 TID！
# ==========================================
# 只提取相对行为特征，这样模型才能泛化到 ImageNet 或 LevelDB
features = ['IOPS', 'SeqRatio', 'AvgStride', 'UniqRatio']
X = df[features]
y = df['label']

print(f"📦 [2/5] Data prepared. Total samples: {len(df)}")

# 划分训练集和测试集 (80% 用于训练，20% 用于验证)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("🧠 [3/5] Training LightGBM model...")
# 配置超参数：在 OS 层面，我们追求极速推理，所以树不能太深，棵数不能太多
clf = lgb.LGBMClassifier(
    n_estimators=30,       # 仅用 30 棵树，足够拟合清晰的物理边界
    max_depth=4,           # 限制树的最大深度，保证微秒级的推理延迟
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1
)

clf.fit(X_train, y_train)

print("\n📊 [4/5] Model Evaluation on Test Set:")
y_pred = clf.predict(X_test)
# 打印精度 (Precision)、召回率 (Recall) 和 F1 分数
print(classification_report(y_test, y_pred, target_names=['LRU (0)', 'MRU (1)'], digits=4))

print("\n🔍 [Feature Importance]:")
# 查看模型认为哪个特征最能区分 Scan 和 Rand
for name, importance in zip(features, clf.feature_importances_):
    print(f" - {name}: {importance}")

# ==========================================
# 🌟 导出模型
# ==========================================
model_path = 'chameleon_model.txt'
clf.booster_.save_model(model_path)
print(f"\n✅ [5/5] Model explicitly saved to {model_path}!")