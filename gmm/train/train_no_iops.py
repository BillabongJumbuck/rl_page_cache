import pandas as pd
import lightgbm as lgb
import pathlib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

ROOT_DIR = '/home/messidor/rl_page_cache/gmm/'
DATA_DIR = pathlib.Path(ROOT_DIR) / 'data_collect'
MRU_CSV = pathlib.Path(DATA_DIR) / 'scan_mru.csv'
LRU_CSV = pathlib.Path(DATA_DIR) / 'rand_lru.csv'

print("🚀 [1/5] Loading datasets for Ablation Study (No IOPS)...")
df_mru = pd.read_csv(MRU_CSV)
df_lru = pd.read_csv(LRU_CSV)

# 丢弃预热期噪音
df_mru = df_mru.iloc[1000:].copy()
df_lru = df_lru.iloc[5000:].copy()

# 目标编码：1 代表 MRU，0 代表 LRU
df_mru['label'] = 1
df_lru['label'] = 0

df = pd.concat([df_mru, df_lru], ignore_index=True)

# ==========================================
# 🌟 核心修改：剔除 IOPS，完全依赖空间局部性特征
# ==========================================
features = ['SeqRatio', 'AvgStride', 'UniqRatio']
X = df[features]
y = df['label']

print(f"📦 [2/5] Data prepared. Total samples: {len(df)}")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("🧠 [3/5] Training LightGBM model (Spatial Features Only)...")
clf = lgb.LGBMClassifier(
    n_estimators=30,
    max_depth=4,
    learning_rate=0.1,
    random_state=42,
    n_jobs=-1
)

clf.fit(X_train, y_train)

print("\n📊 [4/5] Model Evaluation on Test Set (Without IOPS):")
y_pred = clf.predict(X_test)
print(classification_report(y_test, y_pred, target_names=['LRU (0)', 'MRU (1)'], digits=4))

print("\n🔍 [Feature Importance]:")
for name, importance in zip(features, clf.feature_importances_):
    print(f" - {name}: {importance}")

# ==========================================
# ==========================================
# 🌟 另存为新模型
# ==========================================
model_path = 'chameleon_model_aux.txt'
clf.booster_.save_model(model_path)
print(f"\n✅ [5/5] Ablation Model saved to {model_path}!")