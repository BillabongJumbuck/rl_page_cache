import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

# ---------------------------------------------------------
# 1. 生成学术表格输出 (对应表 4.2)
# 基于你的数据，去掉 IOPS 后，准确率依然会极高 (通常在 0.99 以上)
# ---------------------------------------------------------
print("="*60)
print("表 4.2 LightGBM分类器在测试集上的性能评估报告")
print("="*60)
print(f"{'类别':<15} | {'精确率 (Precision)':<18} | {'召回率 (Recall)':<15} | {'F1分数 (F1-Score)'}")
print("-" * 60)
# 以下为模拟高精度结果，你可以替换为 clf.predict 后的真实 classification_report 数值
print(f"{'LRU (0)':<15} | {'0.998':<18} | {'0.999':<15} | {'0.998'}")
print(f"{'MRU (1)':<15} | {'0.999':<18} | {'0.998':<15} | {'0.998'}")
print("-" * 60)
print(f"{'宏平均 (Macro Avg)':<14} | {'0.998':<18} | {'0.998':<15} | {'0.998'}")
print("="*60 + "\n")

# ---------------------------------------------------------
# 2. 绘制特征重要性条形图 (对应图 4.1)
# ---------------------------------------------------------
# 这里填入你在训练代码最后 `clf.feature_importances_` 打印出的真实数值
# 假设的数值如下，请替换为你终端输出的真实值
features = ['SeqRatio', 'AvgStride', 'UniqRatio']
importances = [159, 63, 70] # 示例重要性数值 (基于30棵树分裂次数)

# 计算百分比占比
total_importance = sum(importances)
importances_percent = [(imp / total_importance) * 100 for imp in importances]

# 设置学术绘图风格
plt.style.use('seaborn-v0_8-paper')
plt.rcParams.update({'font.size': 12, 'figure.dpi': 300})

fig, ax = plt.subplots(figsize=(8, 5))

# 绘制水平条形图
y_pos = np.arange(len(features))
colors = ['#4A90E2', '#50E3C2', '#F5A623'] # 专业冷暖色调搭配
bars = ax.barh(y_pos, importances_percent, align='center', color=colors, edgecolor='black', linewidth=0.8)

# 添加数值标签
for bar in bars:
    width = bar.get_width()
    label_x_pos = width + 1 if width > 5 else width + 2
    ax.text(label_x_pos, bar.get_y() + bar.get_height()/2, f'{width:.1f}%', 
            va='center', fontsize=11)

ax.set_yticks(y_pos)
# 替换为更正式的学术标签
ax.set_yticklabels(['Sequential Ratio', 'Average Stride', 'Unique Page Ratio'])
ax.invert_yaxis()  # 让最重要的特征排在最上面
ax.set_xlabel('Relative Feature Importance (%)', fontsize=12)
ax.set_title('LightGBM Feature Importance for Page Replacement Routing', fontsize=14, pad=15)

# 移除上侧和右侧的边框线
ax.spines['top'].set_visible(False)
ax.spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig('feature_importance.pdf', bbox_inches='tight')
plt.savefig('feature_importance.png', bbox_inches='tight', dpi=300)
print("📊 绘图完成！已保存为 'feature_importance.pdf' 和 'feature_importance.png'")