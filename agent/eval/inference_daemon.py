import os
import time
import csv
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv, VecNormalize
from core.env import ChameleonEnv

def main():
    print("============================================")
    print("  启动变色龙 AI 评估大脑 (Daemon Mode)  ")
    print("============================================")

    # 1. 连接靶场环境
    env = ChameleonEnv(
        target_pid=os.getpid(), 
        watch_dir="/tmp/bpf_test", 
        bpf_exec_path="" # 探针由外部脚本管理
    )

    # 2. 包装并加载归一化参数 (解决 AI 失忆的关键)
    vec_env = DummyVecEnv([lambda: env])
    if os.path.exists("checkpoints/vec_normalize.pkl"):
        print(">>> 发现归一化参数，正在同步环境尺度...")
        vec_env = VecNormalize.load("checkpoints/vec_normalize.pkl", vec_env)
        # 极其重要：在评估模式下，绝不能继续更新均值和方差！
        vec_env.training = False 
        vec_env.norm_reward = False 
    else:
        print(">>> 警告: 未找到 checkpoints/vec_normalize.pkl，AI 可能会因为尺度错乱而发挥失常！")

    # 3. 加载神经网络
    model_path = "checkpoints/chameleon_ppo_model.zip"
    if not os.path.exists(model_path):
        raise FileNotFoundError(f"找不到模型文件 {model_path}！")
    print(f"正在加载神经网络: {model_path}...")
    model = PPO.load(model_path)

    # 4. 开启无限循环与决策审计日志
    obs = vec_env.reset()
    csv_file = "logs/ai_decisions_log.csv"
    
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        # 记录头部：时间戳, 动作的5个维度, 奖励, 以及缺页中断率 (观察压力的核心指标)
        writer.writerow(["time", "p_access", "p_direction", "p_threshold", "p_survival", "p_ghost", "reward", "pgfault_rate"])
        
        print("\n--- 大脑已上线，实时监控与策略下发中 (记录至 CSV) ---")
        try:
            step = 0
            while True:
                # deterministic=True: 摘掉探索的随机性，使用绝对理性的最优解
                action, _ = model.predict(obs, deterministic=True)
                obs, reward, done, info = vec_env.step(action)
                
                # 提取真值 (因为 vec_env 会把返回值打包成数组，取 [0])
                act = action[0]
                rew = reward[0]
                # 假设你的 env.py 中 obs[0][7] 是缺页中断率 (请根据你的实际 observation 空间调整索引)
                pgfault = obs[0][7] 
                
                # 写入审计日志
                writer.writerow([time.strftime("%H:%M:%S"), act[0], act[1], act[2], act[3], act[4], rew, pgfault])
                f.flush() # 强制落盘，防止中途被 kill 丢数据
                
                print(f"[{time.strftime('%H:%M:%S')}] 动作: {act.tolist()} | Reward: {rew:6.2f} | 痛觉: {pgfault:.2f}")
                step += 1
                
        except KeyboardInterrupt:
            print("\n>>> 收到终止信号，大脑休眠。")

if __name__ == "__main__":
    main()