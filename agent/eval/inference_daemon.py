import os
import time
import csv
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.vec_env import DummyVecEnv, VecNormalize
from core.env import ChameleonEnv

def main():
    print("============================================")
    print("  启动变色龙 AI 评估大脑 (Daemon Mode)  ")
    print("============================================")

    # 【修复 1】: 动态获取监听目录，不再当瞎子！
    cgroup_path = os.environ.get("CHAMELEON_CGROUP_PATH")
    if not cgroup_path:
        raise ValueError("🚨 致命错误: 未设置 CHAMELEON_CGROUP_PATH 环境变量！大脑不知道该看哪里！")
    print(f">>> 雷达已锁定真实战场目录: {cgroup_path}")

    # 1. 连接靶场环境
    env = ChameleonEnv(
        target_pid=os.getpid(), 
        cgroup_path=cgroup_path
    )

    # 2. 包装并加载归一化参数
    vec_env = DummyVecEnv([lambda: env])
    pkl_path = "checkpoints/chameleon_ppo_backup_10000_steps_vecnormalize.pkl"
    if os.path.exists(pkl_path):
        print(">>> 发现归一化参数，正在同步环境尺度...")
        vec_env = VecNormalize.load(pkl_path, vec_env)
        vec_env.training = False 
        vec_env.norm_reward = False 
    else:
        print(">>> 警告: 未找到 vec_normalize.pkl，AI 极有可能发挥失常！")

    # 【修复 2】: 引入人类专家后门 (Heuristic Override)
    # 如果设置了 EXPERT_MODE，就跳过神经网络，直接用人类给定的绝对最优解！
    is_expert_mode = os.environ.get("CHAMELEON_EXPERT_MODE") == "1"
    
    model = None
    if not is_expert_mode:
        model_path = "checkpoints/chameleon_ppo_backup_10000_steps.zip"
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"找不到模型文件 {model_path}！")
        print(f"正在加载神经网络: {model_path}...")
        model = PPO.load(model_path)
    else:
        print("💡 [作弊模式激活] 已绕过神经网络，将下发纯人类专家级绝对防御策略！")

    # 4. 开启无限循环与决策审计日志
    obs = vec_env.reset()
    csv_file = os.environ.get("CHAMELEON_CSV_LOG", "logs/ai_decisions_log.csv")
    
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["time", "p_access", "p_direction", "p_threshold", "p_survival", "p_ghost", "reward", "pgfault_rate"])
        
        print("\n--- 大脑已上线，实时监控与策略下发中 (记录至 CSV) ---")
        try:
            step = 0
            while True:
                if is_expert_mode:
                    # 【填入你的纯读防御神级参数】
                    # 请根据你的动作空间调整！例如：拉满 ghost 概率，降低 threshold 门槛
                    # 这里假设动作空间支持这种数值，请根据你实际的 action_space 修改
                    expert_action = [2, 70, 2, 1]
                    action = np.array([expert_action], dtype=np.float32)
                else:
                    action, _ = model.predict(obs, deterministic=True)
                
                obs, reward, done, info = vec_env.step(action)
                
                act = action[0]
                rew = reward[0]
                # 假设 obs[0][7] 是缺页率，防止因为 obs 维度不对报错，加个保护
                pgfault = obs[0][7] if len(obs[0]) > 7 else 0.0 
                
                writer.writerow([time.strftime("%H:%M:%S"), act[0], act[1], act[2], act[3], act[4], rew, pgfault])
                f.flush() 
                
                mode_str = "[EXPERT]" if is_expert_mode else "[AI]"
                print(f"[{time.strftime('%H:%M:%S')}] {mode_str} 动作: {act.tolist()} | Reward: {rew:6.2f} | 痛觉: {pgfault:.2f}")
                step += 1
                
        except KeyboardInterrupt:
            print("\n>>> 收到终止信号，大脑休眠。")

if __name__ == "__main__":
    main()