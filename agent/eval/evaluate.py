import os
import time
from stable_baselines3 import PPO
from core.env import ChameleonEnv

def main():
    print("============================================")
    print("  启动变色龙 AI 评估模式 (Inference)  ")
    print("============================================")

    # 1. 连接靶场
    TARGET_PID = os.getpid() # 初始先随便给个 PID，env 内部的雷达会自动纠正
    WATCH_DIR = "/tmp/bpf_test"
    BPF_EXEC = os.path.expanduser("~/rl_page_cache/bpf/cache_ext_reuse.out")

    env = ChameleonEnv(
        target_pid=TARGET_PID, 
        watch_dir=WATCH_DIR, 
        bpf_exec_path=BPF_EXEC
    )

    # 2. 加载你刚刚训练好的大脑
    model_path = "checkpoints/chameleon_ppo_model.zip"
    if not os.path.exists(model_path):
        print(f"找不到模型文件 {model_path}！")
        return
        
    print(f"正在加载神经网络模型: {model_path}...")
    model = PPO.load(model_path)

    # 3. 开始评估循环
    obs, info = env.reset()
    print("\n--- 开始实时监控与策略下发 ---")
    
    try:
        for i in range(100): # 观察它走 100 步
            # 让模型根据当前观测 (obs) 预测最佳动作
            # deterministic=True 表示不随机探索，直接输出网络认为的最优解
            action, _states = model.predict(obs, deterministic=True)
            
            # 下发动作并获取新的状态
            obs, reward, done, truncated, info = env.step(action)
            
            # 实时打印它做出的决策！
            wss_mib = (os.environ.get("WSS_DUMMY", obs[0])) # obs[0] 其实是 log1p 后的，粗略看一下
            action_str = f"[{action[0]}, {action[1]}, {action[2]}, {action[3]}, {action[4]}]"
            
            print(f"Step {i+1:03d} | 动作: {action_str:15} | Reward: {reward:8.2f} | 痛觉(Maj): {obs[7]:.2f}")
            
            if done or truncated:
                obs, info = env.reset()
                
    except KeyboardInterrupt:
        print("\n评估手动中止。")

if __name__ == "__main__":
    main()