import os
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.vec_env import DummyVecEnv, VecNormalize
from stable_baselines3.common.callbacks import CheckpointCallback

# 导入我们打磨好的终极环境
from core.env import ChameleonEnv

def main():
    # 1. 靶场参数 (探针已经在 train.fish 中由 C 程序接管，这里只需提供监控目录)
    TARGET_PID = os.getpid()  # 雷达会自动去抓 fio 的真 PID，这里给个自己的防闪退
    WATCH_DIR = "/tmp/bpf_test"

    print("正在实例化 Chameleon eBPF 强化学习环境...")
    env = ChameleonEnv(
        target_pid=TARGET_PID, 
        watch_dir=WATCH_DIR, 
        bpf_exec_path="" # 留空，探针已经在外面跑起来了
    )

    # 2. 严苛的环境体检
    print("进行环境规范合规性检查...")
    check_env(env)
    print("环境体检通过！")

    # 3. 包装成向量化环境并开启【奖励归一化】(核心改动)
    vec_env = DummyVecEnv([lambda: env])
    # norm_obs=False: 我们已经在 env.py 里对状态做了 log1p，不需要额外归一化
    # norm_reward=True: 强力压制那几百上千的负分 Reward
    vec_env = VecNormalize(vec_env, norm_obs=False, norm_reward=True, clip_reward=10.0)

    # 4. 召唤 PPO 大脑 (增强视野版)
    print("初始化 PPO 神经网络模型...")
    # model = PPO(
    #     "MlpPolicy", 
    #     vec_env, 
    #     verbose=1,
    #     learning_rate=2e-4,     # 稍微调低学习率，让长程训练更平滑
    #     n_steps=256,            # 扩大视野：每收集 256 秒的经验才更新一次大脑
    #     batch_size=64,          # 相应增大 Batch Size
    #     ent_coef=0.01,          # 增加一点熵系数，鼓励它在漫长岁月里多尝试不同的参数组合
    #     device="cpu", 
    #     tensorboard_log="./logs/chameleon_tensorboard/"
    # )

    # 4a. 如果之前训练过，继续从上次的检查点恢复 (如果没有，就从头开始)
    model = PPO.load("checkpoints/chameleon_ppo_backup_12000_steps.zip", env=vec_env)

    # 4b. 自动存档器：每 1000 步保存一次到 checkpoints 目录
    checkpoint_callback = CheckpointCallback(
        save_freq=1000,
        save_path='./checkpoints/',
        name_prefix='chameleon_ppo_backup'
    )

    # 5. 点火训练！
    print("🚀 开始闭环进化！请紧盯终端的 Loss 变化...")
    try:
        # 将 timesteps 拉长到 50,000 步 (这大约需要运行 17 个小时，你可以随时 Ctrl+C 中断)
        model.learn(total_timesteps=50000, callback=checkpoint_callback, progress_bar=True)
    except KeyboardInterrupt:
        print("\n收到中止信号，正在保存脑图...")

    # 6. 保存模型权重与【环境归一化统计量】
    model.save("checkpoints/chameleon_ppo_model")
    vec_env.save("checkpoints/vec_normalize.pkl") 
    print("模型和归一化参数已保存至 checkpoints 目录下！")

if __name__ == "__main__":
    main()