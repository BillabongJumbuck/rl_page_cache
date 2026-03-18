# train.py - ChameleonEnv 的训练脚本，使用 Stable Baselines3 的 PPO 算法
import os
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.vec_env import DummyVecEnv, VecNormalize
from stable_baselines3.common.callbacks import BaseCallback

# 导入我们打磨好的终极环境
from core.env import ChameleonEnv

# =====================================================================
# 🌟 核心利器：自定义的“双端”检查点存档器
# 同时保存 PPO 模型权重 (.zip) 和 环境归一化参数 (.pkl)
# =====================================================================
class DualCheckpointCallback(BaseCallback):
    def __init__(self, save_freq: int, save_path: str, name_prefix: str = "chameleon_ppo_backup", verbose: int = 1):
        super().__init__(verbose)
        self.save_freq = save_freq
        self.save_path = save_path
        self.name_prefix = name_prefix

    def _init_callback(self) -> None:
        if self.save_path is not None:
            os.makedirs(self.save_path, exist_ok=True)

    def _on_step(self) -> bool:
        if self.n_calls % self.save_freq == 0:
            # 1. 组装文件名
            model_path = os.path.join(self.save_path, f"{self.name_prefix}_{self.num_timesteps}_steps")
            pkl_path = os.path.join(self.save_path, f"{self.name_prefix}_{self.num_timesteps}_steps_vecnormalize.pkl")
            
            # 2. 保存神经网络权重 (.zip)
            self.model.save(model_path)
            
            # 3. 强制保存环境的统计数据 (.pkl)
            if self.training_env is not None:
                self.training_env.save(pkl_path)
                
            if self.verbose > 0:
                print(f"\n[存档] 🛡️ 进度 {self.num_timesteps} 步: 模型与 pkl 已同步硬落盘！")
        return True


def main():
    # 1. 靶场参数 (探针已经在 train.fish 中由 C 程序接管，这里只需提供监控目录)
    TARGET_PID = os.getpid()  # 雷达会自动去抓 fio 的真 PID，这里给个自己的防闪退
    CGROUP_PATH = "/sys/fs/cgroup/chameleon_train"

    print("正在实例化 Chameleon eBPF 强化学习环境...")
    env = ChameleonEnv(
        target_pid=TARGET_PID, 
        cgroup_path=CGROUP_PATH
    )

    # 2. 严苛的环境体检
    print("进行环境规范合规性检查...")
    check_env(env)
    print("环境体检通过！")

    # ---------------------------------------------------------
    # 3. 包装成向量化环境并开启【奖励归一化】(带记忆恢复版)
    # ---------------------------------------------------------
    vec_env = DummyVecEnv([lambda: env])
    
    # 检查是否有历史环境尺度存档，如果有，必须加载！
    normalize_path = "checkpoints/chameleon_ppo_backup_10000_steps_vecnormalize.pkl"
    if os.path.exists(normalize_path):
        print(f"📦 发现历史环境尺度存档，正在恢复...")
        vec_env = VecNormalize.load(normalize_path, vec_env)
        # SB3 的特性：加载后的 VecNormalize 默认不更新统计，必须手动开启
        vec_env.training = True
        vec_env.norm_reward = True
    else:
        print(f"🌱 未发现环境存档，创建全新的环境归一化器...")
        vec_env = VecNormalize(vec_env, norm_obs=False, norm_reward=True, clip_reward=10.0)

    # ---------------------------------------------------------
    # 4. 召唤 PPO 大脑 (增强视野版)
    # ---------------------------------------------------------
    print("初始化 PPO 神经网络模型...")
    model = PPO(
       "MlpPolicy", 
       vec_env, 
       verbose=1,
       learning_rate=2e-4,     # 稍微调低学习率，让长程训练更平滑
       n_steps=256,            # 扩大视野：每收集 256 秒的经验才更新一次大脑
       batch_size=64,          # 相应增大 Batch Size
       ent_coef=0.01,          # 增加一点熵系数，鼓励它在漫长岁月里多尝试不同的参数组合
       device="cpu", 
       tensorboard_log="./logs/chameleon_tensorboard/"
    )

    # 4a. 如果之前训练过，继续从上次的检查点恢复 (如果没有，就从头开始)
    # model = PPO.load(
    #     "checkpoints/chameleon_ppo_backup_10000_steps.zip", 
    #     env=vec_env,
    #     tensorboard_log="./logs/chameleon_tensorboard/" 
    # )

    # 4b. 使用我们刚才写的【双端存档器】，每 1000 步连同 pkl 一起保存！
    checkpoint_callback = DualCheckpointCallback(
        save_freq=1000,
        save_path='./checkpoints/',
        name_prefix='chameleon_ppo_backup'
    )

    # 5. 点火训练！
    print("🚀 开始闭环进化！请紧盯终端的 Loss 变化...")
    try:
        # 将 timesteps 拉长到 50,000 步
        model.learn(
            total_timesteps=50000, 
            callback=checkpoint_callback, 
            progress_bar=True,
            reset_num_timesteps=False 
        )
    except KeyboardInterrupt:
        print("\n收到中止信号，正在保存脑图...")

    # 6. 正常结束时，保存最终模型权重与【环境归一化统计量】
    model.save("checkpoints/chameleon_ppo_model")
    vec_env.save("checkpoints/vec_normalize.pkl") 
    print("模型和归一化参数已保存至 checkpoints 目录下！")

if __name__ == "__main__":
    main()
