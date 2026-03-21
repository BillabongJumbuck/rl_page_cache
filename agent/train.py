import os
import numpy as np
from stable_baselines3 import PPO
from stable_baselines3.common.env_checker import check_env
from stable_baselines3.common.vec_env import DummyVecEnv, VecNormalize
from stable_baselines3.common.callbacks import BaseCallback
from stable_baselines3.common.callbacks import CallbackList
from stable_baselines3.common.monitor import Monitor

from core.env import ChameleonEnv

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
            model_path = os.path.join(self.save_path, f"{self.name_prefix}_{self.num_timesteps}_steps")
            pkl_path = os.path.join(self.save_path, f"{self.name_prefix}_{self.num_timesteps}_steps_vecnormalize.pkl")
            
            self.model.save(model_path)
            if self.training_env is not None:
                self.training_env.save(pkl_path)
                
            if self.verbose > 0:
                print(f"\n[存档] 🛡️ 进度 {self.num_timesteps} 步: 模型与 pkl 已同步硬落盘！")
        return True
    
class GracefulStopCallback(BaseCallback):
    def __init__(self, stop_file_path="/tmp/stop_chameleon", verbose=1):
        super().__init__(verbose)
        self.stop_file_path = stop_file_path

    def _on_step(self) -> bool:
        if os.path.exists(self.stop_file_path):
            if self.verbose > 0:
                print(f"\n[🛑 优雅中止] 检测到停止信标文件！正在安全结束训练...")
            os.remove(self.stop_file_path)
            return False 
        return True
    
def main():
    TARGET_PID = os.getpid() 
    CGROUP_PATH = "/sys/fs/cgroup/cache_ext_train"

    print("正在实例化 Chameleon eBPF 强化学习环境 (策略路由版)...")
    env = ChameleonEnv(
        target_pid=TARGET_PID, 
        cgroup_path=CGROUP_PATH
    )

    env = Monitor(env)
    
    print("进行环境规范合规性检查...")
    check_env(env)
    print("环境体检通过！")

    # =========================================================
    # 🌟 降维打击：去除复杂的 Obs 归一化，仅保留 Reward 归一化
    # =========================================================
    vec_env = DummyVecEnv([lambda: env])
    
    normalize_path = "checkpoints/chameleon_ppo_backup_vecnormalize.pkl"
    if os.path.exists(normalize_path):
        print(f"📦 发现历史环境尺度存档，正在恢复...")
        vec_env = VecNormalize.load(normalize_path, vec_env)
        vec_env.training = True
        # 【修改】强制关掉 Obs 归一化，只开 Reward
        vec_env.norm_obs = False 
        vec_env.norm_reward = True
    else:
        print(f"🌱 未发现环境存档，创建全新的环境归一化器...")
        # 【修改】norm_obs=False
        vec_env = VecNormalize(vec_env, norm_obs=False, norm_reward=True, clip_reward=10.0)

    # =========================================================
    # 🌟 调整 PPO 超参数适配离散空间
    # =========================================================
    print("初始化 PPO 神经网络模型...")
    model = PPO(
        "MlpPolicy", 
        vec_env, 
        verbose=1,
        learning_rate=3e-4,      # 离散动作空间收敛快，可以适当调大一点点学习率
        n_steps=1024,            # 减小 n_steps，让 Critic 更频繁地更新 (约 17 分钟更新一次网络)
        batch_size=128,          
        ent_coef=0.05,           # 【关键】：加大探索系数，鼓励智能体在 4 个策略中频繁切换
        gamma=0.99,              
        device="cpu", 
        tensorboard_log="./logs/chameleon_tensorboard/"
    )

    # 4a. 如果之前训练过，继续从上次的检查点恢复 (如果没有，就从头开始)
    # model = PPO.load(
    #     "checkpoints/chameleon_ppo_backup_10000_steps.zip", 
    #     env=vec_env,
    #     tensorboard_log="./logs/chameleon_tensorboard/" 
    # )

    # 4b. 使用我们刚才写的【双端存档器】，每 4000 步连同 pkl 一起保存！
    checkpoint_callback = DualCheckpointCallback(
        save_freq=4000,
        save_path='./checkpoints/',
        name_prefix='chameleon_ppo_backup'
    )

    stop_callback = GracefulStopCallback(stop_file_path="/tmp/stop_chameleon")
    callback_list = CallbackList([checkpoint_callback, stop_callback])

    print("🚀 开始闭环进化！请紧盯终端的 Loss 变化...")
    try:
        model.learn(
            total_timesteps=50000, 
            callback=callback_list, 
            progress_bar=True,
            reset_num_timesteps=False 
        )
    except KeyboardInterrupt:
        print("\n收到中止信号，正在保存脑图...")

    model.save("checkpoints/chameleon_ppo_model")
    vec_env.save("checkpoints/vec_normalize.pkl") 
    print("模型和归一化参数已保存至 checkpoints 目录下！")

if __name__ == "__main__":
    main()