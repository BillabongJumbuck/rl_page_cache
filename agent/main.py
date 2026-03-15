from core.env import ChameleonEnv
import os

# 替换成你真实的 PID 和目录
target_pid = 6816  
watch_dir = "/tmp/bpf_test"
bpf_exec_path = os.path.expanduser("~/r/bpf/cache_ext_reuse.out")

print("初始化强化学习环境...")
env = ChameleonEnv(target_pid, watch_dir, bpf_exec_path)

print("\n执行 Reset...")
obs, info = env.reset()
print(f"初始观测向量: \n{obs}")

print("\n执行随机 Step...")
# 从动作空间随机抽一个动作扔进去
random_action = env.action_space.sample()
print(f"下发随机动作: {random_action}")

obs, reward, done, truncated, info = env.step(random_action)

print(f"Step 观测向量: \n{obs}")
print(f"获得 Reward: {reward}")