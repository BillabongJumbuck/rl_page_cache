import gymnasium as gym
from gymnasium import spaces
import numpy as np
import subprocess
import time
import os

# 导入你刚刚发给我的完美特征提取器
from damon_extractor import DamonFeatureExtractor

class ChameleonEnv(gym.Env):
    def __init__(self, target_pid: int, damon_data_path: str):
        super(ChameleonEnv, self).__init__()
        
        self.target_pid = target_pid
        self.damon_data_path = os.path.abspath(damon_data_path)
        
        # 初始化提取器
        self.damon_extractor = DamonFeatureExtractor(self.damon_data_path)
        
        # 动作空间：5个离散旋钮 [p_access, p_direction, p_threshold, p_survival, p_ghost]
        self.action_space = spaces.MultiDiscrete([3, 2, 4, 2, 2])
        
        # 状态空间：[WSS(MiB), Cold%, Warm%, Hot%]
        # 注意：这里我们给 WSS 设置一个合理的上限(比如1000MiB)，百分比自然是0-1
        self.observation_space = spaces.Box(
            low=np.array([0.0, 0.0, 0.0, 0.0]),
            high=np.array([1000.0, 1.0, 1.0, 1.0]),
            dtype=np.float32
        )
        
        self.map_id = 5 
        self.prev_misses = 0
        self.current_step = 0
        self.max_steps = 200

    def _record_damon_trace(self, duration=1.0):
        """
        在给定的持续时间内录制 DAMON 数据，用于生成下一步的状态
        """
        data_dir = os.path.dirname(self.damon_data_path)
        os.makedirs(data_dir, exist_ok=True)
        
        # 确保旧文件被清理
        if os.path.exists(self.damon_data_path):
            os.remove(self.damon_data_path)

        cmd = [
            "sudo", "damo", "record", 
            "-o", self.damon_data_path,
            str(self.target_pid)
        ]
        
        try:
            # 这里的 timeout 充当了强化学习中的 "让子弹飞一会儿" (time.sleep)
            # 系统在这个 duration 内会带着新的变色龙参数运行
            subprocess.run(cmd, timeout=duration, capture_output=True)
        except subprocess.TimeoutExpired:
            pass # 超时掐断是我们的预期行为

    def _get_system_misses(self) -> int:
        """从 /proc/vmstat 获取绝对缺页数"""
        try:
            with open('/proc/vmstat', 'r') as f:
                for line in f:
                    if line.startswith('pgmajfault'):
                        return int(line.split()[1])
        except Exception:
            pass
        return 0

    def _apply_action(self, action: np.ndarray):
        """调用 bpftool 修改内核变色龙的策略"""
        hex_values = []
        for val in action:
            hex_values.extend([f"{val:02x}", "00", "00", "00"])
        value_hex_str = " ".join(hex_values)
        cmd = f"sudo bpftool map update id {self.map_id} key hex 00 00 00 00 value hex {value_hex_str}"
        subprocess.run(cmd.split(), capture_output=True, check=False)

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        
        # 恢复默认的瞎子 FIFO 策略
        self._apply_action(np.array([0, 0, 0, 0, 0]))
        
        # 录制一小段初始数据并获取基准缺页数
        self._record_damon_trace(duration=1.0)
        self.prev_misses = self._get_system_misses()
        
        # 解析数据生成初始状态
        obs = self.damon_extractor.get_state_vector()
        return obs, {}

def step(self, action):
        # 1. 改变内核策略 (动作)
        self._apply_action(action)
        
        # 2. 获取新状态 (自带 1 秒的物理运行时间和数据采样，时间流逝在这里发生！)
        obs = self.damon_extractor.get_current_state(duration=1.0)
        
        # 3. 计算奖励
        current_misses = self._get_system_misses()
        delta_misses = current_misses - self.prev_misses
        reward = - (delta_misses / 1000.0) 
        self.prev_misses = current_misses
        
        # 4. 步数推进
        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        
        return obs, reward, terminated, False, {}