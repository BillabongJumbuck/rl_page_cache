import gymnasium as gym
from gymnasium import spaces
import numpy as np
import subprocess
import time

class ChameleonEnv(gym.Env):
    """
    AI for OS: 变色龙 eBPF 强化学习沙盒环境
    """
    def __init__(self):
        super(ChameleonEnv, self).__init__()
        
        # ==========================================
        # 1. 动作空间 (Action Space): 变色龙的 5 个旋钮
        # [p_access, p_direction, p_threshold, p_survival, p_ghost]
        # p_access:    0, 1, 2 (瞎子, 布尔, 计数)
        # p_direction: 0, 1    (尾部扫描, 头部扫描) -> 注意：我们目前底层被强制为 0，这里保留维度但Agent会发现改它没用
        # p_threshold: 0, 1, 2, 3 (免死阈值)
        # p_survival:  0, 1    (降级, 摘下重排)
        # p_ghost:     0, 1    (关闭, 开启幽灵表)
        # ==========================================
        self.action_space = spaces.MultiDiscrete([3, 2, 4, 2, 2])
        
        # ==========================================
        # 2. 状态空间 (Observation Space): DAMON/eBPF 提取的特征
        # 假设我们目前喂给 Agent 3 个连续特征：
        # [Delta缺页数(归一化), 重用距离均值, WSS工作集大小]
        # ==========================================
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(3,), dtype=np.float32
        )
        
        # eBPF Map 的 ID (你需要根据实际情况修改，之前我们查到是 5)
        # 更优雅的做法是在 Python 里通过名字查找 ID，这里先硬编码跑通 MVP
        self.map_id = 5 
        
        # 内部状态记录
        self.prev_misses = 0
        self.current_step = 0
        self.max_steps = 1000 # 跑1000次调参算通关一个 Episode

    def _get_system_misses(self) -> int:
        """
        [桩函数] 从系统中读取当前的 Page Fault 次数。
        实际中可以通过读取 /proc/vmstat 中的 pgmajfault 字段来实现。
        """
        try:
            with open('/proc/vmstat', 'r') as f:
                for line in f:
                    if line.startswith('pgmajfault'):
                        return int(line.split()[1])
        except Exception:
            pass
        return 0

    def _get_damon_features(self) -> np.ndarray:
        """
        [桩函数] 从 DAMON 或第一阶段 eBPF 读取状态特征。
        目前先返回随机的 Dummy 数据，证明流水线跑通。
        """
        # 真实场景：读取 /sys/kernel/debug/damon/ 或你的 BPF Map
        delta_miss = np.random.uniform(0, 1)
        reuse_dist_mean = np.random.uniform(10, 100)
        wss_size = np.random.uniform(50, 100)
        return np.array([delta_miss, reuse_dist_mean, wss_size], dtype=np.float32)

    def _apply_action_to_ebpf(self, action: np.ndarray):
        """
        调用 bpftool 瞬间修改内核变色龙的策略！
        action 形如 [1, 0, 0, 1, 0]
        """
        # 将 [1, 0, 0, 1, 0] 转换为小端的十六进制字节流
        # 对应 C 语言里的 struct: p_access, p_direction, p_threshold, p_survival, p_ghost (__u32)
        hex_values = []
        for val in action:
            # __u32 占 4 个字节，小端模式：比如 1 变成 "01 00 00 00"
            hex_values.extend([f"{val:02x}", "00", "00", "00"])
        
        value_hex_str = " ".join(hex_values)
        
        # 拼接命令: sudo bpftool map update id 5 key hex 00 00 00 00 value hex 01 00...
        cmd = f"sudo bpftool map update id {self.map_id} key hex 00 00 00 00 value hex {value_hex_str}"
        
        # 静默执行
        subprocess.run(cmd.split(), capture_output=True, check=False)

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        
        # 重置环境：将变色龙切回纯 FIFO [0, 0, 0, 0, 0]
        self._apply_action_to_ebpf(np.array([0, 0, 0, 0, 0]))
        
        # 初始化基准缺页数
        self.prev_misses = self._get_system_misses()
        
        # 返回初始状态和空 info 字典 (Gymnasium V26 标准)
        obs = self._get_damon_features()
        return obs, {}

    def step(self, action):
        # 1. 下发动作，改变内核策略！
        self._apply_action_to_ebpf(action)
        
        # 2. 让子弹飞一会儿：系统带着新策略运行一段时间（比如 1 秒）
        time.sleep(1.0)
        
        # 3. 收集这 1 秒内的战果
        current_misses = self._get_system_misses()
        delta_misses = current_misses - self.prev_misses
        
        # 4. 计算奖励 (Reward) - 黄金级方案
        # 如果缺页数变少了（系统变好了），由于我们要最大化 reward，给一个负的 delta 作为惩罚
        # 比如：delta 是 500 次缺页，reward 就是 -0.5
        reward = - (delta_misses / 1000.0) 
        
        # 5. 更新内部状态
        self.prev_misses = current_misses
        obs = self._get_damon_features()
        
        # 6. 步数推进与结束判定
        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        truncated = False # 是否因为异常中断
        
        return obs, reward, terminated, truncated, {}