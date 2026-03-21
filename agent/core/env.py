import gymnasium as gym
from gymnasium import spaces
import numpy as np
import subprocess
import os
import struct
import time
import json

class ChameleonEnv(gym.Env):
    """
    AI for OS: 变色龙 eBPF 强化学习沙盒环境 (V7 策略路由 + Cgroup 原生感知)
    """
    def __init__(self, target_pid: int, cgroup_path: str):
        super(ChameleonEnv, self).__init__()
        
        self.target_pid = target_pid
        self.cgroup_path = os.path.abspath(cgroup_path)

        # 查找底层的核心 Map
        self.params_map_id = self._find_bpf_map_id("cml_params_map")
        self.stats_map_id = self._find_bpf_map_id("cml_stats_map")
        
        if not self.params_map_id or not self.stats_map_id:
            print("⚠️ [Env] 警告: 未找到 eBPF Map，请确认变色龙内核探针已加载！")

        # ==========================================
        # 1. 动作空间: 极简的离散 4 维 (专家路由)
        # ==========================================
        # 0: LRU, 1: SIEVE, 2: MRU, 3: LFU
        self.action_space = spaces.Discrete(4)
        self.current_action = 0
        
        # ==========================================
        # 2. 状态空间: 8 维破局向量
        # ==========================================
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(8,), dtype=np.float32 
        )
        
        self.prev_min_flt, self.prev_maj_flt = 0, 0
        self.prev_regrets = np.zeros(4, dtype=np.int64)
        
        self.current_step = 0
        self.max_steps = 1000

    def _get_vmstat(self):
        pgfault, pgmajfault = 0, 0
        try:
            with open('/proc/vmstat', 'r') as f:
                for line in f:
                    if line.startswith('pgmajfault '):
                        pgmajfault = int(line.split()[1])
                    elif line.startswith('pgfault '):
                        pgfault = int(line.split()[1])
        except Exception:
            pass
        return pgfault, pgmajfault

    def _get_cgroup_metrics(self):
        """
        从 Cgroup v2 统一获取绝对隔离的物理指标
        返回: (wss_mb, total_pgfault, pgmajfault)
        """
        wss_bytes = 0
        pgfault = 0
        pgmajfault = 0
        
        stat_file = os.path.join(self.cgroup_path, "memory.stat")
        try:
            with open(stat_file, 'r') as f:
                for line in f:
                    if line.startswith('file '):
                        wss_bytes = int(line.split()[1])
                    elif line.startswith('pgfault '):
                        pgfault = int(line.split()[1])
                    elif line.startswith('pgmajfault '):
                        pgmajfault = int(line.split()[1])
        except Exception:
            pass
            
        return wss_bytes / (1024 * 1024), pgfault, pgmajfault

    def _find_bpf_map_id(self, target_name: str) -> int | None:
        truncated_name = target_name[:15] 
        try:
            result = subprocess.run(["sudo", "bpftool", "map", "list", "-j"], capture_output=True, text=True, check=True)
            maps = json.loads(result.stdout)
            for m in maps:
                map_name = m.get("name", "")
                if map_name == target_name or map_name == truncated_name:
                    return m.get("id")
        except Exception:
            pass
        return None

    def _get_ebpf_regrets(self) -> np.ndarray:
        """纯粹化：只从 cml_stats_map 提取 4 个策略的累计 Regret"""
        if not self.stats_map_id:
            return np.zeros(4, dtype=np.int64)
            
        cmd = ["sudo", "bpftool", "map", "dump", "id", str(self.stats_map_id), "-j"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            entries = json.loads(res.stdout)
            if not entries: 
                return np.zeros(4, dtype=np.int64)
                
            val = entries[0]["value"]
            if isinstance(val, dict):
                regrets = np.array([int(val["score_counts"][i]) for i in range(4)], dtype=np.int64)
            elif isinstance(val, list):
                b_list = bytes([int(x, 16) if isinstance(x, str) else int(x) for x in val])
                unpacked = struct.unpack("<12q", b_list)
                regrets = np.array(unpacked[1:5], dtype=np.int64)
            else:
                return np.zeros(4, dtype=np.int64)
                
            return np.maximum(0, regrets)
            
        except Exception:
            return np.zeros(4, dtype=np.int64)

    def _apply_action_to_ebpf(self, action: int):
        if not self.params_map_id: return
        
        packed_bytes = struct.pack("<I", action)
        value_hex_str = " ".join(f"{b:02x}" for b in packed_bytes)
        cmd = f"sudo bpftool map update id {self.params_map_id} key hex 00 00 00 00 value hex {value_hex_str}"
        
        try:
            subprocess.run(cmd.split(), capture_output=True, text=True, check=True)
            self.current_action = action
        except subprocess.CalledProcessError as e:
            print(f"❌ 警告: 切换底层策略失败! {e.stderr}")

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        
        self._apply_action_to_ebpf(0)
        _, self.prev_total_flt, self.prev_maj_flt = self._get_cgroup_metrics()
        self.prev_regrets = self._get_ebpf_regrets()

        obs = np.zeros(8, dtype=np.float32)
        return obs, {}

    def step(self, action):
        action = int(action)
        self._apply_action_to_ebpf(action)
        
        pre_wss, pre_total, pre_maj = self._get_cgroup_metrics()
        
        # 观测窗口：阻塞 1 秒，等待 I/O 规律显现
        time.sleep(1.0)
        
        post_wss, post_total, post_maj = self._get_cgroup_metrics()
        
        # 精确计算增量
        delta_total = max(0, post_total - pre_total)
        delta_maj = max(0, post_maj - pre_maj)
        delta_min = max(0, delta_total - delta_maj) # 总数减去 Major 就是纯粹的 Minor (内存命中)
        
        # 提取 eBPF 的错杀账本
        curr_regrets = self._get_ebpf_regrets()
        delta_regrets = np.maximum(0, curr_regrets - self.prev_regrets)
        
        # 构建 8 维状态向量
        obs = np.zeros(8, dtype=np.float32)
        obs[0] = np.log1p(delta_min)
        obs[1] = np.log1p(delta_maj)
        obs[2] = np.log1p(post_wss) # 直接使用最新的 WSS
        obs[3] = float(self.current_action)
        obs[4:8] = np.log1p(delta_regrets)
        
        # ==========================================
        # 🏆 精准追责奖励函数 (Reward Shaping)
        # ==========================================
        base_penalty = - (np.log1p(delta_maj) * 2.0)
        
        my_regret = delta_regrets[action]
        regret_penalty = - (np.log1p(my_regret) * 3.0)
        
        reward = base_penalty + regret_penalty
        reward = float(np.clip(reward, -15.0, 5.0))
        
        self.prev_regrets = curr_regrets
        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        
        return obs, reward, terminated, False, {}

if __name__ == "__main__":  
    print("🚀 启动 Chameleon 沙盒环境集成测试 (V7 策略路由 + Cgroup 原生感知)...")
    
    env = ChameleonEnv(
        target_pid=os.getpid(), 
        cgroup_path="/sys/fs/cgroup/cache_ext_test"
    )
    
    print("\n[1/3] 测试环境 Reset...")
    obs, info = env.reset()
    np.set_printoptions(precision=4, suppress=True)
    print(f"✅ Reset 成功! 初始状态向量:\n{obs}")
    
    print("\n[2/3] 测试环境 Step (下发策略 1: SIEVE)...")
    for i in range(5):
        obs, reward, terminated, truncated, info = env.step(1)
        print(f"\n✅ Step {i+1} 成功!")
        print(f"🔹 新状态向量 (Faults & WSS & Regrets): {obs}")
        print(f"🔹 获得 Reward: {reward:.4f}")