# env.py - ChameleonEnv: 变色龙 eBPF 强化学习沙盒环境 (终极 V4 降维纯净版)
import gymnasium as gym
from gymnasium import spaces
import numpy as np
import subprocess
import os
import struct

from .vfs_extractor import DamonVFSExtractor
from .ebpf_extractor import EbpfReuseExtractor

class ChameleonEnv(gym.Env):
    """
    AI for OS: 变色龙 eBPF 强化学习沙盒环境 (终极 V4 降维纯净版)
    """
    def __init__(self, target_pid: int, cgroup_path: str):
        super(ChameleonEnv, self).__init__()
        
        self.target_pid = target_pid

        self.map_name = "cml_params_map" 
        self.map_id = self._find_bpf_map_id(self.map_name)
        if not self.map_id:
            raise RuntimeError(f"致命错误：找不到名为 {self.map_name} 的 eBPF Map！请确认 C 程序已加载。")
        print(f"[Env] 雷达成功锁定变色龙控制平面! ID: {self.map_id}")

        # ==========================================
        # 1. 动作空间: 彻底降维至 4 个旋钮
        # ==========================================
        # [访问计分, 热区百分比, 晋升门槛, 幽灵开关]
        self.action_space = spaces.MultiDiscrete([3, 101, 4, 2])
        self.current_action = np.zeros(4, dtype=np.float32)
        
        # ==========================================
        # 2. 状态空间: 14 维终极向量 (移除了多余的 action 占位)
        # ==========================================
        # 0: log1p(WSS_MiB)
        # 1-3: Cold%, Warm%, Hot%
        # 4-5: log1p(Reuse_Count), log1p(Avg_Distance)
        # 6-7: log1p(Minor_Faults), log1p(Major_Faults)
        # 8-11: Action_1 到 Action_4 (归一化到 0~1 的当前自身状态)
        # 12-13: 痛觉加速度 (Minor Acceleration, Major Acceleration)
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(14,), dtype=np.float32 
        )
        
        print("[Env] 正在挂载 DAMON 宏观雷达与 eBPF 微观显微镜...")
        self.damon_extractor = DamonVFSExtractor(target_pid)
        self.ebpf_extractor = EbpfReuseExtractor(cgroup_path)
        
        self.prev_min_flt = 0
        self.prev_maj_flt = 0
        self.prev_delta_min = 0.0
        self.prev_delta_maj = 0.0
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

    def _get_active_target_pid(self, process_names=["fio", "ycsb"]):
        import time 
        for _ in range(10):
            for name in process_names:
                try:
                    pids = subprocess.check_output(["pidof", name]).decode().strip().split()
                    if pids:
                        self.target_pid = int(pids[0])
                        return self.target_pid
                except subprocess.CalledProcessError:
                    continue
            time.sleep(0.1)
        return os.getpid()

    def _find_bpf_map_id(self, target_name: str) -> int | None:
        import json
        import subprocess
        truncated_name = target_name[:15] 
        try:
            result = subprocess.run(["sudo", "bpftool", "map", "list", "-j"], capture_output=True, text=True, check=True)
            maps = json.loads(result.stdout)
            for m in maps:
                map_name = m.get("name", "")
                if map_name == target_name or map_name == truncated_name:
                    return m.get("id")
        except Exception as e:
            print(f"查找 Map ID 失败: {e}")
        return None

    def _build_observation(self, damon_state, ebpf_state, delta_min, delta_maj) -> np.ndarray:
        obs = np.zeros(14, dtype=np.float32)
        
        obs[0] = np.log1p(damon_state[0]) 
        obs[1:4] = damon_state[1:4] 
        
        obs[4] = np.log1p(ebpf_state[0] * 1000.0) 
        obs[5] = np.log1p(ebpf_state[1] * 1000.0)
        
        obs[6] = np.log1p(delta_min)
        obs[7] = np.log1p(delta_maj)
        
        # [8-11] 自身状态感知 (修正归一化分母：动作2最大值为100)
        max_actions = np.array([2.0, 100.0, 3.0, 1.0], dtype=np.float32)
        safe_max = np.where(max_actions == 0, 1.0, max_actions) 
        obs[8:12] = self.current_action / safe_max
        
        # [12-13] 痛觉加速度 
        obs[12] = obs[6] - np.log1p(self.prev_delta_min)
        obs[13] = obs[7] - np.log1p(self.prev_delta_maj)
        
        return obs

    def _apply_action_to_ebpf(self, action: np.ndarray):
        safe_action = [int(val) & 0xFFFFFFFF for val in action]
        
        # 改为 <4I，打包 4 个 32位整数
        packed_bytes = struct.pack("<4I", *safe_action)
        value_hex_str = " ".join(f"{b:02x}" for b in packed_bytes)
        
        cmd = f"sudo bpftool map update id {self.map_id} key hex 00 00 00 00 value hex {value_hex_str}"
        
        try:
            subprocess.run(cmd.split(), capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ 致命错误: bpftool 更新 Map 失败!")
            print(f"执行命令: {cmd}")
            print(f"错误信息: {e.stderr}")
            raise e 
            
        self.current_action = action

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        self.prev_delta_min = 0.0
        self.prev_delta_maj = 0.0
        
        # 重置出厂设置 [0, 0, 0, 0]
        self._apply_action_to_ebpf(np.zeros(4, dtype=int))
        
        self.prev_min_flt, self.prev_maj_flt = self._get_vmstat()
        current_target_pid = self._get_active_target_pid()
        self.damon_extractor.target_pid = current_target_pid

        damon_state = self.damon_extractor.get_current_state(duration=1.0)
        ebpf_state = self.ebpf_extractor.get_step_stats()
        
        obs = self._build_observation(damon_state, ebpf_state, 0, 0)
        return obs, {}

    def step(self, action):
        self._apply_action_to_ebpf(action)
        
        pre_min, pre_maj = self._get_vmstat()
        current_target_pid = self._get_active_target_pid()
        self.damon_extractor.target_pid = current_target_pid
        
        damon_state = self.damon_extractor.get_current_state(duration=1.0)
        ebpf_state = self.ebpf_extractor.get_step_stats()
        
        post_min, post_maj = self._get_vmstat()
        delta_min = max(0, post_min - pre_min)
        delta_maj = max(0, post_maj - pre_maj)
        
        obs = self._build_observation(damon_state, ebpf_state, delta_min, delta_maj)
        
        base_penalty = - (np.log1p(delta_maj) * 5.0 + np.log1p(delta_min) * 0.5)
        
        overhead_penalty = 0.0
        overhead_penalty -= (action[0] * 0.5)
        # 幽灵表开关现在是索引 3
        if action[3] == 1:
            overhead_penalty -= 1.0
            
        reward = base_penalty + overhead_penalty
        
        self.prev_delta_min = delta_min
        self.prev_delta_maj = delta_maj
        
        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        
        return obs, reward, terminated, False, {}

if __name__ == "__main__":  
    import time
    print("🚀 启动 Chameleon 沙盒环境集成测试...")
    
    env = ChameleonEnv(
        target_pid=os.getpid(), 
        cgroup_path="/sys/fs/cgroup/cache_test"
    )
    
    print("\n[1/3] 测试环境 Reset...")
    obs, info = env.reset()
    np.set_printoptions(precision=4, suppress=True)
    print(f"✅ Reset 成功! 初始状态向量 (14维):\n{obs}")
    
    print("\n[2/3] 等待 1 秒，模拟 RL 推理延迟...")
    time.sleep(1)
    
    print("\n[3/3] 测试环境 Step (下发全 0 动作)...")
    # 降维后下发 4 个 0
    action = np.zeros(4, dtype=int)
    obs, reward, terminated, truncated, info = env.step(action)
    
    print(f"✅ Step 成功!")
    print(f"🔹 新状态向量:\n{obs}")
    print(f"🔹 获得 Reward: {reward:.4f}")
    
    # 优雅退出
    env.ebpf_extractor.cleanup()
    