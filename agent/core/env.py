# env.py - ChameleonEnv: 变色龙 eBPF 强化学习沙盒环境 (终极 V5 纯 eBPF 物理视角版)
import gymnasium as gym
from gymnasium import spaces
import numpy as np
import subprocess
import os
import struct
import time

# 全面抛弃 DAMON，拥抱全能的 eBPF 提取器
from .ebpf_extractor import EbpfStateExtractor

class ChameleonEnv(gym.Env):
    """
    AI for OS: 变色龙 eBPF 强化学习沙盒环境 (终极 V5 纯 eBPF 物理视角版)
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
        # 1. 动作空间: 4 个核心旋钮
        # ==========================================
        # [访问计分, 热区百分比, 晋升门槛, 幽灵开关]
        self.action_space = spaces.MultiDiscrete([3, 101, 4, 2])
        self.current_action = np.zeros(4, dtype=np.float32)
        
        # ==========================================
        # 2. 状态空间: 14 维终极物理向量
        # ==========================================
        # 0: log1p(WSS_MiB)
        # 1-3: Cold%, Warm%, Hot%
        # 4-5: log1p(Reuse_Count), log1p(Avg_Distance)
        # 6-7: log1p(Minor_Faults), log1p(Major_Faults)
        # 8-11: Action_1 到 Action_4 (归一化自身状态)
        # 12-13: 痛觉加速度 (Minor Acceleration, Major Acceleration)
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(14,), dtype=np.float32 
        )
        
        print("[Env] 正在挂载 eBPF 全知上帝之眼...")
        # 只需要实例化这一个强大的提取器即可
        self.extractor = EbpfStateExtractor(cgroup_path)
        
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

    def _find_bpf_map_id(self, target_name: str) -> int | None:
        import json
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

    def _build_observation(self, macro_state, micro_state, delta_min, delta_maj) -> np.ndarray:
        obs = np.zeros(14, dtype=np.float32)
        
        # [0-3] eBPF 宏观物理拓扑 (零延迟、零死角)
        obs[0] = np.log1p(macro_state[0]) 
        obs[1:4] = macro_state[1:4] 
        
        # [4-5] eBPF 微观重用特征
        obs[4] = np.log1p(micro_state[0] * 1000.0) 
        obs[5] = np.log1p(micro_state[1] * 1000.0)
        
        # [6-7] 系统痛觉
        obs[6] = np.log1p(delta_min)
        obs[7] = np.log1p(delta_maj)
        
        # [8-11] 自身动作感知
        max_actions = np.array([2.0, 100.0, 3.0, 1.0], dtype=np.float32)
        safe_max = np.where(max_actions == 0, 1.0, max_actions) 
        obs[8:12] = self.current_action / safe_max
        
        # [12-13] 痛觉加速度 
        obs[12] = obs[6] - np.log1p(self.prev_delta_min)
        obs[13] = obs[7] - np.log1p(self.prev_delta_maj)
        
        return obs

    def _apply_action_to_ebpf(self, action: np.ndarray):
        safe_action = [int(val) & 0xFFFFFFFF for val in action]
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
        
        self._apply_action_to_ebpf(np.zeros(4, dtype=int))
        self.prev_min_flt, self.prev_maj_flt = self._get_vmstat()

        # 直接从 eBPF 提取微观和宏观物理状态 (Reset 时默认门槛假设为 2，或 0)
        micro_state = self.extractor.get_micro_state()
        macro_state = self.extractor.get_macro_state(promote_thresh=2)
        
        obs = self._build_observation(macro_state, micro_state, 0, 0)
        return obs, {}

    def step(self, action):
        self._apply_action_to_ebpf(action)
        pre_min, pre_maj = self._get_vmstat()
        
        # 物理阻塞 1 秒，让子弹飞 (代替了原先 DAMON 脚本里的 duration)
        time.sleep(1.0)
        
        # 提取 eBPF 物理状态，传入 AI 刚刚下发的晋升门槛！
        micro_state = self.extractor.get_micro_state()
        # action[2] 就是 p_promote_thresh
        macro_state = self.extractor.get_macro_state(promote_thresh=int(action[2]))
        
        post_min, post_maj = self._get_vmstat()
        delta_min = max(0, post_min - pre_min)
        delta_maj = max(0, post_maj - pre_maj)
        
        obs = self._build_observation(macro_state, micro_state, delta_min, delta_maj)
        
        # 注意：因为废弃了高开销的 DAMON，去掉了 DAMON 相关的开销惩罚
        base_penalty = - (np.log1p(delta_maj) * 5.0 + np.log1p(delta_min) * 0.5)
        
        overhead_penalty = 0.0
        if action[3] == 1: # 幽灵表内存开销惩罚
            overhead_penalty -= 1.0
            
        reward = base_penalty + overhead_penalty
        
        self.prev_delta_min = delta_min
        self.prev_delta_maj = delta_maj
        
        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        
        return obs, reward, terminated, False, {}

if __name__ == "__main__":  
    print("🚀 启动 Chameleon 沙盒环境集成测试...")
    
    env = ChameleonEnv(
        target_pid=os.getpid(), 
        cgroup_path="/sys/fs/cgroup/cache_ext_train"
    )
    
    print("\n[1/3] 测试环境 Reset...")
    obs, info = env.reset()
    np.set_printoptions(precision=4, suppress=True)
    print(f"✅ Reset 成功! 初始状态向量 (14维):\n{obs}")
    
    print("\n[2/3] 测试环境 Step (下发全 0 动作)...")
    action = np.zeros(4, dtype=int)
    obs, reward, terminated, truncated, info = env.step(action)
    
    print(f"✅ Step 成功!")
    print(f"🔹 新状态向量:\n{obs}")
    print(f"🔹 获得 Reward: {reward:.4f}")
    
    env.extractor.cleanup()