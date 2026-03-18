# env.py - ChameleonEnv: 变色龙 eBPF 强化学习沙盒环境 (终极 V3 成本敏感+对数平滑版)
import gymnasium as gym
from gymnasium import spaces
import numpy as np
import subprocess
import os
import struct


# 导入我们亲手打造的两大神器
from .vfs_extractor import DamonVFSExtractor
from .ebpf_extractor import EbpfReuseExtractor

class ChameleonEnv(gym.Env):
    """
    AI for OS: 变色龙 eBPF 强化学习沙盒环境 (终极 V3 成本敏感+对数平滑版)
    """
    def __init__(self, target_pid: int, watch_dir: str, bpf_exec_path: str):
        super(ChameleonEnv, self).__init__()
        
        self.target_pid = target_pid

        # ==========================================
        # 动态雷达：自动寻的 Chameleon 控制 Map
        # ==========================================
        self.map_name = "cml_params_map" 
        self.map_id = self._find_bpf_map_id(self.map_name)
        if not self.map_id:
            raise RuntimeError(f"致命错误：找不到名为 {self.map_name} 的 eBPF Map！请确认 C 程序已加载。")
        print(f"[Env] 雷达成功锁定变色龙控制平面! ID: {self.map_id}")

        # ==========================================
        # 1. 动作空间 (Action Space): 5 个旋钮
        # ==========================================
        self.action_space = spaces.MultiDiscrete([3, 2, 4, 2, 2])
        self.current_action = np.zeros(5, dtype=np.float32)
        
        # ==========================================
        # 2. 状态空间 (Observation Space): 15 维终极向量
        # ==========================================
        # 0: log1p(WSS_MiB)
        # 1-3: Cold%, Warm%, Hot%
        # 4-5: log1p(Reuse_Count), log1p(Avg_Distance)
        # 6-7: log1p(Minor_Faults), log1p(Major_Faults)
        # 8-12: Action_1 到 Action_5 (归一化到 0~1 的当前自身状态)
        # 13-14: 痛觉加速度 (Minor Acceleration, Major Acceleration)
        self.observation_space = spaces.Box(
            low=-np.inf, high=np.inf, shape=(15,), dtype=np.float32 
        )
        
        # 初始化双子星提取器
        print("[Env] 正在挂载 DAMON 宏观雷达与 eBPF 微观显微镜...")
        self.damon_extractor = DamonVFSExtractor(target_pid)
        self.ebpf_extractor = EbpfReuseExtractor(watch_dir, bpf_exec_path)
        
        # 内部状态记录
        self.prev_min_flt = 0
        self.prev_maj_flt = 0
        # 记忆模块：用于计算痛觉加速度
        self.prev_delta_min = 0.0
        self.prev_delta_maj = 0.0
        self.current_step = 0
        self.max_steps = 1000

    def _get_vmstat(self):
        """
        读取系统的 Minor 和 Major Page Faults
        """
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
        """
        带重试机制的活动 PID 雷达。兼容 FIO 和 YCSB！
        """
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
        """
        调用 bpftool 动态查找 Map ID，完美处理内核 15 字符截断问题
        """
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
        """
        特征工程核心：拼接并平滑极其悬殊的系统级指标，注入系统加速度
        """
        obs = np.zeros(15, dtype=np.float32)
        
        # [0-3] DAMON 宏观状态
        obs[0] = np.log1p(damon_state[0]) 
        obs[1:4] = damon_state[1:4] 
        
        # [4-5] eBPF 微观状态 
        obs[4] = np.log1p(ebpf_state[0] * 1000.0) 
        obs[5] = np.log1p(ebpf_state[1] * 1000.0)
        
        # [6-7] 系统痛觉 (缺页中断对数化)
        obs[6] = np.log1p(delta_min)
        obs[7] = np.log1p(delta_maj)
        
        # [8-12] 自身状态感知 (归一化当前动作)
        max_actions = np.array([2.0, 1.0, 3.0, 1.0, 1.0], dtype=np.float32)
        safe_max = np.where(max_actions == 0, 1.0, max_actions) 
        obs[8:13] = self.current_action / safe_max
        
        # [13-14] 痛觉加速度 (感知系统正在恶化还是好转)
        # 当前对数痛觉减去上一秒的对数痛觉
        obs[13] = obs[6] - np.log1p(self.prev_delta_min)
        obs[14] = obs[7] - np.log1p(self.prev_delta_maj)
        
        return obs

    def _apply_action_to_ebpf(self, action: np.ndarray):
        """调用 bpftool 下发变色龙策略"""
        # 1. 安全转换：处理负数异常，并确保强转为无符号 32 位整数的逻辑
        # (注意：如果 RL 输出是 [-1, 1]，你必须在此之前将其映射到实际物理意义的值，比如 0 或 1)
        safe_action = [int(val) & 0xFFFFFFFF for val in action]
        
        # 2. 极致严谨的内存打包：
        # "<5I" 代表：小端序 (Little-Endian)，5 个 Unsigned Int (32-bit)
        # 这完美对应了 C 语言里面的 struct rl_params
        packed_bytes = struct.pack("<5I", *safe_action)
        
        # 3. 转换为 bpftool 认识的绝对标准的十六进制字符串 (例如: "01 00 00 00 00 00 ...")
        value_hex_str = " ".join(f"{b:02x}" for b in packed_bytes)
        
        cmd = f"sudo bpftool map update id {self.map_id} key hex 00 00 00 00 value hex {value_hex_str}"
        
        # 4. 强硬执行：如果更新失败，必须暴露出来，绝对不能静默！
        try:
            # check=True 会在命令失败时抛出异常
            subprocess.run(cmd.split(), capture_output=True, text=True, check=True)
        except subprocess.CalledProcessError as e:
            print(f"❌ 致命错误: bpftool 更新 Map 失败!")
            print(f"执行命令: {cmd}")
            print(f"错误信息: {e.stderr}")
            # 根据你的容错要求，这里可以抛出异常，也可以选择跳过
            raise e 
            
        self.current_action = action

    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.current_step = 0
        
        # 清除痛觉记忆，防止新一轮被上一轮干扰
        self.prev_delta_min = 0.0
        self.prev_delta_maj = 0.0
        
        # 1. 重置变色龙为出厂设置 [0, 0, 0, 0, 0]
        self._apply_action_to_ebpf(np.zeros(5, dtype=int))
        
        # 2. 建立 vmstat 基线
        self.prev_min_flt, self.prev_maj_flt = self._get_vmstat()
        
        # 2+. 确保 DAMON 监控的 PID 是当前活跃的 fio 进程
        current_target_pid = self._get_active_target_pid()
        self.damon_extractor.target_pid = current_target_pid

        # 3. 提取初始状态
        damon_state = self.damon_extractor.get_current_state(duration=1.0)
        ebpf_state = self.ebpf_extractor.get_step_stats()
        
        obs = self._build_observation(damon_state, ebpf_state, 0, 0)
        return obs, {}

    def step(self, action):
        # 1. 瞬间切换内核策略
        self._apply_action_to_ebpf(action)
        
        # 2. 采样起始时间点的缺页数
        pre_min, pre_maj = self._get_vmstat()

        # 2+. 确保 DAMON 监控的 PID 是当前活跃的 fio 进程
        current_target_pid = self._get_active_target_pid()
        self.damon_extractor.target_pid = current_target_pid
        
        # 3. 让子弹飞：提取 DAMON 数据！(物理阻塞 1.0 秒)
        damon_state = self.damon_extractor.get_current_state(duration=1.0)
        
        # 4. 采集 eBPF 统计的重用增量
        ebpf_state = self.ebpf_extractor.get_step_stats()
        
        # 5. 计算 1 秒内的缺页增量
        post_min, post_maj = self._get_vmstat()
        delta_min = max(0, post_min - pre_min)
        delta_maj = max(0, post_maj - pre_maj)
        
        # 6. 组装 15 维终极状态向量
        obs = self._build_observation(damon_state, ebpf_state, delta_min, delta_maj)
        # print("[Debug] 当前状态向量:", obs)
        
        # ==========================================
        # 7. 灵魂设计：Reward 函数 (V3 终极版：对数平滑 + 成本意识)
        # ==========================================
        # 7.1 对数平滑基础痛觉 (防止瞬间几万次缺页导致梯度爆炸)
        base_penalty = - (np.log1p(delta_maj) * 5.0 + np.log1p(delta_min) * 0.5)
        
        # 7.2 架构开销惩罚 (The Overhead Cost)
        overhead_penalty = 0.0
        # 惩罚DAMON高频采样
        overhead_penalty -= (action[0] * 0.5)
        # 惩罚幽灵表的大内存开销
        if action[4] == 1:
            overhead_penalty -= 1.0
            
        # 7.3 终极结算
        reward = base_penalty + overhead_penalty
        
        # 7.4 [重要] 更新历史记忆，供下一步计算“加速度”使用！
        self.prev_delta_min = delta_min
        self.prev_delta_maj = delta_maj
        
        # 8. 步数推进
        self.current_step += 1
        terminated = self.current_step >= self.max_steps
        
        return obs, reward, terminated, False, {}
