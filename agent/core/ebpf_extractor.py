# ebpf_extractor.py
import subprocess
import json
import threading
import atexit
import os
import numpy as np

class EbpfStateExtractor:
    def __init__(self, cgroup_path: str):
        self.cgroup_path = os.path.abspath(cgroup_path)
        self.bpf_exec_path = os.path.expanduser("~/rl_page_cache/bpf/cache_ext_reuse.out")
        
        # ==========================================
        # 1. 初始化微观状态流 (VFS 重用距离)
        # ==========================================
        self.proc = subprocess.Popen(
            ["sudo", self.bpf_exec_path, "-c", self.cgroup_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        self.latest_data = {"count": 0, "sum": 0, "sum_sq": 0, "seq": 0}
        self.prev_data = {"count": 0, "sum": 0, "sum_sq": 0, "seq": 0}
        
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()
        atexit.register(self.cleanup)

        # ==========================================
        # 2. 锁定宏观状态 Map (RMAP 物理热度)
        # ==========================================
        self.macro_map_name = "folio_meta_map"
        self.macro_map_id = self._find_map_id(self.macro_map_name)
        if not self.macro_map_id:
            print(f"⚠️ [Env] 警告: 找不到 {self.macro_map_name}，宏观状态可能无法提取！")
        else:
            print(f"✅ [Env] 成功锁定物理状态 Map ID: {self.macro_map_id}")

    def _find_map_id(self, target_name: str):
        truncated_name = target_name[:15]
        try:
            res = subprocess.run(["sudo", "bpftool", "map", "list", "-j"], capture_output=True, text=True)
            maps = json.loads(res.stdout)
            for m in maps:
                map_name = m.get("name", "")
                if map_name == target_name or map_name == truncated_name:
                    return m.get("id")
        except:
            pass
        return None

    def _read_loop(self):
        # 持续贪婪读取 VFS 微观流
        for line in self.proc.stdout:
            try:
                self.latest_data = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

    def get_micro_state(self) -> np.ndarray:
        """获取 VFS 维度的重用特征: [重用次数(千次), 平均重用距离(K)]"""
        curr = self.latest_data.copy()
        prev = self.prev_data
        
        d_count = curr["count"] - prev["count"]
        d_sum = curr["sum"] - prev["sum"]
        avg_dist = (d_sum / d_count) if d_count > 0 else 0.0
        
        self.prev_data = curr
        
        return np.array([
            d_count / 1000.0, 
            avg_dist / 1000.0
        ], dtype=np.float32)

    def get_macro_state(self) -> np.ndarray:
        """获取物理内存的真实冷热分布: [WSS(MB), Cold%, Warm%, Hot%]"""
        if not self.macro_map_id:
            return np.zeros(4, dtype=np.float32)

        cmd = ["sudo", "bpftool", "map", "dump", "id", str(self.macro_map_id), "-j"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            entries = json.loads(res.stdout)
        except:
            return np.zeros(4, dtype=np.float32)

        total_pages = len(entries)
        if total_pages == 0:
            return np.zeros(4, dtype=np.float32)

        # --- 核心修复：强力解析 bpftool 的奇葩 JSON 格式 ---
        parsed_scores = []
        for entry in entries:
            val = entry.get("value", 0)
            if isinstance(val, (int, float)):
                # 标准数字：直接转换
                parsed_scores.append(int(val))
            elif isinstance(val, str):
                # 十六进制或十进制字符串，例如 "0x03" 或 "3"
                parsed_scores.append(int(val, 0))
            elif isinstance(val, list):
                # 字节数组，例如 ["0x03", "0x00", "0x00", "0x00"]
                try:
                    b_list = [int(x, 16) if isinstance(x, str) else int(x) for x in val]
                    parsed_scores.append(int.from_bytes(b_list, byteorder='little'))
                except:
                    parsed_scores.append(0)
            elif isinstance(val, dict):
                # 如果 BTF 解析成结构体字典，取第一个值
                try:
                    first_val = list(val.values())[0]
                    parsed_scores.append(int(first_val))
                except:
                    parsed_scores.append(0)
            else:
                parsed_scores.append(0)

        scores = np.array(parsed_scores, dtype=np.int32)
        wss_mb = (total_pages * 4096) / (1024 * 1024) 
        
        # 动态读取或写死你的门槛值，这里以 promote_thresh = 2 为例
        thresh = 2 
        
        cold_ratio = np.sum(scores == 0) / total_pages
        warm_ratio = np.sum((scores > 0) & (scores < thresh)) / total_pages
        hot_ratio = np.sum(scores >= thresh) / total_pages

        return np.array([wss_mb, cold_ratio, warm_ratio, hot_ratio], dtype=np.float32)

    def cleanup(self):
        if self.proc.poll() is None:
            subprocess.run(["sudo", "pkill", "-INT", "-P", str(self.proc.pid)], check=False, stderr=subprocess.DEVNULL)
            self.proc.terminate()

# --- 测试桩 ---
if __name__ == "__main__":
    import time
    
    test_cgroup = "/sys/fs/cgroup/cache_ext_test"
    print(f"🚀 启动全能 eBPF 提取器，监控 Cgroup: {test_cgroup}")
    
    extractor = EbpfStateExtractor(test_cgroup)
    time.sleep(2)
    
    for _ in range(5):
        print("\n--- 采样中 ---")
        micro = extractor.get_micro_state()
        macro = extractor.get_macro_state()
        
        np.set_printoptions(precision=4, suppress=True)
        print(f"🔬 微观状态 (VFS): {micro}")
        print(f"🌍 宏观状态 (RMAP): WSS={macro[0]:.2f}MB, Cold={macro[1]*100:.1f}%, Warm={macro[2]*100:.1f}%, Hot={macro[3]*100:.1f}%")
        time.sleep(1)