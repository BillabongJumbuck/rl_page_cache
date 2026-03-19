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

    def get_macro_state(self, promote_thresh: int = 2) -> np.ndarray:
        """获取物理内存的真实冷热分布: [WSS(MB), Cold%, Warm%, Hot%]"""
        
        # 【关键修改】：去查我们新建的聚合统计 Map
        stats_map_id = self._find_map_id("cml_stats_map")
        if not stats_map_id:
            return np.zeros(4, dtype=np.float32)

        # 现在的 dump 是瞬间完成的 (因为 Map 只有 1 个条目)
        cmd = ["sudo", "bpftool", "map", "dump", "id", str(stats_map_id), "-j"]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            entries = json.loads(res.stdout)
            if not entries: return np.zeros(4, dtype=np.float32)
            
            val = entries[0]["value"]
            # 兼容 BTF 解析和 Raw 字节数组解析
            import struct
            if isinstance(val, dict):
                wss = int(val["wss"])
                counts = [int(val["score_counts"][i]) for i in range(11)]
            elif isinstance(val, list):
                b_list = bytes([int(x, 16) if isinstance(x, str) else int(x) for x in val])
                # 解析 12 个 64 位有符号整数 (1 个 wss + 11 个 count)
                unpacked = struct.unpack("<12q", b_list)
                wss = unpacked[0]
                counts = unpacked[1:12]
            else:
                return np.zeros(4, dtype=np.float32)
        except Exception:
            return np.zeros(4, dtype=np.float32)

        # RL 环境允许一定的并发噪点，防卫性防止负数
        counts = [max(0, c) for c in counts]
        wss = max(0, wss)

        if wss == 0:
            return np.zeros(4, dtype=np.float32)

        wss_mb = (wss * 4096) / (1024 * 1024) 
        
        # 根据当前的门槛值，瞬间算出三级冷热
        cold_pages = counts[0]
        warm_pages = sum(counts[1:promote_thresh])
        hot_pages = sum(counts[promote_thresh:])
        
        total_tracked = cold_pages + warm_pages + hot_pages
        if total_tracked == 0:
            return np.array([wss_mb, 0, 0, 0], dtype=np.float32)

        return np.array([
            wss_mb, 
            cold_pages / total_tracked, 
            warm_pages / total_tracked, 
            hot_pages / total_tracked
        ], dtype=np.float32)

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