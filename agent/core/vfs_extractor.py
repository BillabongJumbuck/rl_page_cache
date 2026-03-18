import os
import subprocess
import numpy as np

class DamonVFSExtractor:
    def __init__(self, target_pid: int):
        self.target_pid = target_pid
        # 1. 获取当前脚本 (vfs_extractor.py) 所在的 core/ 目录
        self.core_dir = os.path.dirname(os.path.abspath(__file__))
        # 2. 绑定同在 core/ 目录下的 fish 脚本
        self.script_path = os.path.join(self.core_dir, "damon_vfs.fish")
        # 3. 把生成的 raw_trace.txt 扔回上一级 (即 agent 根目录)，保持 core 目录的纯净
        self.trace_file = os.path.abspath(os.path.join(self.core_dir, "../logs", "raw_trace.txt"))

    def get_current_state(self, duration=1.0) -> np.ndarray:
        # 1. 呼叫脚本
        subprocess.run([
            "sudo", self.script_path, 
            str(self.target_pid), 
            str(duration), 
            self.trace_file
        ], check=False, stdout=subprocess.DEVNULL)

        if not os.path.exists(self.trace_file):
            return np.zeros(4, dtype=np.float32)
        
        with open(self.trace_file, "r") as f:
            lines = f.readlines()

        # 使用字典来聚合这 1 秒内的访问次数
        # Key: (start_addr, end_addr), Value: 1秒内的总访问次数
        regions_heat = {}

        # 2. 健壮的文本解析
        for line in lines:
            if "damon_aggregated" not in line:
                continue
            try:
                # 使用 .split() 自动处理多个空格的情况
                parts = line.split("nr_regions=")[1].strip().split()
                addr_range = parts[1].replace(":", "")
                
                start_addr, end_addr = map(int, addr_range.split("-"))
                nr_accesses = int(parts[2])
                
                region_key = (start_addr, end_addr)
                if region_key not in regions_heat:
                    regions_heat[region_key] = 0
                
                # 累加这 1 秒内该区域被访问的总次数
                regions_heat[region_key] += nr_accesses
            except Exception:
                continue

        # print(f"[DEBUG] 共解析到 {len(regions_heat)} 个独立的内存区域")

        total_cold_bytes = 0
        total_warm_bytes = 0
        total_hot_bytes = 0
        wss_bytes = 0
        total_tracked_bytes = 0

        # 3. 统计冷热比例
        for (start, end), total_accesses in regions_heat.items():
            region_size = end - start
            total_tracked_bytes += region_size
            
            # 只要在这 1 秒内被碰过一次，就算入工作集 (WSS)
            if total_accesses > 0:
                wss_bytes += region_size
                
            # DAMON 默认每 5ms 采样一次，100ms 聚合一次，最高单次 access=20
            # 1 秒内最高理论 access 为 200。我们可以自由定义冷热阈值：
            if total_accesses <= 2:       # 极冷 (1秒内基本没碰过)
                total_cold_bytes += region_size
            elif total_accesses <= 20:    # 温热
                total_warm_bytes += region_size
            else:                         # 滚烫
                total_hot_bytes += region_size

        if total_tracked_bytes == 0:
            print("[DEBUG] 警告：提取到的总监控内存为 0 字节")
            return np.zeros(4, dtype=np.float32)

        state = np.array([
            wss_bytes / (1024 * 1024), 
            total_cold_bytes / total_tracked_bytes, 
            total_warm_bytes / total_tracked_bytes, 
            total_hot_bytes / total_tracked_bytes
        ], dtype=np.float32)
        
        return state


if __name__ == "__main__":
    import sys
    test_pid = int(sys.argv[1]) if len(sys.argv) > 1 else os.getpid()
    # test_pid = 56877
    
    print(f"正在通过 VFS 提取 PID {test_pid} 的特征，时长 1.0 秒...")
    extractor = DamonVFSExtractor(target_pid=test_pid)
    state = extractor.get_current_state(1.0)
    
    np.set_printoptions(precision=4, suppress=True)
    print(f"状态向量 $S_t$ [WSS(MiB), Cold%, Warm%, Hot%]: {state}")