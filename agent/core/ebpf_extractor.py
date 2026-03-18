# ebpf_extractor.py
import subprocess
import json
import threading
import atexit
import os
import numpy as np

class EbpfReuseExtractor:
    def __init__(self, cgroup_path: str):
        self.cgroup_path = os.path.abspath(cgroup_path)
        self.bpf_exec_path = os.path.expanduser("~/rl_page_cache/bpf/cache_ext_reuse.out")
        
        # 启动 eBPF C 程序作为子进程，替换原来的 -w 为 -c
        self.proc = subprocess.Popen(
            ["sudo", self.bpf_exec_path, "-c", self.cgroup_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, # 屏蔽掉 C 程序的提示信息
            text=True
        )
        
        self.latest_data = {"count": 0, "sum": 0, "sum_sq": 0, "seq": 0}
        self.prev_data = {"count": 0, "sum": 0, "sum_sq": 0, "seq": 0}
        
        # 开启后台守护线程，持续贪婪地读取 JSON 输出
        self.thread = threading.Thread(target=self._read_loop, daemon=True)
        self.thread.start()
        
        # 确保 Python 退出时，超度掉这个 eBPF 探针
        atexit.register(self.cleanup)

    def _read_loop(self):
        # 持续读取 stdout，只要有新行就更新 latest_data
        for line in self.proc.stdout:
            try:
                self.latest_data = json.loads(line.strip())
            except json.JSONDecodeError:
                continue

    def get_step_stats(self) -> np.ndarray:
        """
        返回当前时间步的特征: [重用次数(千次), 平均重用距离(K)]
        """
        curr = self.latest_data.copy()
        prev = self.prev_data
        
        # 计算这一秒内的增量
        d_count = curr["count"] - prev["count"]
        d_sum = curr["sum"] - prev["sum"]
        
        avg_dist = (d_sum / d_count) if d_count > 0 else 0.0
        
        self.prev_data = curr
        
        # 为了让神经网络好消化，把数值缩小一点
        return np.array([
            d_count / 1000.0, 
            avg_dist / 1000.0
        ], dtype=np.float32)

    def cleanup(self):
        if self.proc.poll() is None:
            # 优雅地发送 SIGINT 给 sudo
            subprocess.run(["sudo", "pkill", "-INT", "-P", str(self.proc.pid)], check=False, stderr=subprocess.DEVNULL)
            self.proc.terminate()

# --- 测试桩 ---
if __name__ == "__main__":
    import time
    
    # 填入你编译好的 C 程序路径和监控的 cgroup 目录
    test_cgroup = "/sys/fs/cgroup/cache_test"
    
    print(f"正在启动 eBPF 探针，监控 Cgroup: {test_cgroup}")
    extractor = EbpfReuseExtractor(test_cgroup)
    
    print("等待 2 秒让探针初始化...")
    time.sleep(2)
    
    for _ in range(100):
        print("等待 1 秒采样...")
        time.sleep(1)
        stats = extractor.get_step_stats()
        print(f"当前时间步微观特征 [重用次数(K), 平均距离(K)]: {stats}")