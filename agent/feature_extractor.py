import os
import subprocess
import numpy as np

class DamonFeatureExtractor:
    def __init__(self, data_file_path):
        """
        初始化特征提取器。
        :param data_file_path: DAMON 数据文件的绝对或相对路径 (例如 "../data/damon.data")
        """
        # 转换为绝对路径，方便跨目录调用
        self.data_file_path = os.path.abspath(data_file_path)
        self.data_dir = os.path.dirname(self.data_file_path)
        self.file_name = os.path.basename(self.data_file_path)

    def get_state_vector(self):
        """
        解析 damo report heats 的三维网格数据
        输出: np.ndarray([WSS(MiB), Cold_Ratio, Warm_Ratio, Hot_Ratio])
        """
        # 检查数据文件是否存在
        if not os.path.exists(self.data_file_path):
            print(f"[警告] 数据文件未找到: {self.data_file_path}")
            return np.zeros(4, dtype=np.float32)

        # 核心逻辑：在这个数据文件所在的目录下，执行 sudo damo report heats
        # 这样能完美兼容 v2.2.4 版本默认读取同目录 damon.data 的行为
        cmd = ["sudo", "damo", "report", "heats"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=self.data_dir)
            lines = result.stdout.splitlines()
        except subprocess.CalledProcessError as e:
            print(f"[错误] damo report 解析失败: {e}")
            return np.zeros(4, dtype=np.float32)

        latest_snapshot = -1
        snapshot_data = [] 
        addresses = []     

        for line in lines:
            parts = line.split()
            if len(parts) != 3:
                continue
            
            try:
                snap_id = int(parts[0])
                addr = int(parts[1])
                heat = float(parts[2])
            except ValueError:
                continue

            if snap_id > latest_snapshot:
                latest_snapshot = snap_id
                snapshot_data = []
                addresses = []
            
            if snap_id == latest_snapshot:
                snapshot_data.append(heat)
                addresses.append(addr)

        if len(addresses) < 2:
            return np.zeros(4, dtype=np.float32)

        # 计算桶大小
        bucket_size_bytes = addresses[1] - addresses[0]
        bucket_size_mib = bucket_size_bytes / (1024 * 1024)

        total_size_mib = len(snapshot_data) * bucket_size_mib
        
        wss_mib = sum(1 for heat in snapshot_data if heat > 0) * bucket_size_mib
        cold_mib = sum(1 for heat in snapshot_data if heat < 20) * bucket_size_mib
        warm_mib = sum(1 for heat in snapshot_data if 20 <= heat < 80) * bucket_size_mib
        hot_mib  = sum(1 for heat in snapshot_data if heat >= 80) * bucket_size_mib

        if total_size_mib == 0:
            return np.zeros(4, dtype=np.float32)

        # 组装为浮点数类型的 NumPy 数组，这是 RL 框架 (如 PyTorch) 的标准输入格式
        state_vector = np.array([
            wss_mib, 
            cold_mib / total_size_mib, 
            warm_mib / total_size_mib, 
            hot_mib / total_size_mib
        ], dtype=np.float32)
        
        return state_vector

if __name__ == "__main__":
    # 作为主程序独立运行时，用于快速测试
    # 动态定位到项目根目录下的 data/damon.data
    current_dir = os.path.dirname(os.path.abspath(__file__))
    target_data_file = os.path.join(current_dir, "..", "data", "damon", "damon.data")
    
    print(f"初始化特征提取器，目标文件: {target_data_file}")
    extractor = DamonFeatureExtractor(target_data_file)
    
    state = extractor.get_state_vector()
    np.set_printoptions(precision=4, suppress=True)
    print(f"状态向量 $S_t$ [WSS(MiB), Cold%, Warm%, Hot%]: {state}")