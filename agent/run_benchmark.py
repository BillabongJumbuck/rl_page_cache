import os
import subprocess
import json
import time
import signal

# ==========================================
# 评测核心参数配置
# ==========================================
TEST_DIR = "/tmp/bpf_test"
TEST_FILE = os.path.join(TEST_DIR, "test.dat")
FILE_SIZE = "5G"

# Cgroup 内存限制：必须小于文件大小，强行制造驱逐和 Thrashing！
CGROUP_MEMORY_LIMIT = "2G" 
FIO_RUNTIME = 60  # 每个阶段测试 60 秒

def run_cmd(cmd: str, check=True):
    print(f"[CMD] {cmd}")
    subprocess.run(cmd, shell=True, check=check)

def drop_page_cache():
    print(">>> 正在清空 Linux 原生 Page Cache...")
    run_cmd("sync")
    run_cmd("echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null")
    time.sleep(2)  # 给内核一点时间回收内存

def prepare_test_file():
    os.makedirs(TEST_DIR, exist_ok=True)
    if not os.path.exists(TEST_FILE):
        print(f">>> 正在锻造 {FILE_SIZE} 测试基底文件...")
        run_cmd(f"fio --name=init --filename={TEST_FILE} --rw=write --bs=1M --size={FILE_SIZE} --numjobs=1 > /dev/null")
    else:
        print(f">>> 测试文件 {TEST_FILE} 已存在，跳过创建。")

def get_bpf_map_id(target_name: str) -> int | None:
    """动态获取 Map ID，解决内核 15 字符截断问题"""
    truncated_name = target_name[:15]
    try:
        res = subprocess.run(["sudo", "bpftool", "map", "list", "-j"], capture_output=True, text=True, check=True)
        maps = json.loads(res.stdout)
        for m in maps:
            map_name = m.get("name", "")
            if map_name in [target_name, truncated_name]:
                return m.get("id")
    except Exception as e:
        print(f"警告: 查找 Map '{target_name}' 失败: {e}")
    return None

def reset_chameleon_policy():
    """将变色龙策略重置为全 0 (纯 FIFO / 原生模式)"""
    map_id = get_bpf_map_id("cml_params_map")
    if map_id:
        print(f">>> 重置内核策略 (Map ID: {map_id})...")
        # 变色龙参数有 5 个 __u32 变量，总计 20 字节，全部写 0
        zero_hex = " ".join(["00"] * 20)
        run_cmd(f"sudo bpftool map update id {map_id} key hex 00 00 00 00 value hex {zero_hex}", check=False)
    else:
        print(">>> 未找到 chameleon_params_map，跳过重置 (请确保后台的 eBPF 探针程序已运行)。")

def run_fio_benchmark(name: str) -> float:
    """在受限的 Cgroup 中运行 FIO，返回 IOPS"""
    fio_cmd = (
        f"sudo systemd-run --scope -q "
        f"-p MemoryMax={CGROUP_MEMORY_LIMIT} -p MemorySwapMax=0 "
        f"fio --name={name} --filename={TEST_FILE} "
        f"--rw=randread --random_distribution=zipf:1.2 " 
        f"--bs=4k --size={FILE_SIZE} --runtime={FIO_RUNTIME} --time_based "
        f"--direct=0 "  # 走 Page Cache
        f"--output-format=json"
    )
    
    print(f"开始执行 FIO 压测 [{name}]，持续 {FIO_RUNTIME} 秒，请耐心等待...")
    result = subprocess.run(fio_cmd, shell=True, capture_output=True, text=True)
    
    try:
        data = json.loads(result.stdout)
        iops = data['jobs'][0]['read']['iops']
        bandwidth = data['jobs'][0]['read']['bw_bytes'] / (1024 * 1024)
        print(f"[{name}] 测试完成 -> IOPS: {iops:.2f}, 吞吐量: {bandwidth:.2f} MiB/s")
        return iops
    except Exception as e:
        print(f"解析 FIO 输出失败: {e}")
        # print("FIO 错误输出:", result.stderr) # 调试时可取消注释
        return 0.0

def main():
    print("============================================")
    print("  AI for OS 终极基准测试 (Native LRU vs Chameleon)")
    print("============================================")
    
    # 1. 提权与环境准备
    run_cmd("sudo -v")
    # 物理封锁：关闭系统全局 Swap，逼迫 Linux 进行页面驱逐
    run_cmd("sudo swapoff -a", check=False)
    prepare_test_file()

    # ==========================================
    # 阶段 1：原生 Linux Active/Inactive LRU 跑分
    # ==========================================
    print("\n" + "="*40)
    print("  [Phase 1] 评测原生 Linux (Baseline)")
    print("="*40)
    reset_chameleon_policy()
    drop_page_cache()
    
    baseline_iops = run_fio_benchmark("baseline_lru")

    # ==========================================
    # 阶段 2：AI 驱动 Chameleon 跑分
    # ==========================================
    print("\n" + "="*40)
    print("  [Phase 2] 评测 AI 变色龙 (Chameleon)")
    print("="*40)
    reset_chameleon_policy() # 启动前清零，让 AI 自己接管
    drop_page_cache()
    
    print(">>> 唤醒 AI 大脑守护进程...")
    # preexec_fn=os.setsid 确保 AI 进程及其派生的子进程都在同一个组，方便结束时一网打尽
    ai_process = subprocess.Popen(
        ["uv", "run", "evaluate.py"], 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid 
    )
    
    # 给 AI 5 秒钟启动 DAMON 和雷达的时间
    time.sleep(5)
    
    ai_iops = run_fio_benchmark("ai_chameleon")
    
    print(">>> 压测结束，正在回收 AI 大脑...")
    try:
        # 发送 SIGTERM 优雅地结束整个进程组
        os.killpg(os.getpgid(ai_process.pid), signal.SIGTERM)
    except Exception as e:
        print(f"清理 AI 进程时遇到小问题: {e}")
        ai_process.terminate()

    # ==========================================
    # 阶段 3：宣判时刻
    # ==========================================
    print("\n" + "="*40)
    print("  🏆 最终评测结果对比 🏆")
    print("="*40)
    print(f" 限制内存 : {CGROUP_MEMORY_LIMIT}")
    print(f" 压测负载 : {FILE_SIZE} Zipfian RandRead")
    print("-" * 40)
    print(f" Native Linux LRU IOPS : {baseline_iops:.2f}")
    print(f" AI Chameleon IOPS     : {ai_iops:.2f}")
    print("-" * 40)
    
    if baseline_iops > 0:
        improvement = ((ai_iops - baseline_iops) / baseline_iops) * 100
        print(f" 相对性能提升 : {improvement:+.2f}%")
        
        if improvement > 0:
            print("\n结论: 你的 AI 成功超越了原生 Linux 的调度策略！")
        else:
            print("\n结论: 模型还需要更多的数据喂养 (建议加大 train.py 的训练步数)。")
            
    # 恢复系统的 swap
    run_cmd("sudo swapon -a", check=False)

if __name__ == "__main__":
    main()