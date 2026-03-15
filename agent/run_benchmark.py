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
FIO_RUNTIME = 60  # 每个阶段测试 60 秒

# 统一的 Cgroup 配置，探针和压测都在这里！
CGROUP_DIR = "/sys/fs/cgroup/chameleon_bench"
CGROUP_MEMORY_LIMIT = "2G" 
BPF_DIR = os.path.expanduser("~/rl_page_cache/bpf")

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
    # 你的 C 代码里已经把名字改成了 cml_params_map，只有 14 个字符，不会被截断了！
    map_id = get_bpf_map_id("cml_params_map")
    if map_id:
        print(f">>> 重置内核策略 (Map ID: {map_id})...")
        # 变色龙参数有 5 个 __u32 变量，总计 20 字节，全部写 0
        zero_hex = " ".join(["00"] * 20)
        run_cmd(f"sudo bpftool map update id {map_id} key hex 00 00 00 00 value hex {zero_hex}", check=False)
    else:
        print(">>> 未找到 cml_params_map，跳过重置 (请确保后台的 eBPF 探针程序已运行)。")

def run_fio_benchmark(name: str) -> float:
    """在极其固定的变色龙 Cgroup 中运行 FIO，返回 IOPS"""
    # 抛弃 systemd-run，直接用底层 sh -c 把进程塞进 cgroup.procs
    fio_cmd = (
        f"sudo sh -c 'echo $$ > {CGROUP_DIR}/cgroup.procs && "
        f"exec fio --name={name} --filename={TEST_FILE} "
        f"--rw=randread --random_distribution=zipf:1.2 " 
        f"--bs=4k --size={FILE_SIZE} --runtime={FIO_RUNTIME} --time_based "
        f"--direct=0 "  # 走 Page Cache
        f"--output-format=json'"
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
        return 0.0

def main():
    print("============================================")
    print("  AI for OS 终极基准测试 (Native LRU vs Chameleon)")
    print("============================================")
    
    # 1. 提权与战场清理
    run_cmd("sudo -v")
    run_cmd("sudo swapoff -a", check=False)
    run_cmd("sudo pkill -9 cache_ext_reuse", check=False)
    run_cmd("sudo pkill -9 chameleon", check=False)

    # 2. 建立极其坚固的评测专用 Cgroup
    run_cmd(f"sudo mkdir -p {CGROUP_DIR}")
    run_cmd(f"echo {CGROUP_MEMORY_LIMIT} | sudo tee {CGROUP_DIR}/memory.max > /dev/null")
    run_cmd(f"echo 0 | sudo tee {CGROUP_DIR}/memory.swap.max > /dev/null")

    # 3. 唤醒 eBPF 变色龙双子星
    print("\n============================================")
    print("  唤醒 eBPF 变色龙双子星")
    print("============================================")
    # 注意这里必须进入 bpf 目录执行，否则它可能找不到编译好的 .o 或 .out 文件
    run_cmd(f"cd {BPF_DIR} && sudo ./cache_ext_reuse.out -w {TEST_DIR} &")
    run_cmd(f"cd {BPF_DIR} && sudo ./chameleon.out -w {TEST_DIR} -c {CGROUP_DIR} &")
    time.sleep(3) # 给内核验证器和 libbpf 挂载探针的时间

    # 4. 锻造基底文件
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
    reset_chameleon_policy() 
    drop_page_cache()
    
    print(">>> 唤醒 AI 大脑守护进程...")
    ai_process = subprocess.Popen(
        ["uv", "run", "evaluate.py"], 
        stdout=subprocess.DEVNULL, 
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid 
    )
    
    time.sleep(5)
    
    ai_iops = run_fio_benchmark("ai_chameleon")
    
    print(">>> 压测结束，正在回收 AI 大脑与底层探针...")
    try:
        os.killpg(os.getpgid(ai_process.pid), signal.SIGTERM)
    except Exception as e:
        ai_process.terminate()

    # 测试结束，卸载内核里的 eBPF 程序，保持系统洁净
    run_cmd("sudo pkill -9 cache_ext_reuse", check=False)
    run_cmd("sudo pkill -9 chameleon", check=False)

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
        
    run_cmd("sudo swapon -a", check=False)

if __name__ == "__main__":
    main()