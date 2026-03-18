#!/usr/bin/env python3
# bench_sqlite.py - 变色龙 AI 的 SQLite 穿透评测脚本
import argparse
import logging
import os
import re
import subprocess
import sys
from contextlib import suppress
from time import sleep
import json
from datetime import datetime

log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []

# ==========================================
# 1. 核心系统工具箱 (复用已有稳定逻辑)
# ==========================================
def run(cmd, **kwargs):
    kwargs.setdefault("check", True)
    log.info(f"执行命令: {' '.join(cmd)}")
    return subprocess.run(cmd, **kwargs)

def recreate_cgroup(cgroup, limit_in_bytes):
    with suppress(subprocess.CalledProcessError):
        run(["sudo", "cgdelete", f"memory:{cgroup}"])
    run(["sudo", "cgcreate", "-g", f"memory:{cgroup}"])
    run(["sudo", "sh", "-c", f"echo {limit_in_bytes} > /sys/fs/cgroup/{cgroup}/memory.max"])
    log.info(f"🎯 物理牢笼 {cgroup} 构建完毕, 内存上限: {limit_in_bytes / GiB:.2f} GiB")

def reset_env():
    run(["sudo", "sync"])
    run(["sudo", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"])
    run(["sudo", "swapoff", "-a"])

def clone_database(db_dir: str, temp_db_dir: str):
    if not db_dir.endswith("/"): db_dir += "/"
    log.info("📦 正在极速克隆 SQLite 靶场数据 (包含 db, wal, shm)...")
    run(["rsync", "-avpl", "--delete", db_dir, temp_db_dir], stdout=subprocess.DEVNULL)

def get_mglru_state():
    mglru_path = "/sys/kernel/mm/lru_gen/enabled"
    if os.path.exists(mglru_path):
        res = subprocess.run(["sudo", "cat", mglru_path], capture_output=True, text=True)
        return res.stdout.strip()
    return None

def set_mglru_state(enable: bool):
    mglru_path = "/sys/kernel/mm/lru_gen/enabled"
    if os.path.exists(mglru_path):
        val = "1" if enable else "0" 
        run(["sudo", "sh", "-c", f"echo {val} > {mglru_path}"])
        state_str = "🟢 MGLRU (Multi-Gen LRU) 已激活" if enable else "🔴 传统双链表 LRU 已激活"
        log.info(f"⚙️ 内核淘汰机制已切换: {state_str}")

def restore_mglru_state(orig_state):
    if orig_state is not None:
        mglru_path = "/sys/kernel/mm/lru_gen/enabled"
        run(["sudo", "sh", "-c", f"echo '{orig_state}' > {mglru_path}"])

# ==========================================
# 2. YCSB-C 结果解析器 (针对 C++ 版本的输出格式)
# ==========================================
def parse_sqlite_bench_results(stdout: str) -> dict:
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Throughput(ops/sec)" in line:
            results["total_throughput"] = float(line.split(",")[-1].strip())
        elif "[READ], AverageLatency(us)" in line:
            results["read_latency_avg_us"] = float(line.split(",")[-1].strip())
        # 新增：精准捕获 YCSB-C 的 P99 读延迟
        elif "[READ], 99thPercentileLatency(us)" in line:
            results["read_latency_p99_us"] = float(line.split(",")[-1].strip())
        # 新增：顺手捕获 P99 写延迟（如果有）
        elif "[UPDATE], 99thPercentileLatency(us)" in line:
            results["update_latency_p99_us"] = float(line.split(",")[-1].strip())
    return results

def save_results(results: dict, policy: str, workload: str):
    output_dir = "/home/messidor/rl_page_cache/agent/eval/output_sqlite"
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join(output_dir, f"{policy}_{workload}_{timestamp}.json")
    
    export_data = {
        "metadata": {"policy": policy, "workload": workload, "db": "sqlite", "timestamp": timestamp},
        "metrics": results
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=4)
    log.info(f"💾 战报已永久归档至: {filepath}")

# ==========================================
# 3. 变色龙生命周期管理器
# ==========================================
class ChameleonPolicy:
    def __init__(self, cgroup_name, temp_db_dir, workload_name):
        self.cgroup_name = cgroup_name
        self.temp_db_dir = temp_db_dir
        self.workload_name = workload_name
        self.bpf_dir = "/home/messidor/rl_page_cache/bpf"
        self.agent_dir = "/home/messidor/rl_page_cache/agent"
        self.log_handle = None

    def start(self):
        log.info("🦎 正在唤醒变色龙 eBPF 探针与 PPO 大脑...")
        cgroup_path = f"/sys/fs/cgroup/{self.cgroup_name}"
        
        subprocess.Popen(
            ["sudo", "./chameleon.out", "-c", cgroup_path], 
            cwd=self.bpf_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        sleep(2)

        env = os.environ.copy()
        env["CHAMELEON_CSV_LOG"] = f"logs/sqlite_{self.workload_name}_decisions.csv"
        env["CHAMELEON_CGROUP_PATH"] = cgroup_path
        env["CHAMELEON_EXPERT_MODE"] = "0" 
        
        self.log_handle = open(f"{self.agent_dir}/logs/daemon_sqlite_{self.workload_name}.log", "w")
        subprocess.Popen(
            ["uv", "run", "eval/inference_daemon.py"], 
            cwd=self.agent_dir, stdout=self.log_handle, stderr=self.log_handle, env=env
        )
        sleep(3)

    def stop(self):
        log.info("🛑 正在切断变色龙神经连接...")
        run(["sudo", "pkill", "-9", "-f", "inference_daemon.py"], check=False)
        run(["sudo", "pkill", "-9", "chameleon"], check=False)
        if self.log_handle: self.log_handle.close()

# ==========================================
# 4. 主控战场逻辑
# ==========================================
def main():
    parser = argparse.ArgumentParser("Chameleon SQLite YCSB Evaluator")
    parser.add_argument("-w", "--workload", type=str, required=True, help="Workload name, e.g., 'workloadc'")
    parser.add_argument("-p", "--policy", type=str, choices=["cml", "lru", "mg"], required=True)
    args = parser.parse_args()

    ORIG_DB_DIR = "/home/messidor/rl_page_cache/sqlite_data"
    TEMP_DB_DIR = "/home/messidor/rl_page_cache/sqlite_data_temp"
    CGROUP_NAME = f"eval_sqlite_{args.policy}"
    
    # 指向你刚才编译的 YCSB-C 的可执行文件
    YCSB_BIN = "/home/messidor/r/YCSB-C/ycsb" 
    # YCSB-C 自带的工作负载配置文件路径
    WORKLOAD_FILE = f"/home/messidor/r/YCSB-C/workloads/{args.workload}"

    orig_mglru = get_mglru_state()
    CLEANUP_TASKS.append(lambda: restore_mglru_state(orig_mglru))

    try:
        clone_database(ORIG_DB_DIR, TEMP_DB_DIR)
        reset_env()
        # 对于 SQLite，由于是直接操作文件，Cgroup 给 1GB 甚至 500MB 就能造成极强的 Page Cache 压力
        recreate_cgroup(CGROUP_NAME, 1 * GiB)

        if args.policy == "mg": set_mglru_state(True)
        else: set_mglru_state(False)

        chameleon = None
        if args.policy == "cml":
            chameleon = ChameleonPolicy(CGROUP_NAME, TEMP_DB_DIR, args.workload)
            chameleon.start()
            CLEANUP_TASKS.append(lambda: chameleon.stop())

        # 核心：YCSB-C 运行 SQLite 的专属命令
        # -p sqlite.cachesize=100 是神来之笔：强迫 SQLite 内部只缓存 100 个页，剩余 I/O 全部砸向内核 Page Cache！
        db_file = os.path.join(TEMP_DB_DIR, "ycsb.db")
        cmd = [
            "sudo", "cgexec", "-g", f"memory:{CGROUP_NAME}", 
            YCSB_BIN, "-run", "-db", "sqlite", 
            "-P", WORKLOAD_FILE, 
            "-p", f"sqlite.dbfile={db_file}",
            "-p", "sqlite.cachesize=100" 
        ]
        
        log.info(f"🚀 发射 SQLite YCSB 负载: {args.workload} (策略: {args.policy.upper()})")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        full_output = []
        for line in process.stdout:
            sys.stdout.write(line) 
            full_output.append(line)
        process.wait()

        results = parse_sqlite_bench_results("".join(full_output))
        print("\n" + "="*50)
        print(f"📊 【最终战报】 策略: {args.policy.upper()} | DB: SQLite | 负载: {args.workload.upper()}")
        print("="*50)
        print(f"  👉 总吞吐量 (Ops/sec): {results.get('total_throughput', 0)}")
        print(f"  👉 读延迟 (P99):      {results.get('read_latency_p99_us', 0):.2f} us")
        print("="*50)

        save_results(results, args.policy, args.workload)

    finally:
        log.info("🧹 打扫战场...")
        for task in CLEANUP_TASKS:
            try: task()
            except Exception as e: log.error(f"清理失败: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()