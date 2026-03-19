#!/usr/bin/env python3
# bench_leveldb.py - 变色龙 AI 的 LevelDB 评测脚本，支持 cml, lru, mg 三大核心策略
import argparse
import logging
import os
import re
import subprocess
import sys
from contextlib import contextmanager, suppress
from time import sleep
from ruamel.yaml import YAML
import json
from datetime import datetime

log = logging.getLogger(__name__)
GiB = 2**30
CLEANUP_TASKS = []

# ==========================================
# 1. 核心系统工具箱
# ==========================================
def run(cmd, **kwargs):
    kwargs.setdefault("check", True)
    log.info(f"执行命令: {' '.join(cmd)}")
    return subprocess.run(cmd, **kwargs)

@contextmanager
def edit_yaml_file(file_path):
    yaml = YAML()
    yaml.preserve_quotes = True
    with open(file_path, "r") as file:
        data = yaml.load(file)
    yield data
    with open(file_path, "w") as file:
        yaml.dump(data, file)

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

def set_sysctl(key: str, value):
    run(["sudo", "sysctl", "-w", f"{key}={value}"])

def clone_database(db_dir: str, temp_db_dir: str):
    if not db_dir.endswith("/"): db_dir += "/"
    log.info("📦 正在极速克隆靶场数据 (rsync)...")
    run(["rsync", "-avpl", "--delete", db_dir, temp_db_dir], stdout=subprocess.DEVNULL)

# ----------------- 新增：MGLRU 控制台 -----------------
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
        state_str = "🟢 MGLRU (Multi-Gen LRU) 已激活" if enable else "🔴 传统双链表 LRU (Active/Inactive) 已激活"
        log.info(f"⚙️ 内核淘汰机制已切换: {state_str}")
    else:
        log.warning("⚠️ 当前内核找不到 MGLRU 控制接口，可能内核版本较老 (< 6.1)")

def restore_mglru_state(orig_state):
    if orig_state is not None:
        mglru_path = "/sys/kernel/mm/lru_gen/enabled"
        run(["sudo", "sh", "-c", f"echo '{orig_state}' > {mglru_path}"])
        log.info(f"⚙️ MGLRU 状态已恢复为原始值: {orig_state}")

# ==========================================
# 2. YCSB 结果解析器
# ==========================================
def parse_leveldb_bench_results(stdout: str) -> dict:
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "overall: UPDATE throughput" in line:
            matches = re.findall(r"(\w+ throughput) (\d+\.\d+) ops/sec", line)
            for match in matches:
                if "READ throughput" in match[0]: results["read_throughput"] = float(match[1])
                elif "UPDATE throughput" in match[0]: results["update_throughput"] = float(match[1])
                elif "total throughput" in match[0]: results["total_throughput"] = float(match[1])
        elif "overall: UPDATE average latency" in line:
            matches = re.findall(r"(\w+ \w+ latency) (\d+\.\d+) ns", line)
            for match in matches:
                if "READ average latency" in match[0]: results["read_latency_avg_ns"] = float(match[1])
                elif "READ p99 latency" in match[0]: results["read_latency_p99_ns"] = float(match[1])
    return results

def save_results(results: dict, policy: str, workload: str):
    output_dir = "/home/messidor/rl_page_cache/agent/eval/output"
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{policy}_{workload}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    export_data = {
        "metadata": {
            "policy": policy,
            "workload": workload,
            "timestamp": timestamp
        },
        "metrics": results
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=4)
    log.info(f"💾 战报已永久归档至: {filepath}")

# ==========================================
# 3. 变色龙生命周期管理器 (绝对安全版)
# ==========================================
class ChameleonPolicy:
    def __init__(self, cgroup_name, temp_db, workload_name):
        self.cgroup_name = cgroup_name
        self.temp_db = temp_db
        self.workload_name = workload_name
        self.bpf_dir = "/home/messidor/rl_page_cache/bpf"
        self.agent_dir = "/home/messidor/rl_page_cache/agent"
        self.log_handle = None

    def start(self):
        log.info("🦎 正在唤醒变色龙 eBPF 探针与 PPO 大脑...")
        cgroup_path = f"/sys/fs/cgroup/{self.cgroup_name}"
        
        subprocess.Popen(
            ["sudo", "./chameleon.out", "-c", cgroup_path], 
            cwd=self.bpf_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        sleep(2)

        env = os.environ.copy()
        env["CHAMELEON_CSV_LOG"] = f"logs/ycsb_{self.workload_name}_decisions.csv"
        env["CHAMELEON_CGROUP_PATH"] = cgroup_path
        env["CHAMELEON_EXPERT_MODE"] = "1" 
        
        self.log_handle = open(f"{self.agent_dir}/logs/daemon_ycsb_{self.workload_name}.log", "w")
        subprocess.Popen(
            ["uv", "run", "eval/inference_daemon.py"], 
            cwd=self.agent_dir, stdout=self.log_handle, stderr=self.log_handle, env=env
        )
        sleep(3)

    def stop(self):
        # 🛡️【修复】：严格遵循安全退场仪式，防止内核崩溃！
        log.info("🛑 正在执行安全退场仪式，切断变色龙神经连接...")
        
        # 第一步：杀掉可能还在产生缺页的 YCSB 进程
        run(["sudo", "pkill", "-9", "-f", "run_leveldb"], check=False)
        sleep(2)
        
        # 第二步：核爆清空所有双向链表 (此时 BPF 探针依然存活，绝对安全)
        log.info("  [清理] 正在清空残留内存 (Drop Caches)...")
        run(["sudo", "sync"])
        run(["sudo", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"])
        sleep(2)
        
        # 第三步：拔掉探针
        log.info("  [清理] 正在安全卸载探针与大脑...")
        run(["sudo", "pkill", "-9", "-f", "inference_daemon.py"], check=False)
        run(["sudo", "pkill", "-9", "chameleon"], check=False)
        if self.log_handle:
            self.log_handle.close()

# ==========================================
# 4. 主控战场逻辑
# ==========================================
def main():
    parser = argparse.ArgumentParser("Chameleon YCSB Evaluator")
    parser.add_argument("-w", "--workload", type=str, required=True, help="Workload name, e.g., 'ycsb_c'")
    parser.add_argument("-p", "--policy", type=str, choices=["cml", "lru", "mg"], required=True, 
                        help="Test policy: cml (变色龙), lru (传统 Linux LRU), mg (原生 MGLRU)")
    args = parser.parse_args()

    ORIG_DB = "/home/messidor/rl_page_cache/leveldb_data"
    TEMP_DB = "/home/messidor/rl_page_cache/leveldb_data_temp"
    
    # 🛡️【修复】：强行加上 cache_ext 前缀
    if args.policy == "cml":
        CGROUP_NAME = f"cache_ext_eval_{args.policy}"
    else:
        # lru 和 mg 策略使用纯净名字，彻底避开内核学术框架的干扰！
        CGROUP_NAME = f"eval_{args.policy}"
    
    YCSB_BIN_DIR = "/home/messidor/cache_ext/My-YCSB/build"
    YCSB_BIN = os.path.join(YCSB_BIN_DIR, "run_leveldb")
    YAML_PATH = f"/home/messidor/rl_page_cache/agent/workloads/ycsb_configs/ycsb_{args.workload}.yaml"

    orig_mglru = get_mglru_state()
    CLEANUP_TASKS.append(lambda: restore_mglru_state(orig_mglru))

    set_sysctl("vm.dirty_background_ratio", 1)
    set_sysctl("vm.dirty_ratio", 30)
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_background_ratio", 10))
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_ratio", 20))

    try:
        clone_database(ORIG_DB, TEMP_DB)
        reset_env()
        recreate_cgroup(CGROUP_NAME, 2 * GiB)

        if args.policy == "mg":
            set_mglru_state(True) 
        else:
            set_mglru_state(False) 

        with edit_yaml_file(YAML_PATH) as config:
            config["leveldb"]["data_dir"] = TEMP_DB

        chameleon = None
        if args.policy == "cml":
            chameleon = ChameleonPolicy(CGROUP_NAME, TEMP_DB, args.workload)
            chameleon.start()
            CLEANUP_TASKS.append(lambda: chameleon.stop())

        cmd = ["sudo", "cgexec", "-g", f"memory:{CGROUP_NAME}", YCSB_BIN, YAML_PATH]
        log.info(f"🚀 发射 YCSB 负载: {args.workload} (策略: {args.policy.upper()})")
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        full_output = []
        for line in process.stdout:
            sys.stdout.write(line) 
            full_output.append(line)
        process.wait()

        if process.returncode != 0:
            raise Exception("YCSB 压测崩溃了！")

        results = parse_leveldb_bench_results("".join(full_output))
        print("\n" + "="*50)
        print(f"📊 【最终战报】 策略: {args.policy.upper()} | 负载: {args.workload.upper()}")
        print("="*50)
        print(f"  👉 总吞吐量 (Ops/sec): {results.get('total_throughput', 0)}")
        print(f"  👉 读延迟 (Avg):      {results.get('read_latency_avg_ns', 0) / 1000:.2f} us")
        print(f"  👉 读延迟 (P99):      {results.get('read_latency_p99_ns', 0) / 1000:.2f} us")
        print("="*50)

        save_results(results, args.policy, args.workload)

    finally:
        # Python 的 finally 天然保证即使遇到 Ctrl+C 也会执行清理！
        log.info("🧹 评测结束，打扫战场...")
        for task in CLEANUP_TASKS:
            try: task()
            except Exception as e: log.error(f"清理失败: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()