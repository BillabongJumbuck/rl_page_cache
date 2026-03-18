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
        # 0 = 关闭 (退化为传统 LRU), 1 (或更高级别的 flags) = 开启
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
    
    # 如果目录不存在，自动创建它
    os.makedirs(output_dir, exist_ok=True)
    
    # 生成时间戳，例如: 20260317_174530
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # 拼装文件名: cml_ycsb_c_20260317_174530.json
    filename = f"{policy}_{workload}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    # 顺手把实验的元数据也存进 JSON 里，方便以后画图溯源
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
# 3. 变色龙生命周期管理器
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
        
        # 恢复 1：加回 -w 参数，并将 stdout 重定向到 DEVNULL 避免刷屏
        subprocess.Popen(
            ["sudo", "./chameleon.out", "-c", cgroup_path], 
            cwd=self.bpf_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        sleep(2)

        # 恢复 2：解封 Agent，并配置好环境变量
        env = os.environ.copy()
        env["CHAMELEON_CSV_LOG"] = f"logs/ycsb_{self.workload_name}_decisions.csv"
        # 告诉 AI 真正的 LevelDB 数据在哪个文件夹！
        env["CHAMELEON_CGROUP_PATH"] = cgroup_path
        
        # 开启人类专家作弊模式（1 = 开启专家写死参数，0 = 开启 PPO AI 推理）
        # 既然 AI 丢了 .pkl 发挥失常，我们先用 1 (专家模式) 来验证 BPF 极速版的真实威力！
        env["CHAMELEON_EXPERT_MODE"] = "0" 
        
        self.log_handle = open(f"{self.agent_dir}/logs/daemon_ycsb_{self.workload_name}.log", "w")
        subprocess.Popen(
            ["uv", "run", "eval/inference_daemon.py"], 
            cwd=self.agent_dir, stdout=self.log_handle, stderr=self.log_handle, env=env
        )
        sleep(3)

    def stop(self):
        log.info("🛑 正在切断变色龙神经连接...")
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
    # 【更新】：支持 cml, lru, mg 三大核心策略
    parser.add_argument("-p", "--policy", type=str, choices=["cml", "lru", "mg"], required=True, 
                        help="Test policy: cml (变色龙), lru (传统 Linux LRU), mg (原生 MGLRU)")
    args = parser.parse_args()

    ORIG_DB = "/home/messidor/rl_page_cache/leveldb_data"
    TEMP_DB = "/home/messidor/rl_page_cache/leveldb_data_temp"
    CGROUP_NAME = f"eval_{args.policy}"
    YCSB_BIN_DIR = "/home/messidor/cache_ext/My-YCSB/build"
    YCSB_BIN = os.path.join(YCSB_BIN_DIR, "run_leveldb")
    YAML_PATH = f"/home/messidor/rl_page_cache/agent/workloads/ycsb_configs/ycsb_{args.workload}.yaml"

    # 记录原始的 MGLRU 状态并确保护理期间能恢复
    orig_mglru = get_mglru_state()
    CLEANUP_TASKS.append(lambda: restore_mglru_state(orig_mglru))

    # 脏页参数控制
    set_sysctl("vm.dirty_background_ratio", 1)
    set_sysctl("vm.dirty_ratio", 30)
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_background_ratio", 10))
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_ratio", 20))

    try:
        clone_database(ORIG_DB, TEMP_DB)
        reset_env()
        recreate_cgroup(CGROUP_NAME, 2 * GiB)

        # 核心：根据策略动态切换内核的内存管理底层逻辑
        if args.policy == "mg":
            set_mglru_state(True)   # 开启 MGLRU
        else:
            set_mglru_state(False)  # lru 和 cml 都需要关闭 MGLRU，退化为传统双链表

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
        log.info("🧹 打扫战场...")
        for task in CLEANUP_TASKS:
            try: task()
            except Exception as e: log.error(f"清理失败: {e}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()