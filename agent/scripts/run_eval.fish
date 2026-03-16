#!/usr/bin/env fish
# 变色龙通用评测发射器

set WORKLOAD_SCRIPT $argv[1]

if test -z "$WORKLOAD_SCRIPT"
    echo "用法错误！请提供负载脚本。"
    echo "示例: ./run_eval.fish workloads/ycsb_c.fish"
    exit 1
end

if not test -x "$WORKLOAD_SCRIPT"
    echo "错误: 负载脚本 $WORKLOAD_SCRIPT 不存在或没有执行权限！"
    exit 1
end

set CGROUP_DIR "/sys/fs/cgroup/chameleon_eval"
set BPF_DIR ~/rl_page_cache/bpf

echo "============================================"
echo "  [1/4] 清理战场与 Cgroup 隔离舱准备"
echo "============================================"
sudo -v
sudo swapoff -a
sudo pkill -9 cache_ext_reuse 2>/dev/null
sudo pkill -9 chameleon 2>/dev/null

sudo mkdir -p $CGROUP_DIR
echo "2G" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo "0" | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null

echo "============================================"
echo "  [2/4] 唤醒底盘探针与 AI 决策大脑"
echo "============================================"
cd $BPF_DIR
sudo ./cache_ext_reuse.out -w /tmp/bpf_test &
sudo ./chameleon.out -w /tmp/bpf_test -c $CGROUP_DIR &
cd - > /dev/null
sleep 3

# 启动脱钩的 AI 守护进程，并在后台静默运行
uv run eval/inference_daemon.py > eval/daemon_stdout.log 2>&1 &
set AI_PID (jobs -p | tail -n 1)
echo ">>> AI 大脑已启动 (PID: $AI_PID)，正在监控环境..."

echo "============================================"
echo "  [3/4] 注入目标负载: $WORKLOAD_SCRIPT"
echo "============================================"
# 清空缓存池，确保公平
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

# 将这个极其干净的子 shell 绑定进 Cgroup，并执行你传入的负载
sudo sh -c "echo \$\$ > $CGROUP_DIR/cgroup.procs && exec $WORKLOAD_SCRIPT"

echo "============================================"
echo "  [4/4] 负载结束，回收进程"
echo "============================================"
kill $AI_PID 2>/dev/null
sudo pkill -9 cache_ext_reuse 2>/dev/null
sudo pkill -9 chameleon 2>/dev/null
sudo swapon -a

echo "评测完成！AI 的完整思考记录已保存至 ai_decisions_log.csv"