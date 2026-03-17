#!/usr/bin/env fish
# 变色龙通用评测发射器 (V3 架构版)

# 注册终极清理钩子：无视任何意外，强行打扫战场
function cleanup_battlefield --on-event fish_exit --on-signal SIGINT
    echo -e "\n============================================"
    echo "  [清理] 正在切断负载源、大脑与底盘探针..."
    echo "============================================"
    sudo pkill -9 -f fio 2>/dev/null
    sudo pkill -9 -f inference_daemon.py 2>/dev/null
    sudo pkill -9 chameleon 2>/dev/null
    sudo swapon -a 2>/dev/null
    echo "评测完成！"
    exit 0
end

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

cd ~/rl_page_cache/agent

echo "============================================"
echo "  [1/4] 清理战场与 Cgroup 隔离舱准备"
echo "============================================"
sudo -v
sudo swapoff -a
sudo pkill -9 chameleon 2>/dev/null

sudo mkdir -p $CGROUP_DIR
echo "2G" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo "0" | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null

echo "============================================"
echo "  [2/4] 唤醒底盘探针与 AI 决策大脑"
echo "============================================"
cd $BPF_DIR
# 将输出重定向到黑洞，保持纯净后台
sudo ./chameleon.out -w /tmp/bpf_test -c $CGROUP_DIR > /dev/null 2>&1 &
cd - > /dev/null
sleep 3

# 设置供 AI 守护进程读取的环境变量
set -x CHAMELEON_WATCH_DIR /tmp/bpf_test
set -x CHAMELEON_EXPERT_MODE 0

# 启动脱钩的 AI 守护进程，并在后台静默运行
uv run eval/inference_daemon.py > logs/daemon_stdout.log 2>&1 &
set AI_PID (jobs -p | tail -n 1)
echo ">>> AI 大脑已启动 (PID: $AI_PID)，正在后台监控环境..."

echo "============================================"
echo "  [3/4] 注入目标负载: $WORKLOAD_SCRIPT"
echo "============================================"
# 清空缓存池，确保公平
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

# 将这个极其干净的子 shell 绑定进 Cgroup，并执行你传入的负载
sudo sh -c "echo \$\$ > $CGROUP_DIR/cgroup.procs && exec $WORKLOAD_SCRIPT"

echo "============================================"
echo "  [4/4] 负载结束，触发自动回收"
echo "============================================"
# 脚本自然结束时，顶部的 fish_exit 钩子会自动触发完整的战场清理