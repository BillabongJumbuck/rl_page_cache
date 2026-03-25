#!/usr/bin/env fish

set ROOT_DIR "/home/messidor/rl_page_cache/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set CML_BIN "/home/messidor/rl_page_cache/bpf/chameleon.out"
set FIO_LOOP_BIN "/home/messidor/rl_page_cache/gmm/data_collect/fio_loop.fish"

# ==========================================
# 0. 绝对防御的清理钩子 (放在最前面，防止中途退出炸机)
# ==========================================
function handle_exit --on-signal SIGINT --on-signal SIGTERM
    if set -q _CLEANUP_CALLED
        return
    end
    set -g _CLEANUP_CALLED 1

    echo -e "\n\n[🛡️ Cleanup] 收到中断信号！正在清理后台环境..."
    
    # 强杀负载发生器
    sudo pkill -9 -f "fio_loop.fish" 2>/dev/null
    sudo pkill -9 fio 2>/dev/null

    # 优雅退出 eBPF 和 C 数据泵
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sudo pkill -SIGINT -f "data_streamer.out" 2>/dev/null
    sleep 1 

    # 补刀并销毁牢笼
    sudo pkill -9 -f "chameleon.out" 2>/dev/null
    sudo pkill -9 -f "data_streamer.out" 2>/dev/null
    if test -d $CGROUP_DIR
        sudo rmdir $CGROUP_DIR 2>/dev/null
    end
    echo " └─ ✅ 环境已彻底净化。"
    exit 0
end

# ==========================================
# 1. 环境初始化
# ==========================================
sudo -v
echo "[System] 🧹 初始化物理机环境 (清理缓存, 重置 Cgroup)..."
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
sleep 1

if test -d $CGROUP_DIR
    sudo rmdir $CGROUP_DIR 2>/dev/null
    sleep 1
end
sudo mkdir -p $CGROUP_DIR

echo "1024M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo "800M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null
echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1

# ==========================================
# 2. 启动 eBPF 底层探针 (丢入后台黑洞)
# ==========================================
echo "[eBPF] 🚀 启动内核探针..."
sudo $CML_BIN -c $CGROUP_DIR > /dev/null 2>&1 &
sleep 2 # 等待 Map 挂载

# ==========================================
# 3. 启动 FIO 靶场负载 (丢入后台黑洞)
# ==========================================
echo "[Workload] 💥 启动 FIO 靶场..."
$FIO_LOOP_BIN > /dev/null 2>&1 &
set FIO_PID $last_pid
echo $FIO_PID | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null

# ==========================================
# 4. 启动 AI Agent (前台运行，直击灵魂！)
# ==========================================
echo "======================================================="
echo "🧠 Agent 已接管控制权。正在实时输出推理日志..."
echo "按下 Ctrl+C 即可安全退出并清理所有后台进程。"
echo "======================================================="

# 直接在前台阻塞运行，让它的 print 输出占满你的屏幕
cd $ROOT_DIR
env PYTHONUNBUFFERED=1 /home/messidor/.local/bin/uv run inference/online_agent.py | tee $ROOT_DIR/log/agent.log