#!/usr/bin/env fish

set ROOT_DIR "/home/messidor/rl_page_cache"
set GMM_DIR "$ROOT_DIR/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set CML_BIN "$ROOT_DIR/bpf/chameleon.out"
set COLLECTOR_BIN "$GMM_DIR/data_collect/data_collector.out"
set TARGET_DIR "$HOME/linux"
set CSV_PATH "$GMM_DIR/eval/ripgrep/rg_eval_results.csv"

# 1. 清理系统缓存
echo "[Cleanup] Flushing system caches..."
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
sleep 2

# 2. 创建 cgroup 并设置内存限制
if test -d $CGROUP_DIR
    sudo rmdir $CGROUP_DIR 2>/dev/null
    sleep 1
end
sudo mkdir -p $CGROUP_DIR

echo "[System] Setting cgroup v2 memory limits (800MB)..."
echo "512M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo "400M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

# 3. 关闭 MGLRU 
echo "[System] Disabling MGLRU (Falling back to Classic Active/Inactive LRU)..." 
echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1

# 4. 启动 eBPF 探针
echo "🚀 Starting Chameleon probe..."
sudo $CML_BIN -c $CGROUP_DIR < /dev/null > $GMM_DIR/log/chameleon_collect.log 2>&1 &
sleep 2

# 5. 启动 Data Collector
echo "📡 Starting data collector..."
sudo $COLLECTOR_BIN $CSV_PATH < /dev/null > $GMM_DIR/log/collector_rg.log 2>&1 &
sleep 1

# 6. 启动 ripgrep 负载 (放入 Cgroup 并循环扫表)
echo "🌪️ Starting ripgrep workload (Looping)..."
# 使用 bash 包装：精准入笼 -> 绑核 0 -> 死循环扫描
bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && while true; do taskset -c 0 rg -j 1 'EXPORT_SYMBOL_GPL' $TARGET_DIR > /dev/null; done" &
set RG_BASH_PID $last_pid

echo "✅ Data collection is LIVE. Press [Ctrl+C] after ~30 seconds to stop and save data."

# 7. 清理环境 (加入 fish_exit 钩子，不仅响应 Ctrl+C，也能在异常退出时兜底)
function handle_exit --on-signal SIGINT --on-signal SIGTERM --on-event fish_exit
    if set -q _CLEANUP_CALLED
        return
    end
    set -g _CLEANUP_CALLED 1

    echo -e "\n\n[🛡️ Cleanup] 收到退出信号！正在执行核爆级清理..."

    # 1. 釜底抽薪：强杀 bash 循环和 rg 本尊
    echo "  ├─ 正在强杀 ripgrep 负载..."
    sudo pkill -9 -P $RG_BASH_PID 2>/dev/null
    sudo pkill -9 -f "rg -j 1" 2>/dev/null

    # 2. 优雅通知 eBPF 和 Collector 进行资源落盘和 eBPF Map 卸载
    echo "  ├─ 正在通知探针和收集器落盘退出..."
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sudo pkill -SIGINT -f "data_collector.out" 2>/dev/null

    # 关键：给 bpf_map__unpin 和文件 fflush 一点点时间
    sleep 1.5 

    # 3. 绝不手软：对可能卡死的探针进行补刀
    sudo pkill -9 -f "chameleon.out" 2>/dev/null
    sudo pkill -9 -f "data_collector.out" 2>/dev/null
    
    # 彻底超度幽灵 Map
    sudo rm -f /sys/fs/bpf/cml_feature_events 2>/dev/null
    sudo rm -f /sys/fs/bpf/cml_params_map 2>/dev/null

    # 4. 清理 Cgroup
    if test -d $CGROUP_DIR
        echo "  ├─ 正在销毁 Cgroup..."
        sudo rmdir $CGROUP_DIR 2>/dev/null
    end

    echo "  └─ ✅ 环境已彻底净化，数据收集完毕！"
    exit 0
end

# 8. 挂起主线程，保持存活，等待用户 Ctrl+C
while true
    sleep 1
end