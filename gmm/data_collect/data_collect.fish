#!/usr/bin/env fish

set ROOT_DIR "/home/messidor/rl_page_cache/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set CML_BIN "/home/messidor/rl_page_cache/bpf/chameleon.out"
set COLLECTOR_BIN "./data_collector.out"
set CACHE_MB 800 # 触发软回收的水位
set MAX_MB 1024   # 绝对内存上限 (OOM界限)

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

# 🌟 关键修复：写入 cgroup v2 内存限制，触发内核回收机制
echo "[System] Setting cgroup v2 memory limits..."
echo "1024M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo "800M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

# 3. 关闭MGLRU 
echo "[System] Disabling MGLRU (Falling back to Classic Active/Inactive LRU)..." 
echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1

# 4. 启动 eBPF 探针
echo "Starting Chameleon probe..."
# 🌟 关键修复：加入 & 放入后台，并安全记录 PID
sudo $CML_BIN -c $CGROUP_DIR > $ROOT_DIR/log/chameleon.log 2>&1 &
set CML_PID $last_pid
sleep 2

# 5. 启动FIO负载，加入cgroup
echo "Starting FIO workload..."
# 🌟 关键修复：原生的 cgroup v2 挂载方式，避免 cgexec 兼容性问题
./fio_loop.fish > $ROOT_DIR/log/fio.log 2>&1 &
set FIO_PID $last_pid
echo $FIO_PID | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null

# 6. 启动collector
echo "Starting data collector..."
# 🌟 关键修复：移除未实现的命令行参数
sudo $COLLECTOR_BIN > $ROOT_DIR/log/collector.log 2>&1 &
set COLLECTOR_PID $last_pid

echo "✅ Data collection started. Press Ctrl+C to stop."

# 7. 挂起主线程，保持存活
while true
    sleep 1
end

# 8. 清理环境 (fish_exit 钩子，当接收到 Ctrl+C 或脚本退出时自动触发)
function handle_exit --on-signal SIGINT --on-signal SIGTERM
    if set -q _CLEANUP_CALLED
        return
    end
    set -g _CLEANUP_CALLED 1

    echo -e "\n\n[🛡️ Cleanup] 收到中断信号！正在执行核爆级清理..."

    # 1. 釜底抽薪：先杀循环脚本，再杀 FIO 本体，彻底切断 I/O 源头
    echo " ├─ 正在强杀负载发生器..."
    sudo pkill -9 -f "fio_loop.fish" 2>/dev/null
    sudo pkill -9 fio 2>/dev/null

    # 2. 优雅通知 eBPF 和 Collector 进行资源落盘和 eBPF Map 卸载
    echo " ├─ 正在通知数据面和收集器退出..."
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sudo pkill -SIGINT -f "data_collector.out" 2>/dev/null

    # 关键：给 C++ 里面的 bpf_map__unpin 和 fclose 一点点时间落盘
    sleep 1.5 

    # 3. 绝不手软：对可能卡死的探针进行补刀
    sudo pkill -9 -f "chameleon.out" 2>/dev/null
    sudo pkill -9 -f "data_collector.out" 2>/dev/null

    # 4. 清理 Cgroup：确保没有僵尸进程残留
    if test -d $CGROUP_DIR
        echo " ├─ 正在销毁 Cgroup..."
        sudo rmdir $CGROUP_DIR 2>/dev/null
    end

    echo " └─ ✅ 环境已彻底净化，安全退出。"
    exit 0
end