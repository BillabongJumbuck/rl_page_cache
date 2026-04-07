#!/usr/bin/env fish

# ==========================================
# 环境变量与路径配置
# ==========================================
set ROOT_DIR "/home/messidor/rl_page_cache"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set CML_BIN "$ROOT_DIR/bpf/chameleon.out"
set COLLECTOR_BIN "$ROOT_DIR/gmm/data_collect/data_collector.out"
set YCSB_BIN "/home/messidor/YCSB-cpp/ycsb"
set DB_PATH "/tmp/leveldb_ycsb"
set GOLDEN_PATH "/home/messidor/db_data"

set LOG_DIR "$ROOT_DIR/gmm/log/ycsb_collection"
set CSV_DIR "$ROOT_DIR/gmm/feature_data"

mkdir -p $LOG_DIR
mkdir -p $CSV_DIR

set WORKLOADS f
set RECORD_COUNT 5000000
set OP_COUNT 300000

# ==========================================
# 核爆级清理钩子
# ==========================================
function handle_exit --on-signal SIGINT --on-signal SIGTERM
    if set -q _CLEANUP_CALLED
        return
    end
    set -g _CLEANUP_CALLED 1

    echo -e "\n\n[🛡️ Cleanup] 收到中断信号或任务完成！正在执行核爆级清理..."

    echo " ├─ 正在强杀 YCSB 负载发生器..."
    sudo pkill -9 -f "ycsb" 2>/dev/null

    echo " ├─ 正在通知数据面和收集器退出..."
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sudo pkill -SIGINT -f "data_collector.out" 2>/dev/null

    # 给 C 端的 bpf_map__unpin 和 fclose 落盘时间
    sleep 1.5 

    echo " ├─ 正在对残留探针补刀..."
    sudo pkill -9 -f "chameleon.out" 2>/dev/null
    sudo pkill -9 -f "data_collector.out" 2>/dev/null

    if test -d $CGROUP_DIR
        # 将残留进程移回根 Cgroup 以便销毁
        if test -f $CGROUP_DIR/cgroup.procs
            for pid in (cat $CGROUP_DIR/cgroup.procs 2>/dev/null)
                echo $pid | sudo tee /sys/fs/cgroup/cgroup.procs > /dev/null 2>&1
            end
        end
        echo " ├─ 正在销毁 Cgroup 牢笼..."
        sudo rmdir $CGROUP_DIR 2>/dev/null
    end

    echo " └─ ✅ 环境已彻底净化，安全退出。"
    exit 0
end

# ==========================================
# 1. 基础环境初始化与 Cgroup 约束
# ==========================================
echo "[Cleanup] Flushing system caches..."
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
sleep 2

if test -d $CGROUP_DIR
    sudo rmdir $CGROUP_DIR 2>/dev/null
    sleep 1
end

echo "[System] Setting up Cgroup v2 memory limits (800M High / 1024M Max)..."
sudo mkdir -p $CGROUP_DIR
echo "800M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo "1024M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

echo "[System] Disabling MGLRU (Falling back to Classic Active/Inactive LRU)..." 
echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1

# ==========================================
# 2. 启动 eBPF 探针 (全局常驻)
# ==========================================
echo "🚀 Starting Chameleon Data Plane..."
sudo $CML_BIN -c $CGROUP_DIR > $LOG_DIR/chameleon.log 2>&1 &
set CML_PID $last_pid
sleep 2

# ==========================================
# 3. YCSB 负载特征采集流水线
# ==========================================
for wl in $WORKLOADS
    echo -e "\n======================================================="
    echo " 📡 正在采集 Workload [$wl] 的特征数据..."
    echo "======================================================="

    # 3.1 极速恢复数据库干净状态
    echo " ├─ [Data Restore] 正在从 Golden Copy 克隆数据库状态..."
    rsync -a --delete $GOLDEN_PATH/ $DB_PATH/
    sync

    # 3.2 启动专属的 Data Collector
    set CSV_FILE "$CSV_DIR/ycsb_workload_$wl.csv"
    echo " ├─ [Collector] 启动数据收集器，输出至: $CSV_FILE"
    # 使用参数传入 CSV 路径
    sudo $COLLECTOR_BIN $CSV_FILE > $LOG_DIR/collector_$wl.log 2>&1 &
    set COLLECTOR_PID $last_pid

    # 3.3 将 YCSB 放入 Cgroup 并全速运行
    echo " ├─ [YCSB] 正在执行 Workload $wl (绑定 CPU 0)..."
    
    # 🌟 关键技巧：使用 bash -c + exec 来确保只有 YCSB 进程本身被塞进 Cgroup，而不是整个 fish 脚本
    bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec taskset -c 0 $YCSB_BIN -run -db leveldb -P /home/messidor/YCSB-cpp/workloads/workload$wl -p leveldb.dbname=$DB_PATH -p recordcount=$RECORD_COUNT -p operationcount=$OP_COUNT -p threadcount=1" > $LOG_DIR/ycsb_$wl.log 2>&1

    echo " ├─ [YCSB] 执行完毕！"

    # 3.4 优雅关闭本轮 Collector 触发 CSV 落盘
    echo " ├─ [Collector] 正在保存 CSV 数据..."
    sudo pkill -SIGINT -f "data_collector.out" 2>/dev/null
    wait $COLLECTOR_PID 2>/dev/null
    sleep 1

    echo " └─ ✅ Workload $wl 数据采集完成。"
    
    # 准备下一轮的系统纯净度
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 2
end

echo -e "\n🎉 所有 Workload 采集完毕！即将清理环境..."
# 触发自带清理钩子
kill -SIGINT %self