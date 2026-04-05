#!/usr/bin/env fish
# eval_workloads_full.fish (物理隔离抗毒药验证版)

set ROOT_DIR "/home/messidor/rl_page_cache"
set GMM_DIR "$ROOT_DIR/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set CML_BIN "$ROOT_DIR/bpf/chameleon.out"
set AGENT_BIN "$GMM_DIR/deploy/cml_agent.out"
set YCSB_BIN "/home/messidor/YCSB-cpp/ycsb"

set DB_PATH "/tmp/leveldb_ycsb"
set GOLDEN_PATH "/home/messidor/db_data"  # 👈 你的母体路径
set LOG_DIR "$GMM_DIR/log/ycsb_eval"
mkdir -p $LOG_DIR

set RECORD_COUNT 5000000
set OP_COUNT 300000
set THREAD_COUNT 1

# 测试矩阵设定
set strategies  "standard_lru" "mglru" # "ai_agent"
set workloads a b c d e f
set nr_runs 3

# ==========================================
# 0. 准备毒药文件 (用于模拟缓存污染)
# ==========================================
set POISON_FILE "/tmp/poison_scan.dat"
if not test -f $POISON_FILE
    echo "[Prepare] ☠️ 正在锻造 2GB 毒药文件用于模拟后台扫描污染..."
    dd if=/dev/urandom of=$POISON_FILE bs=1M count=2000 status=progress
    sync
    echo "[Prepare] ✅ 毒药文件锻造完毕！"
end

# ==========================================
# 1. 绝对防御的清理钩子
# ==========================================
function cleanup_bpf_agent
    echo "[Cleanup] 🔪 正在执行深度清理..."
    sudo pkill -9 -f "ycsb" 2>/dev/null
    sudo pkill -9 -f "cat $POISON_FILE" 2>/dev/null  # 🌟 必须杀掉毒药进程
    sudo pkill -SIGINT -f "cml_agent.out" 2>/dev/null
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sleep 2
    sudo pkill -9 -f "cml_agent.out" 2>/dev/null
    sudo pkill -9 -f "chameleon.out" 2>/dev/null
    
    # 强制将 Cgroup 内可能残留的进程移回根 Cgroup
    if test -f $CGROUP_DIR/cgroup.procs
        for pid in (cat $CGROUP_DIR/cgroup.procs 2>/dev/null)
            echo $pid | sudo tee /sys/fs/cgroup/cgroup.procs > /dev/null 2>&1
        end
    end
    
    # 确保旧的 Cgroup 彻底灰飞烟灭
    if test -d $CGROUP_DIR
        sudo rmdir $CGROUP_DIR 2>/dev/null
        sleep 1
    end
end

function handle_exit --on-signal SIGINT --on-signal SIGTERM
    if set -q _CLEANUP_CALLED
        return
    end
    set -g _CLEANUP_CALLED 1
    echo -e "\n\n[🛡️ Cleanup] 收到中断信号！强制终止..."
    cleanup_bpf_agent
    if test -d $CGROUP_DIR
        sudo rmdir $CGROUP_DIR 2>/dev/null
    end
    exit 0
end

function setup_cgroup
    echo "[System] 🧱 正在(重)建 1024MB 内存牢笼..."
    sudo mkdir -p $CGROUP_DIR
    
    echo "800M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
    echo "1024M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
    echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null
    
    if test -d $CGROUP_DIR
        echo "✅ Cgroup 牢笼已就绪：$CGROUP_DIR"
    end
end

# ==========================================
# 2. 检查母体是否存在
# ==========================================
if not test -d $GOLDEN_PATH
    echo "❌ 致命错误：找不到数据母体 $GOLDEN_PATH！请先使用 rsync 备份一份 Golden Copy。"
    exit 1
end

# ==========================================
# 3. 部署全局 Cgroup 牢笼配置
# ==========================================
sudo -v
cleanup_bpf_agent
setup_cgroup

# ==========================================
# 4. 核心大循环：策略 x 负载 x 运行次数
# ==========================================
for strategy in $strategies
    echo "\n\n======================================================="
    echo " 👑 当前比拼策略: [$strategy] "
    echo "======================================================="
    
    cleanup_bpf_agent
    setup_cgroup
    
    # 🌟 每次切换策略时，恢复干净的数据库物理环境
    echo "[Data Restore] 🔄 正在从 Golden Copy 极速克隆数据库状态 (耗时仅需几秒)..."
    rsync -a --delete $GOLDEN_PATH/ $DB_PATH/
    sync
    echo "  └─ ✅ 克隆完成，确保本轮测试物理环境绝对公平！"
    
    if test "$strategy" = "standard_lru"
        echo "[Config] 切换至 Linux 标准双链表 LRU..."
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        
    else if test "$strategy" = "mglru"
        echo "[Config] 切换至 Linux 现代 MGLRU (Multi-Gen LRU)..."
        echo 7 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        
    else if test "$strategy" = "ai_agent"
        echo "[Config] 切换至 🤖 AI Agent 动态控制态..."
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        
        echo "  └─ 🚀 启动变色龙内核探针..."
        sudo $CML_BIN -c $CGROUP_DIR < /dev/null > $LOG_DIR/chameleon_$strategy.log 2>&1 &
        sleep 2 
        
    end

    for wl in $workloads
        for run in (seq 1 $nr_runs)
            echo "-------------------------------------------------------"
            echo "🔥 [$strategy] 正在执行 Workload $wl (第 $run/$nr_runs 次) ..."
            
            sync
            echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
            sleep 10
            
            set CURRENT_LOG "$LOG_DIR/ycsb_"$strategy"_"$wl"_run"$run".log"
            
            # --------------------------------------------------
            # 🛡️ 双核完美隔离战场 (Plan B - 极简证明基点)
            # --------------------------------------------------
            
            # 1. 毒药进程：独占 CPU 1
            echo "  ☠️ 正在注入后台顺序扫描 (精准绑定至 CPU 1)..."
            bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && while true; do taskset -c 1 cat $POISON_FILE > /dev/null; done" &
            set POISON_PID $last_pid

            # 2. YCSB 前台业务：独占 CPU 0
            echo "  👉 正在单核全速压测 YCSB (精准绑定至 CPU 0)，输出至: $CURRENT_LOG"
            bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec taskset -c 0 $YCSB_BIN -run -db leveldb -P /home/messidor/YCSB-cpp/workloads/workload$wl -p leveldb.dbname=$DB_PATH -p recordcount=$RECORD_COUNT -p operationcount=$OP_COUNT -p threadcount=1 -p measurementtype=hdrhistogram" > $CURRENT_LOG 2>&1
            
            # 3. YCSB 跑完后，立刻击毙毒药
            sudo kill -9 $POISON_PID 2>/dev/null
            echo "  └─ ✅ 本次单核压测结束！"
        end
    end
end

echo "\n\n======================================================="
echo "🎉 终极大考结束！"
echo "👉 请前往 $LOG_DIR 查收所有的纯净版日志文件。"
handle_exit