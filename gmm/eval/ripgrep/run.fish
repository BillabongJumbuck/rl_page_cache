#!/usr/bin/env fish
# eval_ripgrep_v2.fish

set ROOT_DIR "/home/messidor/rl_page_cache"
set GMM_DIR "$ROOT_DIR/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_eval_test"
set CML_BIN "$ROOT_DIR/bpf/chameleon.out"

set TARGET_DIR "$HOME/linux"
set LOG_DIR "$GMM_DIR/log/rg_eval"
mkdir -p $LOG_DIR

# 🌟 测试矩阵：为了看到缓存预热后的效果，连续扫描 10 次
set strategies  "ai_agent" "standard_lru" "mglru"
set RUN_COUNT 10

# 检查依赖
if not type -q rg
    echo "❌ 找不到 ripgrep! 请先执行: sudo apt install ripgrep"
    exit 1
end

if not test -d $TARGET_DIR
    echo "❌ 找不到 Linux 源码目录: $TARGET_DIR"
    exit 1
end

# ==========================================
# 0. 绝对防御的清理钩子
# ==========================================
function cleanup_bpf_agent
    sudo pkill -9 -f "rg" 2>/dev/null
    sudo pkill -SIGINT -f "cml_agent.out" 2>/dev/null
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sleep 1
    sudo pkill -9 -f "cml_agent.out" 2>/dev/null
    sudo pkill -9 -f "chameleon.out" 2>/dev/null
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

# ==========================================
# 1. 部署全局 Cgroup 牢笼
# ==========================================
sudo -v
cleanup_bpf_agent

if test -d $CGROUP_DIR
    sudo rmdir $CGROUP_DIR 2>/dev/null
    sleep 1
end
sudo mkdir -p $CGROUP_DIR

echo "[System] 🧱 部署 512MB 内存牢笼..."
echo "400M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo "512M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

# ==========================================
# 2. 核心比拼大循环
# ==========================================
set RESULT_CSV "$LOG_DIR/rg_results.csv"
echo "Strategy,Run,Time(s)" > $RESULT_CSV
set TIME_TMP "/tmp/rg_time.tmp"

for strategy in $strategies
    echo -e "\n======================================================="
    echo " 👑 当前比拼策略: [$strategy] "
    echo "======================================================="
    
    cleanup_bpf_agent
    
    if test "$strategy" = "standard_lru"
        echo "[Config] 切换至 Linux 标准双链表 LRU..."
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        
    else if test "$strategy" = "mglru"
        echo "[Config] 切换至 Linux 现代 MGLRU (Multi-Gen LRU)..."
        echo 7 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        
    else if test "$strategy" = "ai_agent"
        echo "[Config] 切换至 🤖 AI Agent 动态控制态 (硬编码 0.8 MRU)..."
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        
        echo "  └─ 🚀 启动变色龙内核探针..."
        sudo $CML_BIN -c $CGROUP_DIR < /dev/null > $LOG_DIR/chameleon_$strategy.log 2>&1 &
        sleep 2 
    end

    # 🌟 关键修改：每种策略只在最开始清空一次缓存！
    echo "🧹 清理系统 Page Cache，准备冷启动..."
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 2

    set total_time 0

    for run in (seq 1 $RUN_COUNT)
        echo "-------------------------------------------------------"
        echo "🔥 正在执行第 $run/$RUN_COUNT 次多核极速扫描 ..."
        
        # 🌟 关键修改：去掉了 taskset -c 0 和 -j 1，释放多核与多线程并发性能
        /usr/bin/time -f "%e" bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec rg 'EXPORT_SYMBOL_GPL' $TARGET_DIR > /dev/null" 2> $TIME_TMP
        
        set exec_time (cat $TIME_TMP)
        echo "  👉 本次耗时: $exec_time 秒"
        
        echo "$strategy,$run,$exec_time" >> $RESULT_CSV
        set total_time (math "$total_time + $exec_time")
    end
    
    echo "🏁 [$strategy] 10次扫描总耗时: $total_time 秒"
end

echo -e "\n======================================================="
echo "🎉 轻量级大扫表评测结束！"
echo "👉 核心成绩单已生成: $RESULT_CSV"
handle_exit