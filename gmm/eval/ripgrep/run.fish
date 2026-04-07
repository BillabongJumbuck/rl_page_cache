#!/usr/bin/env fish
# eval_ripgrep.fish

set ROOT_DIR "/home/messidor/rl_page_cache"
set GMM_DIR "$ROOT_DIR/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_eval_test"
set CML_BIN "$ROOT_DIR/bpf/chameleon.out"

set TARGET_DIR "$HOME/linux"
set LOG_DIR "$GMM_DIR/log/rg_eval"
mkdir -p $LOG_DIR

# 测试矩阵：每种策略跑 3 次
set strategies  "ai_agent" # "standard_lru" "mglru"
set RUN_COUNT 3

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

echo "[System] 🧱 部署 800MB 内存牢笼..."
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
    echo "\n======================================================="
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
        echo "[Config] 切换至 🤖 AI Agent 动态控制态..."
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        
        echo "  └─ 🚀 启动变色龙内核探针..."
        sudo $CML_BIN -c $CGROUP_DIR < /dev/null > $LOG_DIR/chameleon_$strategy.log 2>&1 &
        sleep 2 
        
    end

    for run in (seq 1 $RUN_COUNT)
        echo "-------------------------------------------------------"
        echo "🔥 [$strategy] 正在执行第 $run/$RUN_COUNT 次大扫表测试 ..."
        
        # 极度公平：每次运行前彻底清空 Page Cache，逼迫物理盘 I/O 满载启动
        sync
        echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
        sleep 1
        
        # 核心：将 rg 扔进牢笼，并使用 /usr/bin/time 提取纯净的执行时间 (%e = real time in seconds)
        # 屏蔽 rg 的标准输出，强制其扫描每一个文件，将 time 的结果输出到临时文件
        /usr/bin/time -f "%e" bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec taskset -c 0 rg -j 1 'EXPORT_SYMBOL_GPL' $TARGET_DIR > /dev/null" 2> $TIME_TMP
        
        set exec_time (cat $TIME_TMP)
        echo "  👉 扫描耗时: $exec_time 秒"
        
        echo "$strategy,$run,$exec_time" >> $RESULT_CSV
    end
end

echo "\n======================================================="
echo "🎉 轻量级大扫表评测结束！"
echo "👉 核心成绩单已生成: $RESULT_CSV"
handle_exit