#!/usr/bin/env fish
# eval_fio_auto.fish (FIO 权威压测版)

set ROOT_DIR "/home/messidor/rl_page_cache"
set GMM_DIR "$ROOT_DIR/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_web"
set CML_BIN "$ROOT_DIR/bpf/chameleon.out"

set DATA_DIR "/tmp/fio_data"
set HOT_FILE "$DATA_DIR/hot_web.dat"
set COLD_FILE "$DATA_DIR/cold_poison.dat"
set LOG_DIR "$GMM_DIR/log/fio_eval"

# ==========================================
# 0. 环境清理与前置检查
# ==========================================
function cleanup
    echo "[Cleanup] 🔪 正在清理战场..."
    sudo pkill -9 fio 2>/dev/null
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sleep 1
    sudo pkill -9 -f "chameleon.out" 2>/dev/null
    
    if test -f $CGROUP_DIR/cgroup.procs
        for pid in (cat $CGROUP_DIR/cgroup.procs 2>/dev/null)
            echo $pid | sudo tee /sys/fs/cgroup/cgroup.procs > /dev/null 2>&1
        end
    end
    if test -d $CGROUP_DIR
        sudo rmdir $CGROUP_DIR 2>/dev/null
    end
end
trap cleanup EXIT INT TERM

sudo -v
cleanup
mkdir -p $LOG_DIR
mkdir -p $DATA_DIR

if not type -q fio
    echo "❌ 找不到 fio! 请执行: sudo apt install fio"
    exit 1
end

# ==========================================
# 1. 弹药制造：使用 FIO 生成精准测试文件
# ==========================================
if not test -f $HOT_FILE
    echo "🛠️ [准备阶段] 正在生成 500MB 热点文件 (Web 数据)..."
    fio --name=prep_hot --filename=$HOT_FILE --size=500M --rw=write --bs=1M &> /dev/null
end

if not test -f $COLD_FILE
    echo "🛠️ [准备阶段] 正在生成 2GB 冷文件 (毒药扫描数据)..."
    fio --name=prep_cold --filename=$COLD_FILE --size=2G --rw=write --bs=1M &> /dev/null
end

# ==========================================
# 2. 部署 600MB 内存牢笼
# ==========================================
sudo mkdir -p $CGROUP_DIR
echo "550M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo "600M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

set strategies "standard_lru" "chameleon_auto"

# ==========================================
# 3. 核心对抗大循环 (FIO 版)
# ==========================================
for strategy in $strategies
    echo -e "\n======================================================="
    echo " 🎯 Web 随机读 vs 后台顺序大扫描: [$strategy] "
    echo "======================================================="
    
    # 彻底清空全局 Page Cache
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 2

    if test "$strategy" = "standard_lru"
        echo "[Config] 切换至 Linux 原生 LRU..."
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
    else
        echo "[Config] 切换至 Chameleon 自治探针..."
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        sudo $CML_BIN -c $CGROUP_DIR > /dev/null 2>&1 &
        sleep 2
    end

    set LOG_FILE "$LOG_DIR/fio_"$strategy".log"
    echo "🚀 [0s] 启动 FIO 前台热点读取 (500MB, 4K 随机读)..."
    
    # 前台：4K 随机读，跑 60 秒。强制利用 Page Cache (direct=0)，不准自己清缓存 (invalidate=0)
    bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec fio --name=web_fg --filename=$HOT_FILE --rw=randread --bs=4k --ioengine=sync --direct=0 --invalidate=0 --time_based --runtime=60 --group_reporting" > $LOG_FILE 2>&1 &
    set fg_pid (jobs -p | head -n 1)

    echo "⏳ 等待 15 秒预热期 (让 500MB 填满 Active 链表)..."
    sleep 15

    echo "☠️ [15s] 警告！后台毒药 FIO (2GB, 1M 顺序纯扫描) 已注入..."
    # 后台：1M 顺序读，跑 45 秒。同样丢进 Cgroup，与前台残酷争抢 600M 内存
    bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec fio --name=poison_bg --filename=$COLD_FILE --rw=read --bs=1M --ioengine=sync --direct=0 --invalidate=0 --time_based --runtime=45" > /dev/null 2>&1 &
    set bg_pid (jobs -p | head -n 1)
    
    # 等待前台 60 秒任务结束
    wait $fg_pid
    
    echo "🏁 [60s] 压测结束，清理后台残留..."
    sudo kill -9 $bg_pid 2>/dev/null
    
    echo -e "\n📊 核心成绩单 ($strategy):"
    # FIO 的输出极度标准，直接抓取 IOPS 所在的行
    grep "IOPS=" $LOG_FILE
    
    sleep 3
end

echo -e "\n🎉 全部 FIO 测试结束！"
cleanup