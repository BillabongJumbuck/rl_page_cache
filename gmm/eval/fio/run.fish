#!/usr/bin/env fish

set ROOT_DIR "/home/messidor/rl_page_cache"
set GMM_DIR "$ROOT_DIR/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_web"
set CML_BIN "$ROOT_DIR/bpf/chameleon.out"

set DATA_DIR "/tmp/fio_data"
set HOT_FILE "$DATA_DIR/hot_web.dat"
set COLD_FILE "$DATA_DIR/cold_poison.dat"
set LOG_DIR "$GMM_DIR/log/fio_eval"

function cleanup
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

# ==========================================
# 1. 数据准备（🔥 修改1：cold file ≥5GB）
# ==========================================
if not test -f $HOT_FILE
    fio --name=prep_hot --filename=$HOT_FILE --size=1024M --rw=write --bs=1M &> /dev/null
end

if not test -f $COLD_FILE
    echo "🛠️ 生成 5GB 冷数据（确保持续污染）"
    fio --name=prep_cold --filename=$COLD_FILE --size=5G --rw=write --bs=1M &> /dev/null
end

# ==========================================
# 2. cgroup
# ==========================================
sudo mkdir -p $CGROUP_DIR
echo "800M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo "1024M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

set strategies "standard_lru" "chameleon_auto"

# ==========================================
# 3. 🔥 修改4：scan 强度 sweep
# ==========================================
set scan_jobs_list 1 2 4 8

for strategy in $strategies
for scan_jobs in $scan_jobs_list

    echo "\n=== [$strategy] scan_jobs=$scan_jobs ==="

    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 2

    if test "$strategy" = "standard_lru"
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
    else
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        sudo $CML_BIN -c $CGROUP_DIR > /dev/null 2>&1 &
        sleep 2
    end

    set LOG_FILE "$LOG_DIR/fio_"$strategy"_scan"$scan_jobs".log"

    echo "🚀 前台热点 (randread)..."
    
    # 🔥 修改3：只关注 foreground（单独 job）
    bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec fio \
        --name=web_fg \
        --filename=$HOT_FILE \
        --rw=randread \
        --bs=4k \
        --ioengine=sync \
        --direct=0 \
        --invalidate=0 \
        --time_based \
        --runtime=90 \
        --group_reporting=0" > $LOG_FILE 2>&1 &
    
    set fg_pid (jobs -p | head -n 1)

    echo "⏳ warmup 15s..."
    sleep 15

    echo "☠️ 注入 scan (jobs=$scan_jobs)..."
    
    bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec fio \
        --name=poison_bg \
        --filename=$COLD_FILE \
        --rw=read \
        --bs=1M \
        --ioengine=sync \
        --direct=0 \
        --invalidate=0 \
        --numjobs=$scan_jobs \
        --fadvise_hint=sequential \
        --time_based \
        --runtime=60" > /dev/null 2>&1 &
    
    set bg_pid (jobs -p | head -n 1)

    wait $fg_pid

    sudo kill -9 $bg_pid 2>/dev/null

    # ==========================================
    # 🔥 修改2：Recovery Phase
    # ==========================================
    echo "🔄 Recovery phase (再跑30s randread)..."

    bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec fio \
        --name=web_recovery \
        --filename=$HOT_FILE \
        --rw=randread \
        --bs=4k \
        --ioengine=sync \
        --direct=0 \
        --invalidate=0 \
        --time_based \
        --runtime=30 \
        --group_reporting=0" >> $LOG_FILE 2>&1

    # ==========================================
    # 输出（只抓 foreground）
    # ==========================================
    echo "\n📊 FG性能 ($strategy, scan=$scan_jobs):"
    grep "web_fg" $LOG_FILE
    grep "web_recovery" $LOG_FILE

    sleep 3
end
end

echo "\n🎉 Done"
cleanup