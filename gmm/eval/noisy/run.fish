#!/usr/bin/env fish

set ROOT_DIR "/home/messidor/rl_page_cache"
set GMM_DIR "$ROOT_DIR/gmm"
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_web"
set CML_BIN "$ROOT_DIR/bpf/chameleon.out"

set PYTHON_BIN "$GMM_DIR/.venv/bin/python"
set AGENT_BIN "$GMM_DIR/inference/agent.py"

set DATA_DIR "/tmp/fio_data"
set HOT_FILE "$DATA_DIR/hot_web.dat"
set COLD_FILE "$DATA_DIR/cold_poison.dat"
set LOG_DIR "$GMM_DIR/log/noisy_eval"

function cleanup
    echo "[Cleanup] Stopping workloads and agents..."
    sudo pkill -9 fio 2>/dev/null
    
    sudo pkill -SIGINT -f "agent.py" 2>/dev/null
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sleep 1.5
    sudo pkill -9 -f "agent.py" 2>/dev/null
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
# 1. 数据准备
# ==========================================
if not test -f $HOT_FILE
    echo "🛠️ 生成 1GB 热点数据..."
    fio --name=prep_hot --filename=$HOT_FILE --size=1024M --rw=write --bs=1M &> /dev/null
end

if not test -f $COLD_FILE
    echo "🛠️ 生成 5GB 冷数据（确保持续污染）..."
    fio --name=prep_cold --filename=$COLD_FILE --size=5G --rw=write --bs=1M &> /dev/null
end

# ==========================================
# 2. cgroup 牢笼设置
# ==========================================
sudo mkdir -p $CGROUP_DIR
echo "1500M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo "2G" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

set strategies "standard_lru" "chameleon_auto"
set scan_jobs_list 1 2

function phase_avg -a log_file start_line end_line
    awk -F, -v s=$start_line -v e=$end_line 'NR>=s&&NR<=e{sum+=$2;n++} END{if(n>0) printf "%.2f", sum/n; else printf "nan"}' $log_file
end

# ==========================================
# 3. 核心评测循环 (90秒连续时间线)
# ==========================================
for strategy in $strategies
    for scan_jobs in $scan_jobs_list

        echo -e "\n================================================="
        echo "🚀 [Start] Strategy: $strategy | Scan Intensity: $scan_jobs Jobs"
        echo "================================================="

        sync
        echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
        sleep 2

        if test "$strategy" = "standard_lru"
            echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
        else
            echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
            echo " ├─ 启动分离的数据面与控制面 (Pipe 链接)..."
            
            # 🌟 核心修改：用管道把 C 的 stdout 直接喂给 Python 的 stdin
            # 将它们包装在一个 bash 命令里运行，统一放后台
            bash -c "sudo $CML_BIN -c $CGROUP_DIR | sudo $PYTHON_BIN $AGENT_BIN > $LOG_DIR/agent_"$scan_jobs".log 2>&1" &
            
            # 抓取外层 bash 的 PID，方便一会清理
            set -g agent_pid $last_pid
            sleep 4

            if not kill -0 $agent_pid 2>/dev/null
                echo " ❌ 控制面启动失败，请检查 $LOG_DIR/agent_"$scan_jobs".log"
                continue
            end
        end

        set LOG_FILE "$LOG_DIR/fio_"$strategy"_scan"$scan_jobs".log"
        # 使用下划线连接，完美避开 Fish 语法坑
        set IOPS_LOG_PREFIX "$LOG_DIR/"$strategy"_scan"$scan_jobs

        rm -f $LOG_FILE
        rm -f $IOPS_LOG_PREFIX*.log

        echo " ├─ 启动前台热点数据库 (贯穿全场, 共 90s)..."
        bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec fio \
            --name=web_fg \
            --filename=$HOT_FILE \
            --rw=randread \
            --bs=4k \
            --ioengine=sync \
            --direct=0 \
            --time_based \
            --runtime=90 \
            --group_reporting=0 \
            --write_iops_log=\"$IOPS_LOG_PREFIX\" \
            --log_avg_msec=1000" > $LOG_FILE 2>&1 &

        # 直接使用 last_pid，避免拿到先前后台任务（例如 agent）的 PID。
        set fg_pid $last_pid
        
        echo " ├─ ⏳ 阶段 1/3: 正常运行期 (等待 30s)..."
        sleep 30

        echo " ├─ ⚠️ 阶段 2/3: 注入恶意扫描负载 (毒药运行 30s)..."
        bash -c "echo \$\$ | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null && exec fio \
            --name=poison_bg \
            --filename=$COLD_FILE \
            --rw=read \
            --bs=1M \
            --ioengine=sync \
            --direct=0 \
            --numjobs=$scan_jobs \
            --fadvise_hint=sequential \
            --time_based \
            --runtime=30" > /dev/null 2>&1 &
        
        echo " ├─ ⏳ 正在承受扫描攻击 (等待 30s)..."
        sleep 30

        echo " ├─ 🔄 阶段 3/3: 毒药已退出，进入恢复期 (等待 30s)..."
        # 等待前台 90s 的 fio 进程自然结束
        wait $fg_pid

        echo " ├─ ✅ 90s 评测时间线结束！"
        echo " 📝 90秒连续 IOPS 数据已保存至: "$IOPS_LOG_PREFIX"_iops.1.log"
        
        if test "$strategy" = "chameleon_auto"
            sudo pkill -SIGINT -f "agent.py" 2>/dev/null
            sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
        end
        sleep 3
    end
end

echo -e "\n🎉 全自动化 Eval 脚本执行完毕！"

echo "\n================ 结果汇总（按阶段均值） ================"
for scan_jobs in $scan_jobs_list
    set std_file "$LOG_DIR/standard_lru_scan"$scan_jobs"_iops.1.log"
    set chm_file "$LOG_DIR/chameleon_auto_scan"$scan_jobs"_iops.1.log"

    if not test -f $std_file
        echo "[scan=$scan_jobs] 缺少基线日志: $std_file"
        continue
    end
    if not test -f $chm_file
        echo "[scan=$scan_jobs] 缺少 chameleon 日志: $chm_file"
        continue
    end

    set std_warm (phase_avg $std_file 1 30)
    set std_attack (phase_avg $std_file 31 60)
    set std_recover (phase_avg $std_file 61 90)

    set chm_warm (phase_avg $chm_file 1 30)
    set chm_attack (phase_avg $chm_file 31 60)
    set chm_recover (phase_avg $chm_file 61 90)

    set attack_delta (awk -v c=$chm_attack -v s=$std_attack 'BEGIN{if(s>0) printf "%.2f", (c-s)/s*100; else printf "nan"}')
    set recover_delta (awk -v c=$chm_recover -v s=$std_recover 'BEGIN{if(s>0) printf "%.2f", (c-s)/s*100; else printf "nan"}')

    echo "[scan=$scan_jobs]"
    echo "  standard_lru: warmup=$std_warm attack=$std_attack recover=$std_recover"
    echo "  chameleon  : warmup=$chm_warm attack=$chm_attack recover=$chm_recover"
    echo "  delta      : attack=$attack_delta% recover=$recover_delta%"
end

cleanup