#!/usr/bin/env fish

# ==========================================
# Chameleon 自动化测试靶场 (时序终极修复版)
# ==========================================

# Define test scope 
set policies linux_classic mru
set num_runs 1

set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set TEST_FILE "/tmp/test.dat"
set FILES_PATH (realpath "$HOME/linux")
set RESULT_FILE "result.txt"

set ROOT_DIR "/home/messidor/rl_page_cache"
set GMM_DIR "$ROOT_DIR/gmm"
set MRU_BIN "$ROOT_DIR/bpf/cache_ext_mru.out"
set MRU_PROC_NAME "cache_ext_mru.out"

# Tunables: keep cgroup hard limit fixed for fair comparisons.
set MEMORY_MAX "1G"
if not set -q MEMORY_HIGH
    set MEMORY_HIGH "800M"
end
if not set -q RG_ROUNDS
    set RG_ROUNDS 5
end
if not set -q RG_THREADS
    set RG_THREADS 1
end
if not set -q RG_PATTERN
    set RG_PATTERN "write"
end

# Clear previous logs
echo "=== Chameleon Automation Benchmark Started ===" > $RESULT_FILE
echo "Timestamp: "(date) >> $RESULT_FILE

for p in $policies
    for i in (seq $num_runs)
        echo "" | tee -a $RESULT_FILE
        echo "========================================================" | tee -a $RESULT_FILE
        echo "▶▶▶ [Progress] Policy [$p] | Run: $i/$num_runs" | tee -a $RESULT_FILE
        echo "========================================================" | tee -a $RESULT_FILE
        
        # ==========================================
        # 🌟 核心防线 1：环境彻底净化
        # ==========================================
        echo "[Cleanup] Flushing system caches..."
        sync
        echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
        sleep 2

        if test -d $CGROUP_DIR
            sudo rmdir $CGROUP_DIR 2>/dev/null
            sleep 1 
        end

        # ==========================================
        # 🌟 核心防线 2：创建牢笼并第一时间设限
        # ==========================================
        sudo mkdir -p $CGROUP_DIR
        
        # 【关键修复】：设置高水位线 (memory.high) 作为 eBPF 触发器
        # 设置硬墙 (memory.max) 作为最后防线，拉开缓冲距离！
        echo $MEMORY_MAX | sudo tee $CGROUP_DIR/memory.max > /dev/null
        echo $MEMORY_HIGH | sudo tee $CGROUP_DIR/memory.high > /dev/null
        echo "0" | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

        set MRU_PID ""
        
        # ==========================================
        # 🌟 核心防线 3：路由分发与挂载 (含 MGLRU 修复)
        # ==========================================
        
        # 关闭 MGLRU，回退到经典 LRU 模式，确保对比的纯粹性
        echo "[System] Disabling MGLRU (Falling back to Classic Active/Inactive LRU)..." | tee -a $RESULT_FILE
        echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1

        # 如果是 linux_classic 策略
        if string match -q "linux_classic" $p
            echo "starting with Linux Classic LRU (No Chameleon probe)..." | tee -a $RESULT_FILE
        else
            echo "Starting mru probe (Preparing Policy: $p)..." | tee -a $RESULT_FILE
            sudo $MRU_BIN -c $CGROUP_DIR > mru.log 2>&1 &
            sleep 0.5
            set MRU_PID (pgrep -f $MRU_PROC_NAME)
            
            echo "Waiting for eBPF probe to inject into kernel space..."
            sleep 2 # 加载探针极快，2秒足矣，10秒太浪费生命了
        end

        echo "[Config] memory.max=$MEMORY_MAX memory.high=$MEMORY_HIGH rg_rounds=$RG_ROUNDS rg_threads=$RG_THREADS" | tee -a $RESULT_FILE
        echo "[Before] memory.current="(cat $CGROUP_DIR/memory.current) | tee -a $RESULT_FILE
        echo "[Before] memory.events="(string join ',' (cat $CGROUP_DIR/memory.events)) | tee -a $RESULT_FILE

        # ==========================================
        # 🌟 核心防线 4：精确投放负载并测量
        # ==========================================
        echo "[Starting read/write pressure...]"
        
        sudo cgexec -g memory:cache_ext_cml_test \
        /usr/bin/time -v -o /tmp/time_output.txt \
        fish -c 'for i in (seq 1 '"$RG_ROUNDS"'); rg -j '"$RG_THREADS"' --no-mmap '"$RG_PATTERN"' '"$FILES_PATH"' > /dev/null; end'
        
        # Append time metrics to the result file
        cat /tmp/time_output.txt >> $RESULT_FILE
        echo "[After] memory.current="(cat $CGROUP_DIR/memory.current) | tee -a $RESULT_FILE
        echo "[After] memory.peak="(cat $CGROUP_DIR/memory.peak 2>/dev/null) | tee -a $RESULT_FILE
        echo "[After] memory.events="(string join ',' (cat $CGROUP_DIR/memory.events)) | tee -a $RESULT_FILE
        
        # ==========================================
        # 🌟 核心防线 5：战后清点
        # ==========================================
        if string match -q "mru" $p
            echo "Cleaning up MRU probe..."
            if test -n "$MRU_PID"
                sudo kill -9 $MRU_PID 2>/dev/null
            end
            while pgrep -f $MRU_PROC_NAME > /dev/null; sleep 0.5; end
            sleep 1 
        end
        
        # 尝试删除 Cgroup
        sudo rmdir $CGROUP_DIR 2>/dev/null
    end
end

# 恢复系统 MGLRU
echo 7 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1

echo "=== Benchmarking Complete. Results saved to $RESULT_FILE ==="