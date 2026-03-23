#!/usr/bin/env fish

# ==========================================
# Chameleon 自动化测试靶场 (时序终极修复版)
# ==========================================

# Define test scope
set workloads wl1 wl2 wl3 wl4 
set policies lru sieve mru linux_classic linux_mglru 
set num_runs 3

set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set TEST_FILE "/tmp/test.dat"
set CACHE_MB 200       # 缓存目标水位 200MB
set MAX_MB 350         # 硬墙设为 210MB！
set FILE_MB 5000
set RESULT_FILE "result.txt"

# Clear previous logs
echo "=== Chameleon Automation Benchmark Started ===" > $RESULT_FILE
echo "Timestamp: "(date) >> $RESULT_FILE

# 1. Generate base test file if it doesn't exist
if not test -f $TEST_FILE
    echo "[Init] Generating 5GB test file..." | tee -a $RESULT_FILE
    dd if=/dev/urandom of=$TEST_FILE bs=1M count=$FILE_MB status=progress
end

for p in $policies
    for w in $workloads
        for i in (seq $num_runs)
            echo "" | tee -a $RESULT_FILE
            echo "========================================================" | tee -a $RESULT_FILE
            echo "▶▶▶ [Progress] Executing: Workload [$w] | Policy [$p] | Run: $i/$num_runs" | tee -a $RESULT_FILE
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
            echo "350M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
            echo "200M" | sudo tee $CGROUP_DIR/memory.high > /dev/null
            echo "0" | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

            set CML_PID ""
            
            # ==========================================
            # 🌟 核心防线 3：路由分发与挂载 (含 MGLRU 修复)
            # ==========================================
            
            # 【关键修复】：只有测试 linux_mglru 时才开启，其余情况全部关闭！
            if test $p = "linux_mglru"
                echo "[System] Enabling Linux MGLRU..." | tee -a $RESULT_FILE
                echo 7 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
            else
                echo "[System] Disabling MGLRU (Falling back to Classic Active/Inactive LRU)..." | tee -a $RESULT_FILE
                echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
            end

            # 启动 eBPF 探针 (如果不是原生 Linux 策略)
            if not string match -q "linux*" $p
                echo "Starting Chameleon probe (Preparing Policy: $p)..."
                
                # 假设脚本在 agent/scripts 目录下，回退两层或一层找到 chameleon.out
                # 请根据你实际存放 chameleon.out 的路径调整这里
                sudo ../chameleon.out -c $CGROUP_DIR > chameleon.log 2>&1 &
                
                sleep 0.5
                set CML_PID (pgrep -f "chameleon.out")
                
                echo "Waiting for eBPF probe to inject into kernel space..."
                sleep 2 # 加载探针极快，2秒足矣，10秒太浪费生命了

                set PIN_PATH "/sys/fs/bpf/cml_params_map"

                # 通过强壮的 pinned 路径下发策略
                switch $p
                    case "lru"
                        sudo bpftool map update pinned $PIN_PATH key 0 0 0 0 value 0 0 0 0 
                        echo "Chameleon switched to eBPF LRU mode!" | tee -a $RESULT_FILE
                    case "sieve"
                        sudo bpftool map update pinned $PIN_PATH key 0 0 0 0 value 1 0 0 0 
                        echo "Chameleon switched to eBPF SIEVE mode!" | tee -a $RESULT_FILE
                    case "mru"
                        sudo bpftool map update pinned $PIN_PATH key 0 0 0 0 value 2 0 0 0 
                        echo "Chameleon switched to eBPF MRU mode!" | tee -a $RESULT_FILE
                    case "lfu"
                        sudo bpftool map update pinned $PIN_PATH key 0 0 0 0 value 3 0 0 0 
                        echo "Chameleon switched to eBPF LFU mode!" | tee -a $RESULT_FILE
                end
            end

            # ==========================================
            # 🌟 核心防线 4：精确投放负载并测量
            # ==========================================
            echo "[Starting read/write pressure...]"
            
            sudo sh -c "echo \$\$ > $CGROUP_DIR/cgroup.procs && exec env /usr/bin/time -v -o /tmp/time_output.txt ./workload_gen.out $TEST_FILE $w $CACHE_MB $FILE_MB > /dev/null"
            
            # Append time metrics to the result file
            cat /tmp/time_output.txt >> $RESULT_FILE
            
            # ==========================================
            # 🌟 核心防线 5：战后清点
            # ==========================================
            if not string match -q "linux*" $p
                echo "Cleaning up Chameleon probe..."
                if test -n "$CML_PID"
                    sudo kill -9 $CML_PID 2>/dev/null
                end
                while pgrep -f "chameleon.out" > /dev/null; sleep 0.5; end
                sleep 1 
            end
            
            # 尝试删除 Cgroup
            sudo rmdir $CGROUP_DIR 2>/dev/null

        end
    end
end

# 恢复系统 MGLRU
echo 7 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1

echo "=== Benchmarking Complete. Results saved to $RESULT_FILE ==="