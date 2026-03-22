#!/usr/bin/env fish

# Define test scope
set workloads wl1 wl2 wl3 wl4
set policies lru mru sieve lfu linux_classic linux_mglru 
set num_runs 1

set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set TEST_FILE "/tmp/test.dat"
set CACHE_MB 200
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
            
            # 1. Setup cgroup v2
            sudo mkdir -p $CGROUP_DIR
            echo "200M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
            echo "0" | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

            # 2. Flush system cache
            echo "[Cleanup] Flushing system caches..."
            sync
            echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
            sleep 2

            # 3. Write current PID to cgroup
            echo $fish_pid | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null

            set CML_PID ""
            
            # 4. Routing: Determine whether to run Linux native control group or our eBPF Chameleon probe
            if string match -q "linux*" $p
                # Check if the policy is linux_classic or linux_mglru and set MGLRU accordingly
                if test $p = "linux_classic"
                    echo "[System] Disabling MGLRU (Falling back to Classic Active/Inactive LRU)..." | tee -a $RESULT_FILE
                    # write 0 (or n/0x0000) to disable MGLRU and revert to classic LRU behavior
                    echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
                else if test $p = "linux_mglru"
                    echo "[System] Enabling Linux MGLRU..." | tee -a $RESULT_FILE
                    # write 7 (or y/0x0007) to enable MGLRU with all generations active (gen0, gen1, gen2)
                    echo 7 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1
                end
            else
                echo "Starting Chameleon probe (Preparing Policy: $p)..."
                # Start eBPF program in background using sudo
                sudo ../chameleon.out -c $CGROUP_DIR > chameleon.log 2>&1 &
                
                # Small sleep to ensure the process is registered
                sleep 0.5
                # Get the actual PID of the background task
                set CML_PID (pgrep -f "chameleon.out")
                
                echo "Waiting for eBPF probe to inject into kernel space..."
                sleep 10

                # Switch Policy (Ensure parameter format is correct)
                set PIN_PATH "/sys/fs/bpf/cml_params_map"

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

            # 5. Core Test: Execute C++ workload and measure time
            echo "[Starting read/write pressure...]"
            env /usr/bin/time -v -o /tmp/time_output.txt ./workload_gen.out $TEST_FILE $w $CACHE_MB $FILE_MB > /dev/null
            
            # Append time metrics to the result file
            cat /tmp/time_output.txt >> $RESULT_FILE
            
            # 6. Post-test Cleanup
            # only kill Chameleon if it was started (i.e., not in Linux native mode)
            if not string match -q "linux*" $p
                echo "Cleaning up Chameleon probe..."
                if test -n "$CML_PID"
                    sudo kill -9 $CML_PID 2>/dev/null
                end
                # Wait for process to fully exit
                while pgrep -f "chameleon.out" > /dev/null; sleep 0.5; end
                sleep 1 
            end
            
            # Cleanup Cgroup 
            # Note: rmdir might fail if processes are lingering, but mkdir will handle it next round
            sudo rmdir $CGROUP_DIR 2>/dev/null

            # Final environment cleanup for the next run
            echo "[Cleanup] Flushing system caches..."
            sync
            echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
            sleep 2
        end
    end
end

# After all tests, ensure MGLRU is enabled for the system's normal operation
echo 1 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null 2>&1

echo "=== Benchmarking Complete. Results saved to $RESULT_FILE ==="