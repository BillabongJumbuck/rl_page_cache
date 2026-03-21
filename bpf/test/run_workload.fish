#!/usr/bin/env fish

# Define test scope
set workloads wl1 wl2 wl3 wl4
set policies linux lru mru sieve lfu 
set num_runs 3

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
            echo "▶▶▶ [Progress] Executing: Workload [$w] | Policy [$p] | Run: $i/3" | tee -a $RESULT_FILE
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
            # 4. Start Chameleon Probe
            if test $p != "linux"
                echo "Starting Chameleon probe (Preparing Policy: $p)..."
                # Start eBPF program in background using sudo
                sudo ../chameleon.out -c $CGROUP_DIR > chameleon.log 2>&1 &
                
                # Small sleep to ensure the process is registered
                sleep 0.5
                # Get the actual PID of the background task
                set CML_PID (pgrep -f "chameleon.out")
                
                echo "Waiting for eBPF probe to inject into kernel space..."
                sleep 2

                # Switch Policy (Ensure parameter format is correct)
                switch $p
                    case "lru"
                        sudo bpftool map update name cml_params_map key 0 0 0 0 value 0 0 0 0 > /dev/null
                        echo "Chameleon switched to LRU mode!" | tee -a $RESULT_FILE
                    case "sieve"
                        sudo bpftool map update name cml_params_map key 0 0 0 0 value 1 0 0 0 > /dev/null
                        echo "Chameleon switched to SIEVE mode!" | tee -a $RESULT_FILE
                    case "mru"
                        sudo bpftool map update name cml_params_map key 0 0 0 0 value 2 0 0 0 > /dev/null
                        echo "Chameleon switched to MRU mode!" | tee -a $RESULT_FILE
                    case "lfu"
                        sudo bpftool map update name cml_params_map key 0 0 0 0 value 3 0 0 0 > /dev/null
                        echo "Chameleon switched to LFU mode!" | tee -a $RESULT_FILE
                end
            end

            # 5. Core Test: Execute C++ workload and measure time
            # Using /usr/bin/time -v to get verbose metrics
            echo "[Starting read/write pressure...]"
            env /usr/bin/time -v -o /tmp/time_output.txt ./workload_gen.out $TEST_FILE $w $CACHE_MB $FILE_MB > /dev/null
            
            # Append time metrics to the result file
            cat /tmp/time_output.txt >> $RESULT_FILE
            
            # 6. Post-test Cleanup
            if test $p != "linux"
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

echo "=== Benchmarking Complete. Results saved to $RESULT_FILE ==="