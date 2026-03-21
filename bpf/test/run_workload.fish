#!/usr/bin/env fish

# 定义测试范围
set workloads wl1 wl2 wl3 wl4
set policies linux lru mru sieve lfu 
set num_runs 3

set CGROUP_DIR "/sys/fs/cgroup/cache_ext_cml_test"
set TEST_FILE "/tmp/test.dat"
set CACHE_MB 200
set FILE_MB 5000
set RESULT_FILE "result.txt"

# 清空之前的日志
echo "=== Chameleon 自动化评测启动 ===" > $RESULT_FILE
echo "时间: "(date) >> $RESULT_FILE

# 1. 如果测试基底文件不存在，先生成
if not test -f $TEST_FILE
    echo "[初始化] 正在生成 5GB 测试文件..." | tee -a $RESULT_FILE
    dd if=/dev/urandom of=$TEST_FILE bs=1M count=$FILE_MB status=progress
end

for p in $policies
    for w in $workloads
        for i in (seq $num_runs)
            echo "" | tee -a $RESULT_FILE
            echo "========================================================" | tee -a $RESULT_FILE
            echo "▶▶▶ [进度指示] 正在执行: Workload [$w] | Policy [$p] | 轮次: $i/3" | tee -a $RESULT_FILE
            echo "========================================================" | tee -a $RESULT_FILE
            
            # 1. 设置 cgroup v2
            sudo mkdir -p $CGROUP_DIR
            echo "200M" | sudo tee $CGROUP_DIR/memory.max > /dev/null
            echo "0" | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null

            # 2. 排空系统缓存
            echo "[环境清理] 正在排空系统缓存..."
            sync
            echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
            sleep 2

            # 3. 将当前 PID 写入 cgroup
            echo $fish_pid | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null

            set CML_PID ""
            # 4. 启动 Chameleon 探针
            if test $p != "linux"
                echo "正在启动变色龙探针 (准备切换 Policy: $p)..."
                # 后台启动 eBPF 程序，使用 sudo
                sudo ../chameleon.out ... > chameleon.log 2>&1 &
                # 获取刚刚通过 sudo 启动的后台任务的真实 PID
                set CML_PID (pgrep -f "chameleon.out")
                
                echo "等待 eBPF 探针注入内核空间..."
                sleep 2

                # 切换策略 (注意：确保参数格式正确)
                if test $p = "lru"
                    sudo bpftool map update name cml_params_map key 0 0 0 0 value 0 0 0 0 > /dev/null
                    echo "变色龙已切换到 LRU 模式！" | tee -a $RESULT_FILE
                else if test $p = "sieve"
                    sudo bpftool map update name cml_params_map key 0 0 0 0 value 1 0 0 0 > /dev/null
                    echo "变色龙已切换到 SIEVE 模式！" | tee -a $RESULT_FILE
                else if test $p = "mru"
                    sudo bpftool map update name cml_params_map key 0 0 0 0 value 2 0 0 0 > /dev/null
                    echo "变色龙已切换到 MRU 模式！" | tee -a $RESULT_FILE
                else if test $p = "lfu"
                    sudo bpftool map update name cml_params_map key 0 0 0 0 value 3 0 0 0 > /dev/null
                    echo "变色龙已切换到 LFU 模式！" | tee -a $RESULT_FILE
                end
            end

            # 5. 核心测试：执行 C++ 负载并测量时间
            # 使用 `time` 并将其标准错误 (stderr) 重定向到文件，因为 time 命令的输出在 stderr
            # 这里的 $w 已经修正
            echo "[开始施加读写压力...]"
            env /usr/bin/time -v -o /tmp/time_output.txt ./workload_gen.out $TEST_FILE $w $CACHE_MB $FILE_MB > /dev/null
            
            # 将 time 的核心耗时结果追加到总文件
            cat /tmp/time_output.txt >> $RESULT_FILE
            
            # 6. 清理现场
            if test $p != "linux"
                echo "正在清理变色龙探针..."
                if test -n "$CML_PID"
                    sudo kill -9 $CML_PID 2>/dev/null
                end
                # 等待进程彻底消失
                while pgrep -f "chameleon.out" > /dev/null; sleep 0.5; end
                sleep 1 
            end
            
            # 清理 Cgroup 
            # 注意：如果目录里还有遗留进程，rmdir 会失败，但没关系，下一轮 mkdir 会兜底
            sudo rmdir $CGROUP_DIR 2>/dev/null

            # 排空系统缓存
            echo "[环境清理] 正在排空系统缓存..."
            sync
            echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
            sleep 2
        end
    end
end

echo "=== 测试全部完成，结果已保存至 $RESULT_FILE ==="