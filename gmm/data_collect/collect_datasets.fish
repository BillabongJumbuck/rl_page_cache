#!/usr/bin/env fish

set CGROUP_DIR "/sys/fs/cgroup/cache_ext_dataset"
set CML_BIN "/home/messidor/rl_page_cache/bpf/chameleon.out"
set TEST_FILE "/tmp/cache_ext_test.dat"
set FILE_SIZE "5G"

# 避免 direct reclaim 的黄金组合：
# 留出 100MB 的 buffer 让 kswapd 从容进行后台回收
set MEM_HIGH "800M"
set MEM_MAX "1024M"

set CSV_MRU "scan_mru.csv"
set CSV_LRU "rand_lru.csv"

# ==========================================
# 0. 优雅退出与清理钩子
# ==========================================
function handle_exit --on-signal SIGINT --on-signal SIGTERM
    if set -q _CLEANUP_CALLED
        return
    end
    set -g _CLEANUP_CALLED 1

    echo -e "\n[🛡️ Cleanup] 执行环境清理..."
    sudo pkill -9 fio 2>/dev/null
    sudo pkill -SIGINT -f "chameleon.out" 2>/dev/null
    sleep 1.5
    sudo pkill -9 -f "chameleon.out" 2>/dev/null
    
    if test -d $CGROUP_DIR
        sudo rmdir $CGROUP_DIR 2>/dev/null
    end
    echo " └─ ✅ 环境已净化。"
    exit 0
end

# ==========================================
# 1. 环境初始化
# ==========================================
echo "🚀 [Init] 准备测试环境..."
echo 0 | sudo tee /sys/kernel/mm/lru_gen/enabled > /dev/null
echo " ├─ 禁用 MGLRU 成功"

if not test -f $TEST_FILE
    echo " ├─ 正在生成测试文件 ($FILE_SIZE)..."
    fio --name=prep --filename=$TEST_FILE --rw=write --size=$FILE_SIZE --bs=1M > /dev/null 2>&1
end

# 准备 Cgroup
if test -d $CGROUP_DIR; sudo rmdir $CGROUP_DIR 2>/dev/null; end
sudo mkdir -p $CGROUP_DIR
echo $MEM_HIGH | sudo tee $CGROUP_DIR/memory.high > /dev/null
echo $MEM_MAX | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo 0 | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null 2>/dev/null
echo " └─ Cgroup 设置完毕 (High: $MEM_HIGH, Max: $MEM_MAX)"

# ==========================================
# 2. 收集 MRU 正样本 (大范围顺序扫描)
# ==========================================
echo "\n========================================"
echo "🎯 [Phase 1] 收集大文件顺序扫描数据 (Label: MRU)"
echo "========================================"
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

echo " ├─ 启动 Chameleon (输出至 $CSV_MRU)..."
# 注意：由于我们在代码里把日志打到了 stderr，标准输出只有纯净的 CSV
sudo $CML_BIN -c $CGROUP_DIR > $CSV_MRU &
sleep 2

echo " ├─ 启动 FIO 顺序读负载..."
# 用 fish 的 block 将 FIO 放入 cgroup 运行
fish -c "echo %self | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null; exec fio --name=scan_test --filename=$TEST_FILE --rw=read --size=$FILE_SIZE --bs=4k --ioengine=sync --direct=0 > /dev/null"

echo " ├─ FIO 顺序读完成，正在落盘..."
sudo pkill -SIGINT -f "chameleon.out"
sleep 2 

# ==========================================
# 3. 收集 LRU 负样本 (Zipfian 局部热点随机读)
# ==========================================
echo "\n========================================"
echo "🎯 [Phase 2] 收集带热点的随机读数据 (Label: LRU)"
echo "========================================"
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null

echo " ├─ 启动 Chameleon (输出至 $CSV_LRU)..."
sudo $CML_BIN -c $CGROUP_DIR > $CSV_LRU &
sleep 2

echo " ├─ 启动 FIO 随机读负载 (持续 120 秒)..."
# 使用 time_based 跑满 120 秒，确保收集到足够多的稳态特征
fish -c "echo %self | sudo tee $CGROUP_DIR/cgroup.procs > /dev/null; exec fio --name=rand_test --filename=$TEST_FILE --rw=randread --size=$FILE_SIZE --bs=4k --ioengine=sync --direct=0 --random_distribution=zipf:1.2 --time_based --runtime=120 > /dev/null"

echo " ├─ FIO 随机读完成，正在落盘..."
sudo pkill -SIGINT -f "chameleon.out"
sleep 2

# ==========================================
# 4. 结束
# ==========================================
echo "\n🎉 [Done] 数据收集完成！"
echo " ├─ 扫描特征已保存至: $CSV_MRU"
echo " └─ 随机特征已保存至: $CSV_LRU"

# 显式调用清理钩子
handle_exit