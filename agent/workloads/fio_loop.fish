#!/usr/bin/env fish
# 变色龙终极炼狱靶场 V2 (SOSP/OSDI 标准评测版)

set TEST_DIR "/tmp/bpf_test"
set TEST_FILE "$TEST_DIR/test.dat"

mkdir -p $TEST_DIR

if not test -f $TEST_FILE
    echo "[FIO] 正在锻造 5GB 测试基底文件 (这可能需要几十秒)..."
    fio --name=init --filename=$TEST_FILE --rw=write --bs=1M --size=5G --numjobs=1 --direct=0 > /dev/null 2>&1
    
    echo "[FIO] 强行刷盘，排空初始化脏页..."
    sync
    sleep 3
end

echo "[FIO] 炼狱靶场准备完毕，开始注入全谱段混合负载！"

while true
    echo ">>> [阶段 1] OLTP 核心热点 (强 Zipfian 纯读) - 2分钟"
    fio --name=zipf_read --filename=$TEST_FILE --rw=randread --random_distribution=zipf:1.2 --bs=4k --size=5G --runtime=120 --time_based --direct=0 > /dev/null 2>&1

    echo ">>> [阶段 2] 复杂事务交火 (70%读/30%写, 弱 Zipfian) - 2分钟"
    fio --name=oltp_mixed --filename=$TEST_FILE --rw=randrw --rwmixread=70 --random_distribution=zipf:0.8 --bs=8k --size=5G --runtime=120 --time_based --direct=0 > /dev/null 2>&1

    echo ">>> [阶段 3] 洪峰突起 (12 线程极高并发随机扫描) - 30秒"
    # 这里不需要 offset_increment，因为 randread 本就是全盘随机跳跃，考验的是并发下的自旋锁
    fio --name=spike --filename=$TEST_FILE --rw=randread --numjobs=12 --bs=4k --size=5G --runtime=30 --time_based --group_reporting --direct=0 > /dev/null 2>&1

    echo ">>> [阶段 4] 分析型宽表扫描 (4 线程错位并发顺序读) - 1分钟"
    # 【核心改动】：offset_increment=1G，让四辆推土机从四个不同的起点同时发车，制造极其惨烈的 Thrashing！
    fio --name=analytics --filename=$TEST_FILE --rw=read --numjobs=4 --offset_increment=1G --bs=1M --size=5G --runtime=60 --time_based --group_reporting --direct=0 > /dev/null 2>&1

    echo ">>> [阶段 5] 业务长尾期 (无规律稀疏散列) - 1分钟"
    fio --name=tail --filename=$TEST_FILE --rw=randread --bs=16k --size=5G --runtime=60 --time_based --direct=0 > /dev/null 2>&1
end