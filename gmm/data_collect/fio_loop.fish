#!/usr/bin/env fish
# 变色龙终极炼狱靶场 V3 (随机 Domain Randomization 版)

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

echo "[FIO] 炼狱靶场准备完毕，开始注入全谱段乱序混合负载！"

# 定义可选的阶段
set phases "zipf" "mixed" "spike" "analytics" "tail"

while true
    # 每轮打乱数组顺序
    set shuffled_phases (random choice -n 5 $phases)
    
    for phase in $shuffled_phases
        switch $phase
            case "zipf"
                echo ">>> [乱序] OLTP 核心热点 (强 Zipfian) - 20秒"
                # Runtime 从 120 秒大幅压缩到 20 秒
                fio --name=zipf_read --filename=$TEST_FILE --rw=randread --random_distribution=zipf:1.2 --bs=4k --size=5G --runtime=20 --time_based --direct=0 --fadvise_hint=0 --invalidate=0 > /dev/null 2>&1

            case "mixed"
                echo ">>> [乱序] 复杂事务交火 (70%读/30%写) - 20秒"
                fio --name=oltp_mixed --filename=$TEST_FILE --rw=randrw --rwmixread=70 --random_distribution=zipf:0.8 --bs=8k --size=5G --runtime=20 --time_based --direct=0 --fadvise_hint=0 --invalidate=0 > /dev/null 2>&1

            case "spike"
                echo ">>> [乱序] 洪峰突起 ( 线程并发) - 15秒"
                fio --name=spike --filename=$TEST_FILE --rw=randread --numjobs=1 --bs=4k --size=5G --runtime=15 --time_based --group_reporting --direct=0 --fadvise_hint=0 --invalidate=0 > /dev/null 2>&1

            case "analytics"
                echo ">>> [乱序] 分析型宽表扫描 (重度 Thrashing) - 20秒"
                fio --name=analytics --filename=$TEST_FILE --rw=read --numjobs=1 --offset_increment=1G --bs=1M --size=5G --runtime=20 --time_based --group_reporting --direct=0 --fadvise_hint=0 --invalidate=0 > /dev/null 2>&1

            case "tail"
                echo ">>> [乱序] 业务长尾期 (稀疏散列) - 15秒"
                fio --name=tail --filename=$TEST_FILE --rw=randread --numjobs=1 --bs=16k --size=5G --runtime=15 --time_based --direct=0 --fadvise_hint=0 --invalidate=0 > /dev/null 2>&1
        end
    end
end