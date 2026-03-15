#!/usr/bin/env fish
# 变色龙终极炼狱靶场 V2：混合真实业务场景

set TEST_DIR "/tmp/bpf_test"
set TEST_FILE "$TEST_DIR/test.dat"

mkdir -p $TEST_DIR

if not test -f $TEST_FILE
    echo "[FIO] 正在锻造 5GB 测试基底文件 (这可能需要几十秒)..."
    fio --name=init --filename=$TEST_FILE --rw=write --bs=1M --size=5G --numjobs=1 > /dev/null
end

echo "[FIO] 炼狱靶场准备完毕，开始注入全谱段混合负载！"

while true
    echo ">>> [阶段 1] OLTP 核心热点 (强 Zipfian 纯读) - 2分钟"
    # 最经典的数据库缓存命中场景。必须开启精准追踪和保护。
    fio --name=zipf_read --filename=$TEST_FILE --rw=randread --random_distribution=zipf:1.2 --bs=4k --size=5G --runtime=120 --time_based > /dev/null

    echo ">>> [阶段 2] 复杂事务交火 (70%读/30%写, 弱 Zipfian) - 2分钟"
    # 极其残酷的考验！引入了脏页 (Dirty Pages)。写操作会触发内核的 writeback 线程。
    # AI 必须学会在系统脏页水位升高时，调整淘汰策略，避免因为等 IO 锁死。
    fio --name=oltp_mixed --filename=$TEST_FILE --rw=randrw --rwmixread=70 --random_distribution=zipf:0.8 --bs=8k --size=5G --runtime=120 --time_based > /dev/null

    echo ">>> [阶段 3] 洪峰突起 (16 线程极高并发随机扫描) - 30秒"
    # 模拟双十一秒杀或突发流量。瞬间拉起 16 个线程无差别轰炸 Page Cache。
    # 原生 LRU 极易在这里发生自旋锁竞争。AI 必须学会降级策略以释放 CPU 压力。
    fio --name=spike --filename=$TEST_FILE --rw=randread --numjobs=16 --bs=4k --size=5G --runtime=30 --time_based --group_reporting > /dev/null

    echo ">>> [阶段 4] 分析型宽表扫描 (4 线程并发顺序读) - 1分钟"
    # 极其恶劣的缓存污染源。并发的顺序大块读取会瞬间填满 2GB 内存。
    # AI 必须立刻反应过来，将新页面的免死金牌收回，防止阶段 1/2 的热数据被冲刷。
    fio --name=analytics --filename=$TEST_FILE --rw=read --numjobs=4 --bs=1M --size=5G --runtime=60 --time_based --group_reporting > /dev/null

    echo ">>> [阶段 5] 业务长尾期 (无规律散列散列) - 1分钟"
    # 夜深人静，极其稀疏的随机访问。考验 AI 是否懂得“节能”——关闭幽灵表等昂贵策略。
    fio --name=tail --filename=$TEST_FILE --rw=randread --bs=16k --size=5G --runtime=60 --time_based > /dev/null
end