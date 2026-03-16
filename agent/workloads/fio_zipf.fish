#!/usr/bin/env fish
# 负载描述: Zipfian 高偏斜随机读 (Zipfian Random Read)
# 模拟场景: 核心关系型数据库 (MySQL/PostgreSQL) 缓存命中池、Redis 热点查询、YCSB-C 纯读负载
# 测试目的: 观察 AI 能否敏锐察觉“时间局部性”的回归，重新开启幽灵表 (p_ghost=1) 并拉高免死门槛保护热数据。

set TEST_DIR "/tmp/bpf_test"
set TEST_FILE "$TEST_DIR/test.dat"

echo "============================================"
echo "  [Workload] 开始注入 Zipfian 核心热点负载 (60秒)"
echo "============================================"

# 防呆设计：确保基底文件存在
if not test -f $TEST_FILE
    echo ">>> 未找到基底文件，正在快速创建 5G 占位文件..."
    mkdir -p $TEST_DIR
    fio --name=init --filename=$TEST_FILE --rw=write --bs=1M --size=5G --numjobs=1 > /dev/null
end

# 核心压测命令
# --rw=randread: 随机读取
# --random_distribution=zipf:1.2: 极其关键！注入高达 1.2 偏斜度的 Zipfian 分布
# --bs=4k: 模拟真实的数据库 4KB/8KB 页访问
# --direct=0: 必须走 Page Cache
fio --name=zipf_hotspot \
    --filename=$TEST_FILE \
    --rw=randread \
    --random_distribution=zipf:1.2 \
    --bs=4k \
    --size=5G \
    --runtime=60 \
    --time_based \
    --direct=0 \
    --group_reporting