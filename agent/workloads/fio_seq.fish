#!/usr/bin/env fish
# 负载描述: 纯顺序扫描 (Sequential Scan)
# 模拟场景: 数据库全表扫描、大文件读取、夜间备份
# 测试目的: 观察 AI 是否能识别缓存污染，并采取“阅后即焚”策略 (降低免死阈值，快速斩杀)

set TEST_DIR "/tmp/bpf_test"
set TEST_FILE "$TEST_DIR/test.dat"

echo "============================================"
echo "  [Workload] 开始注入纯顺序扫描负载 (60秒)"
echo "============================================"

# 防呆设计：确保基底文件存在
if not test -f $TEST_FILE
    echo ">>> 未找到基底文件，正在快速创建 5G 占位文件..."
    mkdir -p $TEST_DIR
    fio --name=init --filename=$TEST_FILE --rw=write --bs=1M --size=5G --numjobs=1 > /dev/null
end

# 核心压测命令
# --rw=read: 纯顺序读取
# --bs=1M: 大块读取，旨在以最快速度填满并冲刷那 2GB 的 Cgroup 内存限制
# --direct=0: 必须走 Page Cache，否则测试毫无意义
fio --name=seq_scan \
    --filename=$TEST_FILE \
    --rw=read \
    --bs=1M \
    --size=5G \
    --runtime=60 \
    --time_based \
    --direct=0 \
    --group_reporting