#!/usr/bin/env fish
# debug_extractor.fish - 变色龙 Extractor 单元测试流水线

echo "============================================"
echo "  [1/4] 编译最新的 BPF 探针 (极度重要)"
echo "============================================"
cd ~/rl_page_cache/bpf
make
cd ~/rl_page_cache/agent

echo "============================================"
echo "  [2/4] 清理并建立测试专属 Cgroup"
echo "============================================"
set CGROUP "/sys/fs/cgroup/cache_ext_test"
sudo cgdelete -g memory:/cache_ext_test 2>/dev/null
sudo rmdir $CGROUP 2>/dev/null
sudo mkdir -p $CGROUP
echo "2G" | sudo tee $CGROUP/memory.max >/dev/null

echo "============================================"
echo "  [3/4] 唤醒变色龙探针并注入热点流量"
echo "============================================"
# 1. 后台挂载变色龙探针
sudo ../bpf/chameleon.out -c $CGROUP &
set CML_PID (jobs -p)
echo "等待探针挂载..."
sleep 2

# 2. 制造热点潮汐：让创建文件 (dd) 和读取文件 (cat) 都在 Cgroup 内发生！
echo "🔥 正在向 Cgroup 注入热点内存流量 (死循环反复读取 30MB 文件)..."
sudo sh -c "echo \$\$ > $CGROUP/cgroup.procs && \
            dd if=/dev/urandom of=/tmp/test_hot.dat bs=1M count=30 2>/dev/null && \
            while true; do cat /tmp/test_hot.dat > /dev/null; done" &
set LOAD_PID (jobs -p)

# 给 dd 写文件和 cat 死循环一点时间，确保存活的页面分数被加爆
sleep 3

echo "============================================"
echo "  [4/4] 🔬 发射 Extractor 探针采样！"
echo "============================================"
# 注意：如果你的文件在 core 目录下，请改为 uv run core/ebpf_extractor.py
uv run core/ebpf_extractor.py

echo "============================================"
echo "  [清理] 测试结束，打扫战场"
echo "============================================"
sudo kill -9 $CML_PID 2>/dev/null
sudo pkill -9 cache_ext_reuse 2>/dev/null
sudo pkill -9 -f "cat /tmp/test_hot.dat" 2>/dev/null
sudo kill -9 $LOAD_PID 2>/dev/null
sudo rm /tmp/test_hot.dat 2>/dev/null
sudo sync
echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
sleep 1
sudo cgdelete -g memory:/cache_ext_test 2>/dev/null

echo "✅ 调试流水线执行完毕！"