#!/usr/bin/env fish
# debug_env.fish - ChameleonEnv 强化学习沙盒集成测试

set CGROUP "/sys/fs/cgroup/cache_ext_train"

echo "============================================"
echo "  [1/3] 建立训练 Cgroup 并启动变色龙探针"
echo "============================================"
sudo cgdelete -g memory:/cache_ext_train 2>/dev/null
sudo rmdir $CGROUP 2>/dev/null
sudo mkdir -p $CGROUP
echo "2G" | sudo tee $CGROUP/memory.max >/dev/null

# 启动底层探针
sudo ../bpf/chameleon.out -c $CGROUP &
set CML_PID (jobs -p)
echo "等待 eBPF 探针注入内核空间..."
sleep 2

echo "============================================"
echo "  [2/3] 🧪 发射！运行 env.py 测试桩"
echo "============================================"
# 注意：如果你的 env.py 在 core 文件夹里，请改成 uv run core/env.py
uv run python -m core.env

echo "============================================"
echo "  [3/3] 打扫战场"
echo "============================================"
sudo kill -9 $CML_PID 2>/dev/null
sudo pkill -9 cache_ext_reuse 2>/dev/null
echo "  [清理] 正在等待 BPF 探针彻底从内核注销..."
while pgrep -f chameleon > /dev/null; sleep 0.5; end
while pgrep -f cache_ext_reuse > /dev/null; sleep 0.5; end
sleep 1 # 额外留 1 秒给内核彻底回收数据结构
sudo cgdelete -g memory:/cache_ext_train 2>/dev/null

echo "✅ 环境集成测试完毕！"