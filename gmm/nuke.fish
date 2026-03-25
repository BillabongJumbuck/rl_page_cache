#!/usr/bin/env fish
# clean_env.fish - 绝对安全的终极物理清理脚本 (针对 eBPF + AI Agent 环境)

echo "============================================"
echo "  [1/4] 切断所有上层负载与 AI Agent 大脑"
echo "============================================"
sudo pkill -9 -f data_collect.fish 2>/dev/null
sudo pkill -9 -f fio_loop.fish 2>/dev/null
sudo pkill -9 fio 2>/dev/null
sudo pkill -9 -f online_agent.py 2>/dev/null
sleep 1

echo "============================================"
echo "  [2/4] 拔除底层 eBPF 探针与 C 数据收集器"
echo "============================================"
sudo pkill -9 -f data_collector.out 2>/dev/null
sudo pkill -9 -f chameleon 2>/dev/null

# 死等底层 C 收集器彻底释放文件句柄
while pgrep -f data_collector.out > /dev/null; sleep 0.2; end
sleep 1

echo "============================================"
echo "  [3/4] 焚毁 eBPF 幽灵挂载点与 Cgroup 牢笼"
echo "============================================"
# 最核心的一步：清理 eBPF Pinned Maps，防止下次报 RingBuffer 占用错误
sudo rm -f /sys/fs/bpf/cml_* 2>/dev/null

echo "============================================"
echo "  [4/4] 执行安全核爆 (清空物理机 Page Cache)"
echo "============================================"
sudo sync
echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
sleep 1


echo "✅ 系统已完全净化！eBPF 探针已拔除，内存已归零。随时可以进行下一轮 Eval 测试。"