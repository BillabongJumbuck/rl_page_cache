#!/usr/bin/env fish
# nuke_env.fish - 绝对安全的终极物理清理脚本 (关机或重启前专用)

echo "============================================"
echo "  [1/3] 切断所有可能的 I/O 与 Python 进程"
echo "============================================"
sudo pkill -9 -f fio_loop.fish 2>/dev/null
sudo pkill -9 fio 2>/dev/null
sudo pkill -9 -f env.py 2>/dev/null
sudo pkill -9 -f train.py 2>/dev/null
sleep 1

echo "============================================"
echo "  [2/3] 执行安全核爆 (清理残留 Page Cache)"
echo "============================================"
sudo sync
echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
sleep 2

echo "============================================"
echo "  [3/3] 拔除 eBPF 探针并焚烧物理牢笼"
echo "============================================"
# 1. 杀探针
sudo pkill -9 chameleon 2>/dev/null
sudo pkill -9 cache_ext_reuse 2>/dev/null

# 2. 死等探针进程彻底消失
while pgrep -f chameleon > /dev/null; sleep 0.5; end
while pgrep -f cache_ext_reuse > /dev/null; sleep 0.5; end
sleep 1 

# 3. 删牢笼
sudo cgdelete -g memory:/cache_ext_train 2>/dev/null
sudo rmdir /sys/fs/cgroup/cache_ext_train 2>/dev/null
sudo cgdelete -g memory:/cache_ext_test 2>/dev/null
sudo rmdir /sys/fs/cgroup/cache_ext_test 2>/dev/null

echo "✅ 系统已完全净化！现在可以安全执行 sudo poweroff 了。"