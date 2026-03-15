#!/usr/bin/env fish
# AI for OS 自动化训练指挥官 (马拉松装甲版)

echo "============================================"
echo "  [1/4] 申请 Root 权限与战场清理"
echo "============================================"
sudo -v
sudo pkill -9 fio 2>/dev/null
sudo pkill -9 cache_ext_reuse 2>/dev/null
sudo pkill -9 chameleon 2>/dev/null
sudo swapoff -a
mkdir -p /tmp/bpf_test

# 创建专用的训练 Cgroup
set CGROUP_DIR "/sys/fs/cgroup/chameleon_train"
sudo mkdir -p $CGROUP_DIR
echo "2G" | sudo tee $CGROUP_DIR/memory.max >/dev/null
echo "0" | sudo tee $CGROUP_DIR/memory.swap.max >/dev/null


echo "============================================"
echo "  [2/4] 唤醒 eBPF 变色龙双子星"
echo "============================================"
cd ~/rl_page_cache/bpf
sudo ./cache_ext_reuse.out -w /tmp/bpf_test &
sudo ./chameleon.out -w /tmp/bpf_test -c $CGROUP_DIR &
cd ~/rl_page_cache/agent
sleep 2 # 给 libbpf 挂载探针的时间


echo "============================================"
echo "  [3/4] 点火！启动受限的 FIO 潮汐负载"
echo "============================================"
# 巧妙利用 sh -c 将 fio_loop 进程强行塞入刚才建好的 Cgroup 中
sudo sh -c "echo \$\$ > $CGROUP_DIR/cgroup.procs && exec ./workloads/fio_loop.fish" &
set FIO_JOB_PID (jobs -p | tail -n 1)

echo "等待 FIO 潮汐发生器预热..."
sleep 5


echo "============================================"
echo "  [4/4] 唤醒 PPO 神经网络，开启长程闭环训练"
echo "============================================"
uv run train.py


echo "============================================"
echo "  [清理] 训练终止，执行战场打扫"
echo "============================================"
kill $FIO_JOB_PID 2>/dev/null
sudo pkill -9 fio 2>/dev/null
sudo pkill -9 cache_ext_reuse 2>/dev/null
sudo pkill -9 chameleon 2>/dev/null
sudo swapon -a
echo "战场已打扫干净。模型已保存！"