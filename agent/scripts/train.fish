#!/usr/bin/env fish
# AI for OS 自动化训练指挥官 (四策略路由版)

function cleanup_battlefield --on-event fish_exit
    echo -e "\n============================================"
    echo "  [清理] 正在切断负载源与卸载探针..."
    echo "============================================"
    sudo pkill -9 -f fio_loop.fish 2>/dev/null
    sudo pkill -9 fio 2>/dev/null
    
    echo "  [清理] 等待 I/O 彻底平息..."
    sleep 2
    
    echo "  [清理] 正在执行安全核爆 (Drop Caches)..."
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    sleep 2 

    echo "  [清理] 正在安全卸载变色龙探针..."
    sudo pkill -9 chameleon 2>/dev/null
    # 【修改】：已经没有 cache_ext_reuse 了，将其删除

    echo "  [清理] 正在等待 BPF 探针彻底从内核注销..."
    while pgrep -f chameleon > /dev/null; sleep 0.5; end
    sleep 1 
    
    echo "  [清理] 正在焚烧物理牢笼..."
    sudo cgdelete -g memory:/cache_ext_train 2>/dev/null
    sudo rmdir /sys/fs/cgroup/cache_ext_train 2>/dev/null
    
    sudo swapon -a 2>/dev/null
    echo "战场已彻底打扫干净，安全退出！"
end

echo "============================================"
echo "  [1/4] 申请 Root 权限与战场清理"
echo "============================================"
sudo -v

sudo sysctl -w vm.dirty_background_ratio=1 >/dev/null
sudo sysctl -w vm.dirty_ratio=30 >/dev/null

cleanup_battlefield 

mkdir -p /tmp/bpf_test

set CGROUP_DIR "/sys/fs/cgroup/cache_ext_train"
sudo mkdir -p $CGROUP_DIR
echo "200M" | sudo tee $CGROUP_DIR/memory.max >/dev/null # 【关键】：内存限制改为 200M 制造激烈竞争
echo "0" | sudo tee $CGROUP_DIR/memory.swap.max >/dev/null

echo "============================================"
echo "  [2/4] 唤醒 eBPF 变色龙策略路由探针"
echo "============================================"
cd ~/rl_page_cache/bpf
sudo ./chameleon.out -c $CGROUP_DIR &
cd ~/rl_page_cache/agent
sleep 2 

echo "============================================"
echo "  [3/4] 点火！启动乱序 FIO 潮汐负载"
echo "============================================"
# 注意路径是否匹配你的实际结构
sudo sh -c "echo \$\$ > $CGROUP_DIR/cgroup.procs && exec ./workloads/fio_loop.fish" &
echo "等待 FIO 潮汐发生器预热..."
sleep 5

echo "============================================"
echo "  [4/4] 唤醒 PPO 神经网络，开启长程闭环训练"
echo "============================================"
# 使用 uv 启动训练脚本
uv run train.py