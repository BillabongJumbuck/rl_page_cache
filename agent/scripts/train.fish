#!/usr/bin/env fish
# AI for OS 自动化训练指挥官 (马拉松装甲版)

# ==========================================
# 注册终极清理钩子：无视任何意外，强行打扫战场
# ==========================================
function cleanup_battlefield --on-event fish_exit --on-signal SIGINT
    echo -e "\n============================================"
    echo "  [清理] 正在切断负载源与卸载探针..."
    echo "============================================"
    # 1. 致命一击：必须先杀掉产生 fio 的外层循环，阻止其重生！
    sudo pkill -9 -f fio_loop.fish 2>/dev/null
    
    # 2. 再清理残余的 fio 实体
    sudo pkill -9 fio 2>/dev/null
    
    # 3. 卸载内核探针
    sudo pkill -9 cache_ext_reuse 2>/dev/null
    sudo pkill -9 chameleon 2>/dev/null
    
    # 4. 解除物理封锁
    sudo swapon -a 2>/dev/null
    
    echo "战场已彻底打扫干净！"
end

echo "============================================"
echo "  [1/4] 申请 Root 权限与战场清理"
echo "============================================"
sudo -v
# 启动前主动调用一次清理，确保环境绝对纯净
cleanup_battlefield 

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
sudo sh -c "echo \$\$ > $CGROUP_DIR/cgroup.procs && exec ./workloads/fio_loop.fish" &
echo "等待 FIO 潮汐发生器预热..."
sleep 5

echo "============================================"
echo "  [4/4] 唤醒 PPO 神经网络，开启长程闭环训练"
echo "============================================"
cd ~/rl_page_cache/agent
uv run train.py

# ==========================================
# 脚本自然结束时，fish_exit 事件会自动触发 cleanup_battlefield
# 无需在这里重复写清理代码
# ==========================================