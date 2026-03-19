#!/usr/bin/env fish
# AI for OS 自动化训练指挥官 (马拉松装甲版)

# ==========================================
# 注册终极清理钩子：无视任何意外，强行打扫战场
# ==========================================
function cleanup_battlefield --on-event fish_exit
    echo -e "\n============================================"
    echo "  [清理] 正在切断负载源与卸载探针..."
    echo "============================================"
    # 1. 切断新页面的产生源头
    sudo pkill -9 -f fio_loop.fish 2>/dev/null
    sudo pkill -9 fio 2>/dev/null
    
    echo "  [清理] 等待 I/O 彻底平息..."
    sleep 2
    
    # 2. 【绝对核心保命操作】：在探针存活时，清空所有残留页面！
    echo "  [清理] 正在执行安全核爆 (Drop Caches)..."
    sudo sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches >/dev/null
    
    # 等待一小会儿，确保内核 Evictor 把双向链表拆解干净
    sleep 2 

    # 3. 此时物理内存已打扫干净，可以安全销毁探针了
    echo "  [清理] 正在安全卸载变色龙及重用探针..."
    sudo pkill -9 chameleon 2>/dev/null
    sudo pkill -9 cache_ext_reuse 2>/dev/null  # <== 【新增】顺手杀死微观提取器

    echo "  [清理] 正在等待 BPF 探针彻底从内核注销..."
    while pgrep -f chameleon > /dev/null; sleep 0.5; end
    while pgrep -f cache_ext_reuse > /dev/null; sleep 0.5; end
    sleep 1 # 额外留 1 秒给内核彻底回收数据结构
    
    # 4. 【致命补枪】：把僵尸 Cgroup 连根拔起！防止下次扫盘死机！
    echo "  [清理] 正在焚烧物理牢笼..."
    sudo cgdelete -g memory:/cache_ext_train 2>/dev/null
    sudo rmdir /sys/fs/cgroup/cache_ext_train 2>/dev/null
    
    # 5. 解除物理封锁
    sudo swapon -a 2>/dev/null
    
    echo "战场已彻底打扫干净，安全退出！"
end

echo "============================================"
echo "  [1/4] 申请 Root 权限与战场清理"
echo "============================================"
sudo -v

# 【新增】：设置激进的脏页回写策略，防止 I/O 延迟尖刺干扰 RL 的 Reward 信号！
echo "  [系统调优] 设置脏页后台刷盘水位至 1% (平滑 I/O 曲线)..."
sudo sysctl -w vm.dirty_background_ratio=1 >/dev/null
sudo sysctl -w vm.dirty_ratio=30 >/dev/null


# 启动前主动调用一次清理，确保环境绝对纯净
cleanup_battlefield 

mkdir -p /tmp/bpf_test

# 创建专用的训练 Cgroup
set CGROUP_DIR "/sys/fs/cgroup/cache_ext_train"
sudo mkdir -p $CGROUP_DIR
echo "2G" | sudo tee $CGROUP_DIR/memory.max >/dev/null
echo "0" | sudo tee $CGROUP_DIR/memory.swap.max >/dev/null


echo "============================================"
echo "  [2/4] 唤醒 eBPF 变色龙双子星"
echo "============================================"
cd ~/rl_page_cache/bpf
sudo ./chameleon.out -c $CGROUP_DIR &
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