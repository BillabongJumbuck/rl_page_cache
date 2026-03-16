#!/usr/bin/env fish
# 变色龙 YCSB 单发精确评测发射器

if test (count $argv) -ne 1
    echo "🚨 用法错误: ./scripts/run_ycsb_single.fish <workload> (例如: a, b, c, d, e, f)"
    exit 1
end

set WL $argv[1]
set CONFIG_FILE "./workloads/ycsb_configs/run_$WL.yaml"
set ORIG_DB "/home/messidor/rl_page_cache/leveldb_data"
set TEMP_DB "/home/messidor/rl_page_cache/leveldb_data_temp"
set YCSB_BIN "./My-YCSB/build/ycsb"
set CGROUP_DIR "/sys/fs/cgroup/chameleon_eval"

# 动态指定大脑的日记本
set -x CHAMELEON_CSV_LOG "logs/ycsb_"$WL"_decisions.csv"
set DAEMON_LOG "logs/daemon_ycsb_$WL.log"

function cleanup_battlefield --on-event fish_exit --on-signal SIGINT
    echo -e "\n============================================"
    echo "  [清理] 正在切断 YCSB 负载与底层探针..."
    echo "============================================"
    sudo pkill -9 -f ycsb 2>/dev/null
    sudo pkill -9 -f inference_daemon.py 2>/dev/null
    sudo pkill -9 cache_ext_reuse 2>/dev/null
    sudo pkill -9 chameleon 2>/dev/null
    sudo swapon -a 2>/dev/null
    
    # 恢复内核脏页默认值，防止影响你日常用电脑
    sudo sysctl -w vm.dirty_background_ratio=10 >/dev/null
    sudo sysctl -w vm.dirty_ratio=20 >/dev/null
    
    echo "🎯 评测完成！AI 决策记录已保存至 $CHAMELEON_CSV_LOG"
    exit 0
end

# 1. 前置防呆检查
if not test -f $CONFIG_FILE
    echo "🚨 找不到配置文件 $CONFIG_FILE，请先创建！"
    exit 1
end
if not test -d $ORIG_DB
    echo "🚨 找不到原始数据库 $ORIG_DB，请先运行 Load 阶段生成数据！"
    exit 1
end

echo "============================================"
echo "  [1/4] 重置靶场：数据克隆与脏页调优"
echo "============================================"
# 核心：确保每次测试的数据都是原汁原味的 20GB！(注意 rsync 源路径末尾的斜杠)
echo ">>> 正在通过 rsync 极速克隆数据库 (这可能需要几十秒)..."
mkdir -p $TEMP_DB
rsync -avpl --delete $ORIG_DB/ $TEMP_DB/ > /dev/null

echo ">>> 正在注入极端的脏页回写参数..."
sudo sysctl -w vm.dirty_background_ratio=1 >/dev/null
sudo sysctl -w vm.dirty_ratio=30 >/dev/null

echo ">>> 清空 Page Cache，还 AI 一个冰冷的起跑线！"
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
sleep 2

echo "============================================"
echo "  [2/4] 构建 Cgroup 物理牢笼并唤醒 eBPF"
echo "============================================"
sudo mkdir -p $CGROUP_DIR
echo "2G" | sudo tee $CGROUP_DIR/memory.max > /dev/null
echo "0" | sudo tee $CGROUP_DIR/memory.swap.max > /dev/null

cd ~/rl_page_cache/bpf
# 【极度关键】：让探针死死盯住 TEMP_DB，绝不是 ORIG_DB！
sudo ./cache_ext_reuse.out -w $TEMP_DB &
sudo ./chameleon.out -w $TEMP_DB -c $CGROUP_DIR &
cd ~/rl_page_cache/agent
sleep 2

echo "============================================"
echo "  [3/4] 唤醒 PPO 大脑，开启上帝视角"
echo "============================================"
# 大脑会读取刚才 set -x 的 CHAMELEON_CSV_LOG 环境变量
uv run eval/inference_daemon.py > $DAEMON_LOG 2>&1 &
sleep 3

echo "============================================"
echo "  [4/4] 释放 YCSB Workload $WL 洪荒巨兽！"
echo "============================================"
# 把 C++ 的 YCSB 强行锁进 2GB 的 Cgroup 牢笼中并执行！
sudo sh -c "echo \$\$ > $CGROUP_DIR/cgroup.procs && exec $YCSB_BIN $CONFIG_FILE"

# ==========================================
# 评测自然结束，fish_exit 会自动触发清理钩子
# ==========================================