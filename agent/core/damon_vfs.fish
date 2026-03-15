#!/usr/bin/env fish
# 直接读写 VFS 操控 DAMON 的终极脚本

if test (count $argv) -lt 3
    echo "用法: sudo ./damon_vfs.fish <PID> <持续秒数> <输出文件>"
    exit 1
end

set TARGET_PID $argv[1]
set DURATION $argv[2]
set OUTPUT_FILE $argv[3]

# 定义内核 VFS 路径
set DAMON_ADMIN "/sys/kernel/mm/damon/admin"
set FTRACE_DIR "/sys/kernel/debug/tracing"

echo "[1/4] 清理战场，重置 DAMON 和 ftrace..."
# 1. 停止现有的 kdamond 并清空实例
echo off | sudo tee $DAMON_ADMIN/kdamonds/0/state > /dev/null 2>&1
echo 0 | sudo tee $DAMON_ADMIN/kdamonds/nr_kdamonds > /dev/null

# 2. 清空 ftrace 缓冲区并关闭追踪
echo 0 | sudo tee $FTRACE_DIR/tracing_on > /dev/null
echo | sudo tee $FTRACE_DIR/trace > /dev/null


echo "[2/4] 通过 sysfs 构建 DAMON 控制平面..."
# 1. 创建 1 个 kdamond 线程 (内核会自动生成 kdamonds/0 目录)
echo 1 | sudo tee $DAMON_ADMIN/kdamonds/nr_kdamonds > /dev/null

# 2. 为它创建 1 个 context (上下文)
echo 1 | sudo tee $DAMON_ADMIN/kdamonds/0/contexts/nr_contexts > /dev/null

# 3. 指定监控类型为虚拟内存 (vaddr)
echo vaddr | sudo tee $DAMON_ADMIN/kdamonds/0/contexts/0/operations > /dev/null

# 4. 创建 1 个监控目标，并绑定 PID
echo 1 | sudo tee $DAMON_ADMIN/kdamonds/0/contexts/0/targets/nr_targets > /dev/null
echo $TARGET_PID | sudo tee $DAMON_ADMIN/kdamonds/0/contexts/0/targets/0/pid_target > /dev/null


echo "[3/4] 开启 ftrace 数据泵，点火运行！"
# 1. 订阅 damon_aggregated 事件
echo 1 | sudo tee $FTRACE_DIR/events/damon/damon_aggregated/enable > /dev/null

# 2. 打开 ftrace 总闸
echo 1 | sudo tee $FTRACE_DIR/tracing_on > /dev/null

# 3. 启动 DAMON 线程！
echo on | sudo tee $DAMON_ADMIN/kdamonds/0/state > /dev/null

# 强化学习的物理时间推移
echo ">>> 系统采样中，让子弹飞 $DURATION 秒..."
sleep $DURATION

# 4. 刹车！关闭 DAMON 和 ftrace
echo off | sudo tee $DAMON_ADMIN/kdamonds/0/state > /dev/null
echo 0 | sudo tee $FTRACE_DIR/tracing_on > /dev/null
echo 0 | sudo tee $FTRACE_DIR/events/damon/damon_aggregated/enable > /dev/null


echo "[4/4] 数据提取完成，写入 $OUTPUT_FILE"
# 将 ftrace 缓冲区里积攒的纯文本数据直接导出来
sudo cat $FTRACE_DIR/trace > $OUTPUT_FILE

echo "大功告成！"