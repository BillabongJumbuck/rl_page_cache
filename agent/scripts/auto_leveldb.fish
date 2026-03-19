#!/usr/bin/env fish
# auto_leveldb.fish - 变色龙 AI vs Linux LRU 全量评测矩阵自动化脚本

# 定义测试矩阵
set workloads a b c d e f
set policies lru cml
set num_runs 3

echo "🚀 开始全量自动化评测矩阵 (LevelDB YCSB A-F)..."
echo "预估总测试次数: "(math (count $workloads) \* (count $policies) \* $num_runs)" 次"
echo "=================================================="
cd /home/messidor/rl_page_cache/agent || exit 1

# 1. 外层循环：遍历 Workload (A -> F)
for w in $workloads
    # 2. 中层循环：遍历 Policy (先 lru，后 cml)
    for p in $policies
        # 3. 内层循环：每个组合运行 3 次
        for i in (seq $num_runs)
            echo ""
            echo "▶▶▶ [进度指示] 正在执行: Workload [$w] | Policy [$p] | 轮次: $i/3"
            echo "▶▶▶ 执行命令: uv run eval/bench_leveldb.py -w $w -p $p"
            
            # 发射评测命令
            uv run eval/bench_leveldb.py -w $w -p $p
            
            # 检查命令是否因为 OOM 或其他原因崩溃
            if test $status -ne 0
                echo "❌ 致命错误: 压测在 Workload $w, Policy $p (第 $i 次) 崩溃了！"
                echo "⚠️ 自动化脚本已强行中止，请检查 dmesg 或日志。"
                exit 1
            end
            
            # 每次测试之间强制深呼吸 5 秒，让内核脏页刷完，内存彻底回收
            echo "⏳ 单次测试完成，系统深呼吸 5 秒..."
            sleep 5
        end
    end
end

echo ""
echo "🎉 太棒了！所有的 LevelDB 评测任务已经全部圆满完成！"
echo "📂 快去 /home/messidor/rl_page_cache/agent/eval/output 目录下查看你的战利品吧！"