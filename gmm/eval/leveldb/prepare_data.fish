#!/usr/bin/env fish
# prepare_data.fish

set YCSB_BIN "/home/messidor/YCSB-cpp/ycsb"
set DB_PATH "/home/messidor/db_data"
set RECORD_COUNT 5000000

echo "[System] 🧹 正在清理旧数据库..."
rm -rf $DB_PATH && mkdir -p $DB_PATH

echo "[Load] 🚜 开始锻造 5GB YCSB 基底数据 (约 500 万条记录)..."
$YCSB_BIN -load -db leveldb -P /home/messidor/YCSB-cpp/workloads/workloada -p leveldb.dbname=$DB_PATH -p recordcount=$RECORD_COUNT -p threadcount=1

echo "✅ 数据装载完成！"