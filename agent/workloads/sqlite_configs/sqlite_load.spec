# 对应 nr_entry 和 nr_op
recordcount=40000000
operationcount=40000000

# 对应 value_size: 200 (YCSB 默认有多个字段，我们限制为 1 个 200 字节的字段)
fieldcount=1
fieldlength=200

# 对应 operation_proportion (100% Insert 用于生成数据)
insertproportion=1.0
readproportion=0.0
updateproportion=0.0
scanproportion=0.0

# 对应 request_distribution: "zipfian"
requestdistribution=zipfian
zipfianconst=0.99

# 为了性能，可以开启多线程 (对应 nr_thread: 8)
threadcount=8