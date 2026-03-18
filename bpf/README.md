RL Page Cache: Chameleon & Reuse Tracker
本项目基于 SOSP '25 的 cache_ext 框架，旨在利用强化学习（RL）在 Linux 内核侧实现智能的 Page Cache 驱逐策略。

为了实现极低的系统开销和高度的灵活性，系统被彻底解耦为两个核心组件，均基于 cgroup v2 实现精确的工作负载隔离：

Chameleon (Policy): 运行在内核态的 eBPF 策略执行器，负责拦截页面缓存的生命周期，并根据用户态（RL Agent）下发的参数决定页面的去留。

Reuse Tracker (Telemetry): 运行在内核态的 eBPF 遥测探针，负责无侵入地监控目标 cgroup 的页面访问流，实时计算并输出重用距离（Reuse Distance），作为强化学习环境的 Reward 信号。

🛠️ 环境要求
操作系统：带有 cache_ext 补丁的 Linux Kernel (>= v6.6.8)

挂载并启用的 cgroup v2 (/sys/fs/cgroup)

编译工具链：clang (>= 14), bpftool, libbpf-dev

开发环境推荐：VS Code + C/C++ 插件

🚀 快速编译
在项目根目录下，直接使用 make 构建所有 BPF 目标文件及用户态加载器：

代码段
make clean
make all
编译成功后，将生成两个核心可执行文件：chameleon.out 和 cache_ext_reuse.out。

📖 使用指南
测试或运行本框架时，我们需要先建立隔离环境，然后分别启动策略和监控，最后将目标工作负载注入该环境。

1. 准备 cgroup 隔离环境
首先，创建一个专门用于测试的 cgroup 节点。

代码段
# 创建测试用的 cgroup 节点
sudo mkdir -p /sys/fs/cgroup/cache_test
2. 启动 Chameleon (变色龙策略执行器)
Chameleon 将接管目标 cgroup 的 Page Cache 驱逐权。在终端 1 中运行：

代码段
sudo ./chameleon.out -c /sys/fs/cgroup/cache_test
预期输出: Chameleon Policy successfully attached to cgroup!
(此时 Chameleon 处于静默拦截状态，等待 Python Agent 注入参数)

3. 启动 Reuse Tracker (重用距离遥测)
Reuse Tracker 将附着于同一个 cgroup，并在后台采集数据。在终端 2 中运行：

代码段
sudo ./cache_ext_reuse.out -c /sys/fs/cgroup/cache_test
预期输出: Reuse Tracker attached to cgroup_id: <ID>，随后系统将以 1Hz 的频率向标准输出（stdout）打印 JSON 格式的遥测数据流。

4. 注入工作负载 (Workload)
在终端 3 中，将当前的 shell 进程（例如你的 fish shell）加入到我们创建的 cgroup 中：

代码段
# 将当前 fish shell 加入 cgroup
echo $fish_pid | sudo tee /sys/fs/cgroup/cache_test/cgroup.procs

# 验证加入成功
cat /sys/fs/cgroup/cache_test/cgroup.procs
此后，该终端内执行的所有 I/O 操作（如使用 dd 生成文件，或编译代码）所产生的页面缓存，都将被 Chameleon 和 Reuse Tracker 共同管理与监控。

📊 数据管道与 RL 对接 (WIP)
本系统的设计初衷是与 Python 编写的 RL Agent 进行交互。

State & Reward (Data Out):
cache_ext_reuse.out 会持续输出如下格式的 JSON 数据：

JSON
{"count": 3930, "sum": 4447826, "sum_sq": 7103401990, "seq": 5195}
count: 发生重用的页面总次数。

sum: 重用距离（Reuse Distance）的总和。

sum_sq: 重用距离的平方和（可用于计算方差）。

seq: 全局内存访问的逻辑时钟序号。
RL Agent 可以通过 subprocess 管道读取这些数据，计算出 Reward（如平均重用距离）。

Action (Data In):
Chameleon 在内核中维护了一个 BPF_MAP_TYPE_ARRAY 类型的参数表（cml_params_map）。RL Agent 推理出新的策略后，可直接使用 Python 的 ebpf 相关库或调用 C 接口，向该 Map 的 index 0 写入最新的决策权重，Chameleon 将在下一次缺页中断时立即应用新策略。

📝 调试建议
如果需要临时修改代码或排查配置，建议在服务器终端直接使用 vim 编辑代码并重新 make。注意不要使用 nano，以免破坏代码的缩进和格式。