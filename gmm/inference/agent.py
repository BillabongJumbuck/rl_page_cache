import lightgbm as lgb
import numpy as np
import ctypes
import os
import sys
import time

# ==========================================
# 🌟 身份识别：线程名缓存字典
# ==========================================
tid_comm_cache = {}

def get_thread_name(tid: int) -> str:
    if tid in tid_comm_cache:
        return tid_comm_cache[tid]
    try:
        with open(f"/proc/{tid}/comm", "r") as f:
            comm = f.read().strip()
            tid_comm_cache[tid] = comm
            return comm
    except Exception:
        tid_comm_cache[tid] = "unknown"
        return "unknown"

print("🧠 [1/3] Loading LightGBM Model (No-IOPS Ablation Version)...")
try:
    bst = lgb.Booster(model_file='/home/messidor/rl_page_cache/gmm/chameleon_model_no_iops.txt')
except Exception as e:
    print(f"❌ Failed to load model: {e}")
    sys.exit(1)

# ==========================================
# 🌟 高级技巧：直接通过 libbpf 操作 eBPF Map
# ==========================================
print("🔗 [2/3] Binding to libbpf for zero-overhead Map updates...")
try:
    libbpf = ctypes.CDLL("libbpf.so.1", use_errno=True)
except OSError:
    try:
        libbpf = ctypes.CDLL("libbpf.so.0", use_errno=True)
    except OSError:
        print("❌ Could not find libbpf.so. Please ensure libbpf is installed.")
        sys.exit(1)

bpf_obj_get = libbpf.bpf_obj_get
bpf_obj_get.argtypes = [ctypes.c_char_p]
bpf_obj_get.restype = ctypes.c_int

bpf_map_update_elem = libbpf.bpf_map_update_elem
bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
bpf_map_update_elem.restype = ctypes.c_int

MAP_PATH = "/sys/fs/bpf/chameleon/ai_policy_map"

print(f"⏳ Waiting for Data Plane to pin eBPF map at {MAP_PATH}...")
map_fd = -1
max_retries = 20
for _ in range(max_retries):
    if os.path.exists(MAP_PATH):
        map_fd = bpf_obj_get(MAP_PATH.encode('utf-8'))
        if map_fd >= 0:
            break
    time.sleep(0.5)

if map_fd < 0:
    print(f"❌ Failed to open pinned map after waiting. Is chameleon.out running?")
    sys.exit(1)

print("✅ eBPF Map successfully bounded!")

def update_kernel_policy(tid: int, policy: int):
    c_key = ctypes.c_uint32(tid)
    c_val = ctypes.c_uint32(policy)
    ret = bpf_map_update_elem(map_fd, ctypes.byref(c_key), ctypes.byref(c_val), 0)
    if ret != 0:
        print(f"⚠️ Failed to update policy for TID {tid}")

# ==========================================
# 🌟 数据面对接：通过标准输入(stdin)接收遥测流
# ==========================================
policy_names = ["LRU", "MRU"]

print("\n🤖 AI Agent is now actively managing Page Cache Polices (Decoupled Mode)!\n")
print("TID-aware policy control enabled (low-overhead mode).")

last_policy_by_tid = {}
tid_prob_ema = {}   # 🌟 必须初始化 EMA 状态字典
tid_seen_events = {}

# 更快响应在线负载切换：先快后稳。
ALPHA_WARMUP = 0.20
ALPHA_STEADY = 0.05
WARMUP_EVENTS = 8
ENTER_MRU_TH = 0.70
EXIT_MRU_TH = 0.35

events_total = 0
updates_total = 0
window_events = 0
window_updates = 0
window_start_ts = time.time()

tid_window_stats = {}
tid_last_seen = {}
SUMMARY_INTERVAL_SEC = float(os.getenv("CHAMELEON_TID_SUMMARY_INTERVAL", "10"))
IDLE_TID_TTL_SEC = 15.0
summary_last_ts = time.time()
ENABLE_TID_SUMMARY = os.getenv("CHAMELEON_TID_SUMMARY", "0") == "1"
STATS_INTERVAL_SEC = float(os.getenv("CHAMELEON_AGENT_STATS_INTERVAL", "5"))

def maybe_print_stats(now_ts: float):
    global window_events, window_updates, window_start_ts
    if now_ts - window_start_ts < STATS_INTERVAL_SEC:
        return
    dt = now_ts - window_start_ts
    eps = window_events / dt
    ups = window_updates / dt
    print(
        f"[stats] events={events_total} updates={updates_total} "
        f"active_tids={len(last_policy_by_tid)} eps={eps:.0f} ups={ups:.1f}"
    )
    window_events = 0
    window_updates = 0
    window_start_ts = now_ts

def update_tid_window(tid: int, raw_prob: float, smoothed_prob: float,
                      seq_ratio: float, avg_stride: float, uniq_ratio: float,
                      now_ts: float):
    ws = tid_window_stats.get(tid)
    if ws is None:
        ws = {
            "count": 0,
            "raw_sum": 0.0,
            "smooth_sum": 0.0,
            "seq_sum": 0.0,
            "stride_sum": 0.0,
            "uniq_sum": 0.0,
        }
        tid_window_stats[tid] = ws

    ws["count"] += 1
    ws["raw_sum"] += raw_prob
    ws["smooth_sum"] += smoothed_prob
    ws["seq_sum"] += seq_ratio
    ws["stride_sum"] += avg_stride
    ws["uniq_sum"] += uniq_ratio
    tid_last_seen[tid] = now_ts

def maybe_print_tid_summary(now_ts: float):
    global summary_last_ts
    if not ENABLE_TID_SUMMARY:
        return

    if now_ts - summary_last_ts < SUMMARY_INTERVAL_SEC:
        return

    # 清理长期消失的 tid
    dead_tids = [tid for tid, ts in tid_last_seen.items() if now_ts - ts > IDLE_TID_TTL_SEC]
    for tid in dead_tids:
        tid_last_seen.pop(tid, None)
        tid_window_stats.pop(tid, None)
        tid_prob_ema.pop(tid, None)
        tid_seen_events.pop(tid, None)

    rows = []
    for tid, ws in tid_window_stats.items():
        c = ws["count"]
        if c <= 0:
            continue
        comm = get_thread_name(tid)
        rows.append((
            c,
            f"[tid-summary] tid={tid}({comm}) n={c} "
            f"raw={ws['raw_sum']/c:.2f} smooth={ws['smooth_sum']/c:.2f} "
            f"seq={ws['seq_sum']/c:.2f} stride={ws['stride_sum']/c:.1f} uniq={ws['uniq_sum']/c:.2f} "
            f"policy={policy_names[last_policy_by_tid.get(tid, 0)]}"
        ))

    rows.sort(key=lambda x: x[0], reverse=True)
    for _, line in rows[:6]:
        print(line)

    # 重置窗口，进入下一统计周期
    for ws in tid_window_stats.values():
        ws["count"] = 0
        ws["raw_sum"] = 0.0
        ws["smooth_sum"] = 0.0
        ws["seq_sum"] = 0.0
        ws["stride_sum"] = 0.0
        ws["uniq_sum"] = 0.0

    summary_last_ts = now_ts

try:
    while True:
        line = sys.stdin.readline()
        
        # 读不到数据说明管道断开了 (EOF)，退出循环
        if not line:
            break
            
        line = line.strip()
        if line.startswith("TID") or not line:
            continue
        
        try:
            parts = line.split(',')
            if len(parts) < 5:
                continue
                
            tid = int(parts[0])
            iops = float(parts[1])
            seq_ratio = float(parts[2])
            avg_stride = float(parts[3])
            uniq_ratio = float(parts[4])

            x = np.array([[seq_ratio, avg_stride, uniq_ratio]], dtype=np.float32)
            
            # 🌟 提取原始预测概率
            raw_prob = bst.predict(x)[0]
            
            # 🌟 核心防御：指数移动平均 (EMA) 滤波器计算
            seen = tid_seen_events.get(tid, 0) + 1
            tid_seen_events[tid] = seen
            alpha = ALPHA_WARMUP if seen <= WARMUP_EVENTS else ALPHA_STEADY

            if tid not in tid_prob_ema:
                tid_prob_ema[tid] = raw_prob
            else:
                tid_prob_ema[tid] = alpha * raw_prob + (1.0 - alpha) * tid_prob_ema[tid]
            
            smoothed_prob = tid_prob_ema[tid]
            
            # 🌟 施密特触发器：用平滑后的概率做迟滞判断
            last_policy = last_policy_by_tid.get(tid)
            
            if last_policy is None:
                # 首次观测到该线程时，直接用当前平滑概率给出初始策略。
                policy = 1 if smoothed_prob > ENTER_MRU_TH else 0
            else:
                if last_policy == 0:
                    # LRU -> MRU: 有明显扫描特征时尽快切换
                    policy = 1 if smoothed_prob > ENTER_MRU_TH else 0
                else:
                    # MRU -> LRU: 仅在扫描特征明显消失后回切
                    policy = 0 if smoothed_prob < EXIT_MRU_TH else 1

            events_total += 1
            window_events += 1
            now_ts = time.time()
            update_tid_window(tid, raw_prob, smoothed_prob, seq_ratio, avg_stride, uniq_ratio, now_ts)

            # 首次看到该线程就记录，避免“长期默认 LRU 但日志完全不可见”。
            if last_policy is None:
                update_kernel_policy(tid, policy)
                last_policy_by_tid[tid] = policy
                updates_total += 1
                window_updates += 1
                
                comm = get_thread_name(tid)
                print(f"[init] tid={tid}({comm}) policy={policy_names[policy]} "
                      f"raw={raw_prob:.2f} smoothed={smoothed_prob:.2f} "
                      f"seq={seq_ratio:.2f} stride={avg_stride:.1f}")

            # 🌟 当 Policy 发生翻转时，调用 eBPF 更新内核并打印日志
            elif last_policy != policy:
                update_kernel_policy(tid, policy)
                last_policy_by_tid[tid] = policy
                updates_total += 1
                window_updates += 1
                
                comm = get_thread_name(tid)
                print(f"[switch] tid={tid}({comm}) policy={policy_names[policy]} "
                      f"raw={raw_prob:.2f} smoothed={smoothed_prob:.2f} "
                      f"seq={seq_ratio:.2f} stride={avg_stride:.1f}")

            maybe_print_stats(now_ts)
            maybe_print_tid_summary(now_ts)

        except Exception as e:
            print(f"⚠️ Pipeline Error: {e}", file=sys.stderr)
            continue

except KeyboardInterrupt:
    print("\n🛑 AI Agent shutting down naturally...")
finally:
    if map_fd >= 0:
        os.close(map_fd)