// chameleon.bpf.c: eBPF 程序部分，负责核心逻辑和数据结构定义
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

#define DATA_COLLECT // 🌟 开启数据收集功能，方便用户态训练和分析

#define TRACK_DEPTH 4
#define HISTORY_DEPTH 8 // 用于近似计算 unique pages
#define BATCH_SIZE 512
#define SKIP_SIZE 4096
#define MRU_PROTECTED_HEAD_FOLIOS 8
#define MRU_MOVE_SAMPLE_MASK 0x7

enum policy_type {
    POLICY_LRU = 0,
    POLICY_MRU = 1,
};

static u64 main_list; 

enum runtime_stat_idx {
    STAT_MRU_ADD = 0,
    STAT_MRU_MOVE = 1,
    STAT_MRU_EVICT = 2,
    STAT_TOTAL_EVICT = 3,
    STAT_POLICY_SYNC = 4,
    STAT_POLICY_MISS = 5,
};

struct runtime_stats {
    u64 counters[6];
};

// ==========================================
// 1. AI 决策下发表 (Control Plane)
// 用户态 LightGBM 算出结果后，写回这个 Map
// ==========================================
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);   // tid
    __type(value, u32); // policy_type
} ai_policy_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct runtime_stats);
} runtime_stats_map SEC(".maps");

// ==========================================
// 2. 状态存储 (Data Plane): Task Storage
// ==========================================
struct thread_stat_accumulator {
    u32 access_count;
    u32 seq_count;
    u64 stride_sum; 
    
    // 新增特征所需状态
    u64 start_time_ns;
    u32 unique_pages;
    u64 history_mappings[HISTORY_DEPTH];
    u64 history_indexes[HISTORY_DEPTH];
    u8  history_idx;

    u64 last_mapping;
    u64 last_index;
    u64 last_mappings[TRACK_DEPTH];
    u64 last_indexes[TRACK_DEPTH];
    
    u32 current_policy; // 缓存 AI 的决策，避免每次都查 Hash Map
    u32 skip_count;
    u32 mru_touch_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct thread_stat_accumulator);
} stat_storage SEC(".maps");

// ==========================================
// 3. 通往用户态的高速通道 (Data Collection)
// ==========================================
struct feature_event {
    u32 tid;
    u32 access_count; // 通常等于 BATCH_SIZE
    u32 seq_count;
    u32 unique_pages;
    u64 stride_sum;
    u64 duration_ns;  // 耗时，用于用户态计算 IOPS
};

#ifdef DATA_COLLECT
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} feature_ringbuf SEC(".maps");
#endif

// ==========================================
// 核心逻辑
// ==========================================

static __always_inline void bump_stat(enum runtime_stat_idx idx) {
    u32 key = 0;
    struct runtime_stats *s = bpf_map_lookup_elem(&runtime_stats_map, &key);
    if (!s) {
        return;
    }
    if (idx >= 0 && idx < 6) {
        s->counters[idx]++;
    }
}

static __always_inline void record_access(struct task_struct *task, u32 tid, u64 mapping, u64 index) {
    struct thread_stat_accumulator init_acc = { .current_policy = POLICY_LRU, .skip_count = 0 };
    struct thread_stat_accumulator *acc = bpf_task_storage_get(&stat_storage, task, &init_acc, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!acc) return;

    // 🌟 1. 极速过滤：如果还在休眠期，直接跳过所有复杂的特征提取！
    if (acc->skip_count > 0) {
        acc->skip_count--;
        return;
    }

    u64 now_ns = bpf_ktime_get_ns();
    if (acc->access_count == 0) {
        acc->start_time_ns = now_ns;
    }

    acc->access_count++;

    // 1. 计算 Stride
    if (acc->last_mapping == mapping) {
        s64 diff = (s64)index - (s64)acc->last_index;
        acc->stride_sum += (diff < 0) ? -diff : diff;
    }
    acc->last_mapping = mapping;
    acc->last_index = index;

    // 2. 估算 Unique Pages (mapping + index 联合去重，避免跨文件 index 冲突)
    bool is_unique = true;
    #pragma unroll
    for (int i = 0; i < HISTORY_DEPTH; i++) {
        if (acc->history_mappings[i] == mapping &&
            acc->history_indexes[i] == index) {
            is_unique = false;
            break;
        }
    }
    if (is_unique) {
        acc->unique_pages++;
    }
    acc->history_mappings[acc->history_idx & (HISTORY_DEPTH - 1)] = mapping;
    acc->history_indexes[acc->history_idx & (HISTORY_DEPTH - 1)] = index;
    acc->history_idx++;

    // 3. 计算 Seq Count
    bool is_seq = false;
    #pragma unroll
    for (int i = 0; i < TRACK_DEPTH; i++) {
        if (acc->last_mappings[i] == mapping) {
            u64 diff = index - acc->last_indexes[i];
            if (diff > 0 && diff <= 512) {
                acc->seq_count++;
                is_seq = true;
            }
            acc->last_indexes[i] = index; 
            break;
        }
    }
    
    if (!is_seq) {
        int replace_idx = acc->access_count & (TRACK_DEPTH - 1); 
        acc->last_mappings[replace_idx] = mapping;
        acc->last_indexes[replace_idx] = index;
    }

    // 4. Batch 结束：发送特征 & 更新 AI 策略
    if (acc->access_count >= BATCH_SIZE) {
        u64 duration = now_ns - acc->start_time_ns;

#ifdef DATA_COLLECT
        struct feature_event *event = bpf_ringbuf_reserve(&feature_ringbuf, sizeof(*event), 0);
        if (event) {
            event->tid = tid;
            event->access_count = acc->access_count; // 依然是 256
            event->seq_count = acc->seq_count;
            event->stride_sum = acc->stride_sum;
            event->unique_pages = acc->unique_pages;
            
            // 🌟 这里的 duration 是这 256 次访问的真实耗时
            // 因此 Python 端算出的 IOPS = 256 / duration，这是极其精准的“瞬时 IOPS”，毫无失真！
            event->duration_ns = duration; 
            bpf_ringbuf_submit(event, 0);
        }
#endif
        // 🌟 策略同步：从 Hash Map 拉取用户态 AI 的最新决策，缓存到本地
        u32 *ai_policy = bpf_map_lookup_elem(&ai_policy_map, &tid);
        if (ai_policy) {
            acc->current_policy = *ai_policy;
            bump_stat(STAT_POLICY_SYNC);
        } else {
            // 如果用户态还没来得及下发（或者进程刚启动），保守回退到 LRU。
            acc->current_policy = POLICY_LRU;
            bump_stat(STAT_POLICY_MISS);
        }

        // 重置计数器
        acc->access_count = 0;
        acc->seq_count = 0;
        acc->stride_sum = 0;
        acc->unique_pages = 0;

        acc->skip_count = SKIP_SIZE;
    }
}

// ==========================================
// Hook 点保持极速
// ==========================================

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (task->flags & 0x00200000) {
        return; 
    }

    struct thread_stat_accumulator *acc = bpf_task_storage_get(&stat_storage, task, 0, 0);
    if (acc && acc->current_policy == POLICY_MRU) {
        bpf_cache_ext_list_add_batched(main_list, folio);
        bump_stat(STAT_MRU_ADD);
    }
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    struct task_struct *task = bpf_get_current_task_btf();
    if (task->flags & 0x00200000) {
        return;
    }
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    
    record_access(task, tid, (u64)mapping, index);

    struct thread_stat_accumulator *acc = bpf_task_storage_get(&stat_storage, task, 0, 0);
    if (acc && acc->current_policy == POLICY_MRU) {
        // 对 move 做抽样，保留时序信息同时降低热路径回调开销。
        acc->mru_touch_count++;
        if ((acc->mru_touch_count & MRU_MOVE_SAMPLE_MASK) == 0) {
            bpf_cache_ext_list_move_batched(main_list, folio, false);
            bump_stat(STAT_MRU_MOVE);
        }
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    // 保持链表与实际页生命周期一致，避免陈旧节点影响回收质量。
    bpf_cache_ext_list_del(folio);
    bump_stat(STAT_TOTAL_EVICT);
}

static int evict_mru_cb(int idx, struct cache_ext_list_node *a) {
    if (!a || !a->folio) return CACHE_EXT_CONTINUE_ITER;

    bool uptodate = folio_test_uptodate(a->folio);
    bool lru = folio_test_lru(a->folio);
    bool dirty = folio_test_dirty(a->folio);
    bool writeback = folio_test_writeback(a->folio);
    bool locked = folio_test_locked(a->folio);

    if (locked || writeback || dirty || !uptodate || !lru) {
        return CACHE_EXT_CONTINUE_ITER;
    }

    // 头部保护区：避免误伤刚被访问的热页。
    if (idx < MRU_PROTECTED_HEAD_FOLIOS) {
        return CACHE_EXT_CONTINUE_ITER;
    }

    bump_stat(STAT_MRU_EVICT);
    return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    bpf_cache_ext_list_iterate(memcg, main_list, evict_mru_cb, eviction_ctx);
}

SEC(".struct_ops.link")
struct cache_ext_ops chameleon_ops = {
    .init = (void *)chameleon_init,
    .evict_folios = (void *)chameleon_evict_folios,
    .folio_accessed = (void *)chameleon_folio_accessed,
    .folio_evicted = (void *)chameleon_folio_evicted,
    .folio_added = (void *)chameleon_folio_added,
};