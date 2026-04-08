#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

#define TRACK_DEPTH 4
#define BATCH_SIZE 1000

enum policy_type {
    POLICY_LRU = 0,
    POLICY_MRU = 1,
};

static u64 main_list; 

// ==========================================
// 1. 策略槽：存放用户态 Agent 下发的决策
// ==========================================
struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, u32); // 存储 policy_type
} policy_storage SEC(".maps");

// ==========================================
// 2. 采集槽：暂存当前线程未满 1000 次的访问统计
// ==========================================
struct thread_stat_accumulator {
    u32 access_count;
    u32 seq_count;
    u64 stride_sum; // 简化：只存跨步绝对值的和，方差交由用户态算
    u64 last_mapping;
    u64 last_index;
    u64 last_mappings[TRACK_DEPTH];
    u64 last_indexes[TRACK_DEPTH];
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct thread_stat_accumulator);
} stat_storage SEC(".maps");

// ==========================================
// 3. 通往用户态的单向高速通道
// ==========================================
struct feature_event {
    u32 tid;
    u32 seq_count;
    u64 stride_sum;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} feature_ringbuf SEC(".maps");

// ==========================================
// 核心逻辑
// ==========================================

// 极速获取策略 (无锁，无 Hash Map 查询)
static __always_inline u32 get_thread_policy(struct task_struct *task) {
    u32 *policy = bpf_task_storage_get(&policy_storage, task, 0, 0);
    if (policy) {
        return *policy;
    }
    return POLICY_LRU; // 默认回退到标准 LRU
}

static __always_inline void record_access(struct task_struct *task, u64 mapping, u64 index) {
    struct thread_stat_accumulator init_acc = {};
    struct thread_stat_accumulator *acc = bpf_task_storage_get(&stat_storage, task, &init_acc, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!acc) return;

    acc->access_count++;

    // 1. 计算跨步偏移和 (抛弃除法)
    if (acc->last_mapping == mapping) {
        s64 diff = (s64)index - (s64)acc->last_index;
        acc->stride_sum += (diff < 0) ? -diff : diff;
    }
    acc->last_mapping = mapping;
    acc->last_index = index;

    // 2. 连续性计算
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

    // 3. 满 1000 次批量打包发往用户态
    if (acc->access_count >= BATCH_SIZE) {
        struct feature_event *event = bpf_ringbuf_reserve(&feature_ringbuf, sizeof(*event), 0);
        if (event) {
            event->tid = (u32)bpf_get_current_pid_tgid();
            event->seq_count = acc->seq_count;
            event->stride_sum = acc->stride_sum;
            bpf_ringbuf_submit(event, 0);
        }
        // 重置累加器
        acc->access_count = 0;
        acc->seq_count = 0;
        acc->stride_sum = 0;
    }
}

s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    main_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (main_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {
    struct task_struct *task = bpf_get_current_task_btf();
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    u64 raw_tick = bpf_ktime_get_ns();
    
    // 提升采样率到 1/8，因为纯加法计算极其轻量
    if ((raw_tick & 0x7) == 0) {
        record_access(task, (u64)mapping, index);
    }

    // 毫无负担的策略执行
    if (get_thread_policy(task) == POLICY_MRU) {
        bpf_cache_ext_list_add_batched(main_list, folio);
    }
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    struct task_struct *task = bpf_get_current_task_btf();
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    u64 raw_tick = bpf_ktime_get_ns();
    
    if ((raw_tick & 0x7) == 0) {
        record_access(task, (u64)mapping, index);
    }

    if (get_thread_policy(task) == POLICY_MRU) {
        bpf_cache_ext_list_move_batched(main_list, folio, false); 
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {}

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