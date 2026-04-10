#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

#define TRACK_DEPTH 4
#define BATCH_SIZE 1024

enum policy_type {
    POLICY_LRU = 0,
    POLICY_MRU = 1,
};

static u64 main_list; 

// ==========================================
// 2. 状态存储 (Data Plane): Task Storage
// 恢复无敌的 Per-Thread 隔离，消除所有的累加锁！
// ==========================================
struct thread_stat_accumulator {
    u32 access_count;
    u32 seq_count;
    u64 stride_sum; 
    u64 last_mapping;
    u64 last_index;
    u64 last_mappings[TRACK_DEPTH];
    u64 last_indexes[TRACK_DEPTH];
    u32 current_policy;
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

// 极速状态记录：Task Storage 无锁累加
static __always_inline void record_access(struct task_struct *task, u32 tid, u64 mapping, u64 index) {
    struct thread_stat_accumulator init_acc = { .current_policy = POLICY_LRU };
    struct thread_stat_accumulator *acc = bpf_task_storage_get(&stat_storage, task, &init_acc, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!acc) return;

    acc->access_count++;

    if (acc->last_mapping == mapping) {
        s64 diff = (s64)index - (s64)acc->last_index;
        acc->stride_sum += (diff < 0) ? -diff : diff;
    }
    acc->last_mapping = mapping;
    acc->last_index = index;

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

    // 🌟 核心修改：每 128 次访问做一次内核态就地裁决
    if ((acc->access_count & 0x7F) == 0 && acc->access_count > 0) {
        // 判断 seq_count / access_count > 0.8
        // 为了避免浮点运算，转换为整数乘法：seq_count * 10 > access_count * 8
        if (acc->seq_count * 10 > acc->access_count * 8) {
            acc->current_policy = POLICY_MRU;
        } else {
            acc->current_policy = POLICY_LRU;
        }
        // 测试：强行把策略切换到 MRU，看看效果
        // acc->current_policy = POLICY_LRU;
    }

    // RingBuffer 发送逻辑保持不变，依然可以给你的用户态发数据做日志/未来 AI 训练用
    if (acc->access_count >= BATCH_SIZE) {
        struct feature_event *event = bpf_ringbuf_reserve(&feature_ringbuf, sizeof(*event), 0);
        if (event) {
            event->tid = tid;
            event->seq_count = acc->seq_count;
            event->stride_sum = acc->stride_sum;
            bpf_ringbuf_submit(event, 0);
        }
        // 重置计数器，准备下一个统计周期
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
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    u64 raw_tick = bpf_ktime_get_ns();
    
    if ((raw_tick & 0x7) == 0) {
        record_access(task, tid, (u64)mapping, index);
    }

    struct thread_stat_accumulator *acc = bpf_task_storage_get(&stat_storage, task, 0, 0);
    if (acc && acc->current_policy == POLICY_MRU) {
        bpf_cache_ext_list_add_batched(main_list, folio);
    }
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    struct task_struct *task = bpf_get_current_task_btf();
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct address_space *mapping = BPF_CORE_READ(folio, mapping);
    u64 index = (u64)BPF_CORE_READ(folio, index);
    u64 raw_tick = bpf_ktime_get_ns();
    
    // 每 8 次采样 1 次
    if ((raw_tick & 0x7) == 0) {
        record_access(task, tid, (u64)mapping, index);
    }

    // 🌟 极速无锁读取：直接从 Task Storage 拿策略
    struct thread_stat_accumulator *acc = bpf_task_storage_get(&stat_storage, task, 0, 0);
    if (acc && acc->current_policy == POLICY_MRU) {
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