// chameleon.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "cache_ext_lib.bpf.h"

char _license[] SEC("license") = "GPL";

// 【重定义动作空间】与 Python 端 5 维动作保持物理结构对齐
struct rl_params {
    __u32 p_access;         // 0=关闭, 1=二元, 2=累加计分
    __u32 p_protected_pct;  // 热链表占比百分比 (原 p_direction，0~100)
    __u32 p_promote_thresh; // 晋升门槛 (原 p_threshold)
    __u32 p_ghost;          // 幽灵表开关 (0=关闭, 1=开启)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rl_params);
} cml_params_map SEC(".maps");

// 【双子星架构】
static u64 probation_list; // 冷链表 (考察期，新页面的出生地)
static u64 protected_list; // 热链表 (保护区，神圣不可侵犯)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4000000); 
    __type(key, __u64); 
    __type(value, u32); // 【关键优化】必须改为 u32，以支持内核原子操作
} folio_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH); 
    __uint(max_entries, 1000000); 
    __type(key, __u64);
    __type(value, u8);
} ghost_map SEC(".maps");


s32 BPF_STRUCT_OPS_SLEEPABLE(chameleon_init, struct mem_cgroup *memcg) {
    // 实例化双链表
    probation_list = bpf_cache_ext_ds_registry_new_list(memcg);
    protected_list = bpf_cache_ext_ds_registry_new_list(memcg);
    if (probation_list == 0 || protected_list == 0) return -1;
    return 0;
}

void BPF_STRUCT_OPS(chameleon_folio_added, struct folio *folio) {

    // 【调试】获取当前进程的 PID 和 Cgroup ID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    u64 cg_id = bpf_get_current_cgroup_id();
    
    // 强制打印，不带任何 if 过滤
    bpf_printk("CML_DEBUG: Added folio %p, PID: %u, CG_ID: %llu\n", folio, pid, cg_id);
    
    // 1. 所有新数据，无脑进入冷链表 (Probation List)
    bpf_cache_ext_list_add(probation_list, folio); 

    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return;

    __u64 key = (__u64)folio;
    u32 initial_score = 0;

    // 2. 幽灵判定
    if (params->p_ghost == 1) {
        u8 *ghost = bpf_map_lookup_elem(&ghost_map, &key);
        if (ghost) {
            // 如果是幽灵回归，赋予初始高分，下一次访问直接保送热链表
            initial_score = params->p_promote_thresh ? params->p_promote_thresh : 1; 
            bpf_map_delete_elem(&ghost_map, &key); 
        }
    }
    bpf_map_update_elem(&folio_meta_map, &key, &initial_score, BPF_ANY);
}

void BPF_STRUCT_OPS(chameleon_folio_accessed, struct folio *folio) {
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params || params->p_access == 0) return;

    __u64 key = (__u64)folio;
    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);
    if (!score) return; 

    // 1. 原子计分 (彻底杜绝 8 线程并发压测下的脏写)
    if (params->p_access > 0) {
        __sync_fetch_and_add(score, 1);
    }

    // 2. 晋升判定 (O(1) 跨链表物理转移)
    // 注意：哪怕它已经在热链表了，只要分数达标，我们也会把它拉回热链表的头部（续命）
    if (*score >= params->p_promote_thresh) {
        bpf_cache_ext_list_move(protected_list, folio, false);
        *score = 0; // 重置分数，防止溢出
    }
}

void BPF_STRUCT_OPS(chameleon_folio_evicted, struct folio *folio) {
    __u64 key = (__u64)folio;
    bpf_map_delete_elem(&folio_meta_map, &key);
}

static int bpf_chameleon_evict_cb(int idx, struct cache_ext_list_node *a) {
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio)) return CACHE_EXT_CONTINUE_ITER;
    if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio)) return CACHE_EXT_CONTINUE_ITER;

    // 在双链表架构中，这里扫到的全部都是冷数据（考察失败的页面）
    // 因此无需再做纠结的降级判定，直接无情斩杀！
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    if (!params) return CACHE_EXT_EVICT_NODE;

    __u64 key = (__u64)a->folio;
    u32 *score = bpf_map_lookup_elem(&folio_meta_map, &key);

    // 【上帝之眼降临】：主动去查硬件 PTE 是否被偷偷访问过！
    int hw_refs = bpf_folio_check_referenced(a->folio);
    
    if (hw_refs > 0) {
        // 抓到你了！mmap 在硬件层偷偷摸了这个页面
        if (score) {
            __sync_fetch_and_add(score, hw_refs); // 把漏掉的分数补上
        } else {
            u32 init_score = hw_refs;
            bpf_map_update_elem(&folio_meta_map, &key, &init_score, BPF_ANY);
        }
        // 既然刚刚被访问过，直接免死一次，留在内存里！
        return CACHE_EXT_CONTINUE_ITER; 
    }

    // 留下幽灵印记
    if (params->p_ghost == 1) {
        u8 dummy = 1;
        bpf_map_update_elem(&ghost_map, &key, &dummy, BPF_ANY);
    }
    return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(chameleon_evict_folios, struct cache_ext_eviction_ctx *eviction_ctx, struct mem_cgroup *memcg) {
    __u32 param_key = 0;
    struct rl_params *params = bpf_map_lookup_elem(&cml_params_map, &param_key);
    
    // --- 宏观调控：热链表超载降级机制 ---
    if (params) {
        u64 ratio = params->p_protected_pct;
        // 防呆设计：兼容旧的 0/1 动作空间，将其映射为 30% 或 70% 的占比
        if (ratio == 0) ratio = 30;
        else if (ratio == 1) ratio = 70;
        else if (ratio > 100) ratio = 50; 

        u64 prob_len = bpf_cache_ext_list_length(memcg, probation_list);
        u64 prot_len = bpf_cache_ext_list_length(memcg, protected_list);
        u64 total = prob_len + prot_len;

        if (total > 0) {
            u64 max_prot = (total * ratio) / 100;
            if (prot_len > max_prot) {
                u32 batch = prot_len - max_prot;
                // 单次最多批量降级 1024 个页面，防止 eBPF 长时间加锁触发 Watchdog 报警
                if (batch > 1024) batch = 1024;
                bpf_cache_ext_list_demote_batch(memcg, protected_list, probation_list, batch);
            }
        }
    }

    // --- 极速扫描驱逐 ---
    // 1. 优先只扫冷链表！(热点数据完美躲避了昂贵的遍历)
    bpf_cache_ext_list_iterate(memcg, probation_list, bpf_chameleon_evict_cb, eviction_ctx);
    
    // 2. 兜底防御：如果冷链表里全是不准驱逐的脏页，才去扫热链表（极其罕见，但能防止 OOM 崩溃）
    if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict) {
        bpf_cache_ext_list_iterate(memcg, protected_list, bpf_chameleon_evict_cb, eviction_ctx);
    }
}

SEC(".struct_ops.link")
struct cache_ext_ops chameleon_ops = {
    .init = (void *)chameleon_init,
    .evict_folios = (void *)chameleon_evict_folios,
    .folio_accessed = (void *)chameleon_folio_accessed,
    .folio_evicted = (void *)chameleon_folio_evicted,
    .folio_added = (void *)chameleon_folio_added,
};