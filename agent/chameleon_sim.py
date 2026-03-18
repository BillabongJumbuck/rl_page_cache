class ChameleonCache:
    def __init__(self, capacity, p_access, p_direction, p_threshold, p_survival, p_ghost, debug=False):
        self.capacity = capacity
        self.p_access = p_access
        self.p_direction = p_direction
        self.p_threshold = p_threshold
        self.p_survival = p_survival
        self.p_ghost = p_ghost
        self.debug = debug
        
        self.cache_list = []      # 物理主链表 (索引 0 为 Head/最新, 末尾为 Tail/最老)
        self.metadata = {}        # 页面元数据 (得分)
        self.ghost_history = set()# 幽灵历史记录
        self.hits = 0
        self.misses = 0

    def log(self, msg):
        if self.debug:
            print(f"  [DEBUG] {msg}")

    def print_state(self):
        if self.debug:
            # 格式化输出: [Head(新) -> ... -> Tail(老)]
            state_str = [f"Page:{p}(Score:{self.metadata.get(p, 0)})" for p in self.cache_list]
            print(f"  [STATE] Cache: [{', '.join(state_str)}] | Ghosts: {self.ghost_history}\n")

    def access_page(self, page_id):
        self.log(f"========== 接入页面 {page_id} ==========")
        if page_id in self.metadata:
            self.hits += 1
            old_score = self.metadata[page_id]
            
            # 【命中】更新得分
            if self.p_access == 1:
                self.metadata[page_id] = 1
            elif self.p_access == 2:
                self.metadata[page_id] += 1
                
            self.log(f"HIT! 得分更新: {old_score} -> {self.metadata[page_id]}")
        else:
            self.misses += 1
            self.log(f"MISS! 准备读入内存...")
            
            # 【未命中】检查是否需要驱逐
            if len(self.cache_list) >= self.capacity:
                self._evict()
            
            # 插入物理链表头部 (Head)
            self.cache_list.insert(0, page_id)
            
            # 检查幽灵历史
            if self.p_ghost == 1 and page_id in self.ghost_history:
                self.metadata[page_id] = 2 # Refault! 给予初始高分保护
                self.ghost_history.remove(page_id)
                self.log(f"GHOST HIT! 幽灵归来，跳过新手期，初始得分 = 2")
            else:
                self.metadata[page_id] = 0
                self.log(f"纯新页面，初始得分 = 0")
                
        self.print_state()

    def _evict(self):
        self.log(f"触发驱逐! 当前容量满载 ({self.capacity}/{self.capacity})")
        
        while True: # 模拟 eBPF 中防止活锁的多次扫描
            if not self.cache_list:
                return

            # 决定扫描方向
            scan_indices = range(len(self.cache_list) - 1, -1, -1) if self.p_direction == 0 else range(len(self.cache_list))
            direction_str = "尾部(Tail) -> 头部(Head)" if self.p_direction == 0 else "头部(Head) -> 尾部(Tail)"
            self.log(f"--- 开启扫描 ({direction_str}) ---")

            for i in scan_indices:
                page = self.cache_list[i]
                score = self.metadata[page]

                self.log(f"-> 检查 Page {page} (得分: {score}, 免死阈值: {self.p_threshold})")

                if score > self.p_threshold:
                    # 【免死降级】
                    if self.p_access == 1:
                        self.metadata[page] = 0
                    elif self.p_access == 2:
                        self.metadata[page] -= 1
                    
                    self.log(f"   [免死] 扣减得分 -> {self.metadata[page]}")

                    # 【走位判定】
                    if self.p_survival == 1:
                        self.cache_list.pop(i)
                        self.cache_list.insert(0, page)
                        self.log(f"   [走位: Requeue] 摘下页面 {page}，重新排到 Head 保护区!")
                        break # 链表结构已改变，打断 for 循环，重新开启 while 扫描
                    else:
                        self.log(f"   [走位: Stay] 原地不动，迭代器继续扫下一个...")
                        pass 
                else:
                    # 【斩杀】
                    victim = self.cache_list.pop(i)
                    del self.metadata[victim]
                    self.log(f"   [斩杀] 无情驱逐 Page {victim}!")
                    
                    # 【幽灵记录】
                    if self.p_ghost == 1:
                        self.ghost_history.add(victim)
                        self.log(f"   [幽灵] Page {victim} 的灵魂已记入 Ghost Map。")
                    return