#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

#define MB (1024 * 1024)
#define TOTAL_SIZE (1000 * MB) // 总共分配 1000MB
#define HOT_SIZE   (200 * MB)  // 前 200MB 极度活跃 (20%)
#define WARM_SIZE  (300 * MB)  // 接着 300MB 偶尔活跃 (30%)
// 剩下的 500MB 打入冷宫，永远不碰 (50%)

int main() {
    printf("🎯 靶场 PID: %d\n", getpid());
    
    // 强制分配 1000MB 的匿名页
    char *mem = mmap(NULL, TOTAL_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap 失败"); return 1;
    }

    // 初始化：把所有页都写一遍，强制内核分配真正的物理内存 (缺页中断)
    memset(mem, 0, TOTAL_SIZE);
    printf("✅ 1000MB 物理内存已全部分配并驻留。\n");
    printf("🔥 正在持续施加冷热负载...\n");

    int counter = 0;
    while(1) {
        // [Hot 区域]: 每次循环都疯狂写入，保持滚烫
        for(int i = 0; i < HOT_SIZE; i += 4096) mem[i] = 1;

        // [Warm 区域]: 每 10 次循环才写入一次，保持温热
        if (counter % 10 == 0) {
            for(int i = HOT_SIZE; i < HOT_SIZE + WARM_SIZE; i += 4096) mem[i] = 2;
        }

        // [Cold 区域]: 彻底遗忘，让它自然冷却

        counter++;
        usleep(10000); // 稍微休息 10ms，防止把单核 CPU 打满
    }
    return 0;
}