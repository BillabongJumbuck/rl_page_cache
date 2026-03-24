#include <iostream>
#include <vector>
#include <random>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <chrono>
#include <algorithm>
#include <thread>
#include <chrono>

const int PAGE_SIZE = 4096;

// Zipfian 生成器 (保持不变)
class ZipfianGenerator {
    std::vector<double> cdf;
public:
    ZipfianGenerator(int n, double alpha) {
        cdf.reserve(n);
        double c = 0.0;
        for (int i = 1; i <= n; i++) {
            c += 1.0 / std::pow(i, alpha);
            cdf.push_back(c);
        }
        for (int i = 0; i < n; i++) {
            cdf[i] /= c;
        }
    }
    int next(std::mt19937& gen) {
        std::uniform_real_distribution<double> dist(0.0, 1.0);
        double u = dist(gen);
        auto it = std::lower_bound(cdf.begin(), cdf.end(), u);
        return std::distance(cdf.begin(), it);
    }
};

// =========================================================================
// Workload 1: 循环扫描 (Looping Access)
// 预期获胜者：MRU
// 模式：反复读取一个刚好比缓存容量大一点点的数据集。
// =========================================================================
void workload_loop(int fd, int cache_pages) {
    std::cout << ">>> 执行 Workload 1: 循环扫描 (预期 MRU 胜出)" << std::endl;
    // 数据集大小为缓存的 110%
    int working_set = cache_pages + (cache_pages / 10); 
    char* buf = new char[PAGE_SIZE];

    for (int iter = 0; iter < 50; iter++) {
        for (int i = 0; i < working_set; i++) {
            pread(fd, buf, PAGE_SIZE, (off_t)i * PAGE_SIZE);
        }
    }
    delete[] buf;
}

void workload_scan_thrash(int fd, int cache_pages, int total_file_pages) {
    std::cout << ">>> 执行 Workload 2: 密集热区+交替冷扫描 (预期 SIEVE 胜出)" << std::endl;
    std::mt19937 gen(42);
    
    // 热区放大到缓存的 90%，如果 LRU 被冲刷，惩罚将极其惨重
    int hot_zone = cache_pages * 0.9;
    std::uniform_int_distribution<> hot_dist(0, hot_zone);
    char* buf = new char[PAGE_SIZE];

    // 进行 10 轮惨烈的攻防战
    for (int round = 0; round < 10; round++) {
        // 1. 密集访问热区，让页面被打上硬件 accessed 标记
        for (int i = 0; i < 50000; i++) {
            pread(fd, buf, PAGE_SIZE, (off_t)hot_dist(gen) * PAGE_SIZE);
        }
        
        // 2. 引入洪峰：每次用一段全新的、2倍于缓存容量的冷数据进行扫描
        int scan_start = hot_zone + 1 + round * (cache_pages * 2);
        int scan_end = scan_start + (cache_pages * 2);
        if (scan_end > total_file_pages) scan_end = total_file_pages; // 防越界
        
        for (int i = scan_start; i < scan_end; i++) {
            pread(fd, buf, PAGE_SIZE, (off_t)i * PAGE_SIZE);
            // 给后台 BPF 留一点点喘息时间
            if (i % 256 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }
    delete[] buf;
}

// =========================================================================
// Workload 3: 强偏斜频次分布 (Highly Skewed Zipfian)
// 预期获胜者：LFU
// 模式：降低一点倾斜度，暴增访问量，使得工作集远远突破缓存。
// =========================================================================
void workload_zipfian(int fd, int cache_pages, int total_file_pages) {
    std::cout << ">>> 执行 Workload 3: 强偏斜频次分布 (预期 LFU 胜出)" << std::endl;
    std::mt19937 gen(1337);
    
    // 只在文件的前 2GB 范围内生成 Zipfian（约 50万个页面）
    // 防止初始化 CDF 数组时耗时过长，同时也保证冷页面足够多来冲击缓存
    int zipf_range = std::min(total_file_pages, 500000);
    // Alpha 设为 0.99，长尾会更厚，必然击穿 200M (51200页) 的缓存
    ZipfianGenerator zipf(zipf_range, 0.99); 
    char* buf = new char[PAGE_SIZE];

    // 访问量暴增到 500 万次
    for (int i = 0; i < 5000000; i++) {
        int page_idx = zipf.next(gen);
        pread(fd, buf, PAGE_SIZE, (off_t)page_idx * PAGE_SIZE);
        
        // 限速防止 Direct Reclaim 绕过 BPF
        if (i % 512 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    delete[] buf;
}

// =========================================================================
// Workload 4: 局部性平移 (Shifting Temporal Locality)
// 预期获胜者：LRU
// 模式：访问热区在文件中不断向后滑动。旧的热数据彻底变冷，新的热数据不断涌现。
// =========================================================================
void workload_shifting(int fd, int cache_pages, int total_file_pages) {
    std::cout << ">>> 执行 Workload 4: 局部性平移 (预期 LRU 胜出)" << std::endl;
    std::mt19937 gen(2026);
    char* buf = new char[PAGE_SIZE];

    // 滑动窗口大小为缓存的 50%
    int window_size = cache_pages / 2;
    int shift_steps = total_file_pages - window_size;

    // 窗口每次向后平移
    for (int step = 0; step < shift_steps; step += window_size / 4) {
        std::uniform_int_distribution<> window_dist(step, step + window_size - 1);
        // 在当前窗口内密集访问
        for (int i = 0; i < 50000; i++) {
            pread(fd, buf, PAGE_SIZE, (off_t)window_dist(gen) * PAGE_SIZE);
        }
    }
    delete[] buf;
}

// =========================================================================
// Workload 5: B-Tree 索引穿透 (B-Tree Index Simulation)
// 预期获胜者：LFU
// 模式：模拟数据库查询。每次查询必经高频的“索引页”，然后落入海量低频的“数据页”。
// =========================================================================
void workload_btree(int fd, int cache_pages, int total_file_pages) {
    std::cout << ">>> 执行 Workload 5: B-Tree 索引穿透 (预期 LFU 胜出)" << std::endl;
    std::mt19937 gen(888);
    char* buf = new char[PAGE_SIZE];

    // 假设文件的前 1000 个 page 是核心索引结构
    int index_pages = std::min(1000, total_file_pages);
    std::uniform_int_distribution<> index_dist(0, index_pages - 1);
    
    // 其余的全是底层海量数据页
    std::uniform_int_distribution<> leaf_dist(index_pages, total_file_pages - 1);

    // 模拟 300 万次数据库穿透查询
    for (int i = 0; i < 3000000; i++) {
        // 1. 查索引：每次查询都需要遍历 3 个高频索引节点
        for (int j = 0; j < 3; j++) {
            pread(fd, buf, PAGE_SIZE, (off_t)index_dist(gen) * PAGE_SIZE);
        }
        // 2. 拿数据：最终读取 1 个大概率极冷的底层数据页
        pread(fd, buf, PAGE_SIZE, (off_t)leaf_dist(gen) * PAGE_SIZE);
        
        // 限速，给 BPF 一点处理时间
        if (i % 1024 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    delete[] buf;
}

int main(int argc, char** argv) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <file_path> <workload: wl1|wl2|wl3|wl4> <cache_size_mb> <file_size_mb>" << std::endl;
        return 1;
    }

    std::string file_path = argv[1];
    std::string mode = argv[2];
    int cache_pages = std::stoi(argv[3]) * 1024 * 1024 / PAGE_SIZE;
    int total_pages = std::stoi(argv[4]) * 1024 * 1024 / PAGE_SIZE;

    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        return 1;
    }
    // 禁用预读，确保我们的算法能真实反映在 I/O 上
    posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM);

    if (mode == "wl1") workload_loop(fd, cache_pages);
    else if (mode == "wl2") workload_scan_thrash(fd, cache_pages, total_pages);
    else if (mode == "wl3") workload_zipfian(fd, cache_pages, total_pages);
    else if (mode == "wl4") workload_shifting(fd, cache_pages, total_pages);
    else if (mode == "wl5") workload_btree(fd, cache_pages, total_pages);
    else std::cerr << "Unknown workload. Please use wl1, wl2, wl3, or wl4." << std::endl;

    close(fd);
    return 0;
}