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

// =========================================================================
// Workload 2: 热区 + 偶发全表扫描 (Hotset with Scan Thrashing)
// 预期获胜者：SIEVE (FIFO类)
// 模式：大部分时间在访问一个小热区，中途突然切入一次全表顺序扫描。
// =========================================================================
void workload_scan_thrash(int fd, int cache_pages, int total_file_pages) {
    std::cout << ">>> 执行 Workload 2: 热区+偶发全表扫描 (预期 SIEVE 胜出)" << std::endl;
    std::mt19937 gen(42);
    // 热区只占缓存的 30%
    int hot_zone = cache_pages * 0.3;
    std::uniform_int_distribution<> hot_dist(0, hot_zone);
    char* buf = new char[PAGE_SIZE];

    // 1. 先进行大量热区访问，让所有算法建立热点
    for (int i = 0; i < 200000; i++) {
        pread(fd, buf, PAGE_SIZE, (off_t)hot_dist(gen) * PAGE_SIZE);
    }

    // 2. 突然切入一次洪峰：全表顺序扫描（完全不重复的冷数据）
    for (int i = hot_zone + 1; i < total_file_pages; i++) {
        pread(fd, buf, PAGE_SIZE, (off_t)i * PAGE_SIZE);
    }

    // 3. 扫描过后，立刻恢复热区访问。
    // 如果是 LRU，此时热点已经全军覆没，这部分会全是 Miss。
    // 如果是 SIEVE，刚才的全表扫描不会挤掉热点，这部分依然全是 Hit。
    for (int i = 0; i < 100000; i++) {
        pread(fd, buf, PAGE_SIZE, (off_t)hot_dist(gen) * PAGE_SIZE);
    }
    delete[] buf;
}

// =========================================================================
// Workload 3: 强偏斜频次分布 (Highly Skewed Zipfian)
// 预期获胜者：LFU
// 模式：极端少数页面被极高频访问，其余页面伴随随机散列访问。
// =========================================================================
void workload_zipfian(int fd, int cache_pages, int total_file_pages) {
    std::cout << ">>> 执行 Workload 3: 强偏斜频次分布 (预期 LFU 胜出)" << std::endl;
    std::mt19937 gen(1337);
    // Alpha=1.2 意味着极强的倾斜
    ZipfianGenerator zipf(total_file_pages, 1.2); 
    char* buf = new char[PAGE_SIZE];

    for (int i = 0; i < 500000; i++) {
        int page_idx = zipf.next(gen);
        pread(fd, buf, PAGE_SIZE, (off_t)page_idx * PAGE_SIZE);
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
    else std::cerr << "Unknown workload. Please use wl1, wl2, wl3, or wl4." << std::endl;

    close(fd);
    return 0;
}