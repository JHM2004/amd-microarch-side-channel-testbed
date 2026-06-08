/**
 * spy.h
 * DES Flush+Reload Attack - 攻击模块头文件
 * 
 * 提供侧信道攻击相关的函数声明
 */

#ifndef SPY_H
#define SPY_H

#include <stdint.h>
#include <stdbool.h>
#include "des.h"

// 全局变量声明
extern uint64_t g_threshold;
extern SBox *g_sboxes;

// 攻击主函数 - 返回是否成功恢复密钥
bool attack_des_full(uint64_t key);

// 密钥重建测试
bool test_key_reconstruction();

// 第一轮攻击
void first_round_attack(uint32_t R, uint64_t K, int *cache_row_hits, int round_num);

// 从S-box条目推导K1片段
uint8_t derive_k1_fragment(int sbox, int entry_index, uint64_t E_R0);

// 缓存操作函数（内联汇编实现）
static inline uint64_t rdtsc();
static inline void flush_cache_line(const void *addr);
static inline uint64_t measure_time_single(const void *addr);
static inline uint64_t measure_time(const void *addr);

// 时间戳计数器
static inline uint64_t rdtsc() {
    uint64_t a, d;
#ifdef __has_builtin
    #if __has_builtin(__builtin_ia32_rdtscp)
        uint32_t aux;
        __builtin_ia32_rdtscp(&aux);
        asm volatile ("rdtsc" : "=a"(a), "=d"(d));
    #else
        asm volatile ("mfence\nlfence\nrdtsc" : "=a"(a), "=d"(d));
    #endif
#else
    asm volatile ("mfence\nlfence\nrdtsc" : "=a"(a), "=d"(d));
#endif
    return (d << 32) | a;
}

// Flush缓存行
static inline void flush_cache_line(const void *addr) {
    asm volatile ("clflush 0(%0)" :: "r"(addr) : "memory");
    asm volatile ("mfence" ::: "memory");
}

// 单次测量访问时间
static inline uint64_t measure_time_single(const void *addr) {
    uint64_t start, end;
    volatile uint32_t val;
    
    asm volatile ("mfence\nlfence" ::: "memory");
    start = rdtsc();
    
    asm volatile (
        "movl (%1), %0\n"
        : "=r" (val)
        : "r" (addr)
        : "memory"
    );
    
    asm volatile ("lfence" ::: "memory");
    end = rdtsc();
    return end - start;
}

// 多次测量取最小值
static inline uint64_t measure_time(const void *addr) {
    uint64_t min_time = ~0ULL;
    for (int i = 0; i < 3; i++) {
        uint64_t t = measure_time_single(addr);
        if (t < min_time) min_time = t;
    }
    return min_time;
}

#endif /* SPY_H */
