/**
 * utils.h - 缓存攻击工具函数
 * 
 * 提供Flush+Reload攻击所需的底层工具函数：
 * - 时间测量（rdtsc）
 * - 缓存操作（flush, measure）
 * - 阈值校准
 * - CPU核心绑定
 */

#ifndef UTILS_H
#define UTILS_H

#define _GNU_SOURCE
#include <stdint.h>
#include <sched.h>

// ==================== 时间测量 ====================

/**
 * rdtsc() - 读取时间戳计数器
 * 返回：当前CPU时钟周期数
 * 
 * 使用rdtsc指令读取CPU的64位时间戳计数器
 * 用于高精度时间测量
 */
static inline uint64_t rdtsc(void) {
    uint64_t a, d;
    asm volatile ("rdtsc" : "=a" (a), "=d" (d));
    return (d << 32) | a;
}

// ==================== 缓存操作 ====================

/**
 * flush_cache_line() - 刷新缓存行
 * @addr: 要刷新的内存地址
 * 
 * 使用clflush指令将指定地址所在的缓存行从所有级别的缓存中移除
 * 这是Flush+Reload攻击的核心操作
 */
static inline void flush_cache_line(const void *addr) {
    asm volatile ("clflush 0(%0)" :: "r" (addr) : "memory");
}

/**
 * measure_time_single() - 测量单次内存访问时间
 * @addr: 要访问的内存地址
 * 返回：访问时间（CPU周期数）
 * 
 * 使用rdtsc测量一次内存读取的时间
 * 时间短 = 缓存命中
 * 时间长 = 缓存未命中
 */
static inline uint64_t measure_time_single(const void *addr) {
    uint64_t t1, t2;
    volatile uint32_t val;
    
    t1 = rdtsc();
    asm volatile ("lfence" ::: "memory");
    val = *(volatile uint32_t*)addr;
    asm volatile ("lfence" ::: "memory");
    t2 = rdtsc();
    
    (void)val;
    return t2 - t1;
}

// ==================== 辅助函数 ====================

/**
 * sort_uint64_array() - 对uint64数组排序
 * @arr: 数组指针
 * @n: 数组长度
 * 
 * 使用冒泡排序，用于校准阈值时对时间数组排序
 */
static inline void sort_uint64_array(uint64_t *arr, int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = i + 1; j < n; j++) {
            if (arr[i] > arr[j]) {
                uint64_t tmp = arr[i];
                arr[i] = arr[j];
                arr[j] = tmp;
            }
        }
    }
}

/**
 * calibrate_cache_threshold() - 校准缓存阈值
 * @test_addr: 测试地址（需要是可访问的内存地址）
 * @median_hit: 输出缓存命中时间中位数
 * @median_miss: 输出缓存未命中时间中位数
 * 返回：阈值 = (median_hit + median_miss) / 2
 * 
 * 原理：
 * 1. 测量100次缓存命中时间（先访问，数据在缓存中）
 * 2. 测量100次缓存未命中时间（先刷新，数据不在缓存中）
 * 3. 取中位数，阈值 = (hit_median + miss_median) / 2
 */
static inline uint64_t calibrate_cache_threshold(void *test_addr, 
                                                  uint64_t *median_hit, 
                                                  uint64_t *median_miss) {
    #define CALIB_SAMPLES 10000
    static uint64_t hit_times[CALIB_SAMPLES], miss_times[CALIB_SAMPLES];
    
    for (int i = 0; i < CALIB_SAMPLES; i++) {
        volatile uint32_t val = *(volatile uint32_t*)test_addr;
        (void)val;
        asm volatile ("mfence; lfence" ::: "memory");
        hit_times[i] = measure_time_single(test_addr);
        
        flush_cache_line(test_addr);
        asm volatile ("mfence" ::: "memory");
        for (volatile int j = 0; j < 400; j++);
        miss_times[i] = measure_time_single(test_addr);
    }
    
    sort_uint64_array(hit_times, CALIB_SAMPLES);
    sort_uint64_array(miss_times, CALIB_SAMPLES);
    
    *median_hit = hit_times[CALIB_SAMPLES/2];
    *median_miss = miss_times[CALIB_SAMPLES/2];
    
    return (*median_hit + *median_miss) / 2;
}

/**
 * pin_to_core() - 绑定进程到指定CPU核心
 * @core_id: CPU核心编号
 * 
 * 确保victim和attacker在同一核心上共享缓存
 * 这是Flush+Reload攻击的必要条件
 */
static inline void pin_to_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);
}

#endif // UTILS_H
