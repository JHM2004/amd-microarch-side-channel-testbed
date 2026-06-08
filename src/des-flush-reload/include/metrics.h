/**
 * metrics.h
 * DES Flush+Reload Attack - 量化指标分析模块
 * 
 * 功能：
 * - 泄露带宽计算 (Leakage Bandwidth)
 * - 命中率统计 (Hit Rate)
 * - 信噪比分析 (SNR)
 * - 缓存计时统计
 */

#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <stdbool.h>
#include "config.h"

// 量化指标结构体
typedef struct {
    // 泄露带宽相关
    double leakage_bandwidth;      // 泄露带宽 (bits/second)
    double bits_per_attack;        // 每次攻击获取的密钥位数
    double attack_duration_ms;     // 攻击持续时间 (毫秒)
    
    // 命中率相关
    double cache_hit_rate;         // 缓存命中率 (0-1)
    double true_positive_rate;     // 真正例率 (正确检测/实际访问)
    double false_positive_rate;    // 假正例率 (错误检测/未访问)
    
    // 信噪比相关
    double snr_db;                 // 信噪比 (dB)
    double signal_mean;            // 信号均值 (命中时间)
    double noise_mean;             // 噪声均值 (未命中时间)
    double signal_std;             // 信号标准差
    double noise_std;              // 噪声标准差
    
    // 计时统计
    uint64_t min_hit_time;         // 最小命中时间 (cycles)
    uint64_t max_hit_time;         // 最大命中时间 (cycles)
    uint64_t min_miss_time;        // 最小未命中时间 (cycles)
    uint64_t max_miss_time;        // 最大未命中时间 (cycles)
    uint64_t threshold;            // 当前阈值
    
    // 攻击效果
    int recovered_fragments;       // 恢复的密钥片段数
    int total_fragments;           // 总片段数 (通常为8)
    double recovery_rate;          // 恢复率 (0-1)
    
} AttackMetrics;

// 计时数据收集结构
typedef struct {
    uint64_t *hit_times;           // 命中时间数组
    uint64_t *miss_times;          // 未命中时间数组
    int hit_count;                 // 命中次数
    int miss_count;                // 未命中次数
    int capacity;                  // 数组容量
} TimingData;

// 函数声明

// 初始化/清理
void metrics_init(AttackMetrics *metrics);
void timing_data_init(TimingData *data, int capacity);
void timing_data_free(TimingData *data);

// 数据收集
void timing_data_add_hit(TimingData *data, uint64_t time);
void timing_data_add_miss(TimingData *data, uint64_t time);

// 指标计算
void metrics_calculate_bandwidth(AttackMetrics *metrics, double duration_sec, int bits_recovered);
void metrics_calculate_hit_rate(AttackMetrics *metrics, int true_positives, int false_positives, 
                                 int true_negatives, int false_negatives);
void metrics_calculate_snr(AttackMetrics *metrics, TimingData *data);
void metrics_calculate_timing_stats(AttackMetrics *metrics, TimingData *data);

// 综合计算
void metrics_compute_all(AttackMetrics *metrics, TimingData *data, 
                         double duration_sec, int bits_recovered,
                         int tp, int fp, int tn, int fn);

// 输出
void metrics_print_summary(AttackMetrics *metrics);
void metrics_save_json(AttackMetrics *metrics, const char *filename);
void metrics_save_csv(AttackMetrics *metrics, const char *filename, int round_num);

// 辅助函数
double calculate_cohens_d(double mean1, double mean2, double std1, double std2);
double calculate_separation_quality(uint64_t threshold, double hit_mean, double miss_mean,
                                     double hit_std, double miss_std);

#endif /* METRICS_H */
