#ifndef OUTPUT_H
#define OUTPUT_H

/**
 * output.h
 * DES Flush+Reload Attack 结果输出模块
 * 
 * 功能：将攻击和校准结果输出到文件（JSON、CSV格式）
 */

#include <stdint.h>

/* ==================== 校准结果输出函数 ==================== */

/**
 * 输出校准数据的CSV格式文件
 * @param filename: 基础文件名（不含扩展名）
 * @param hit_times: 缓存命中时间数组
 * @param miss_times: 缓存未命中时间数组
 * @param n: 样本数量
 * 功能：将时间测量数据导出为CSV格式，便于Python等工具分析
 * 输出格式：sample_id,type,time_cycles
 * 注意：最多输出5000个样本，避免文件过大
 */
void output_calibration_csv(const char *filename, 
                             uint64_t *hit_times, uint64_t *miss_times, int n);

/**
 * 输出校准统计结果到JSON文件
 * @param filename: 输出文件名
 * @param hit_times: 缓存命中时间数组（原始数据）
 * @param miss_times: 缓存未命中时间数组（原始数据）
 * @param n: 样本数量
 * @param threshold: 缓存命中/未命中的判断阈值（CPU周期）
 * 功能：计算并输出完整的统计指标到JSON格式文件
 * 输出内容包括：
 *   1. sample_info: 样本基本信息
 *   2. cache_hit_stats: 缓存命中的统计指标
 *   3. cache_miss_stats: 缓存未命中的统计指标
 *   4. threshold_info: 阈值信息和可区分性指标
 *   5. raw_data: 原始时间数据（前1000个样本）
 */
void output_calibration_stats(const char *filename,
                               uint64_t *hit_times, uint64_t *miss_times, int n,
                               uint64_t threshold);

/* ==================== 攻击结果输出函数 ==================== */

/**
 * 输出攻击统计结果到JSON文件
 * @param filename: 输出文件名
 * @param hit_counts: 每个S-box每个entry的命中次数数组 [SBOX_COUNT][64]
 * @param detected_entries: 每个S-box检测到的最佳entry索引数组
 * @param round_num: 攻击轮次编号
 * 功能：记录每轮攻击的详细结果，包括：
 *   - 攻击轮次信息
 *   - 每个S-box的检测结果
 *   - 命中分布情况
 *   - 最佳entry和命中率
 */
void output_attack_stats(const char *filename, 
                         int hit_counts[][64],
                         int detected_entries[],
                         int round_num);

#endif /* OUTPUT_H */
