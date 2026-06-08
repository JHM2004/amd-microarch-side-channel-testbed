#ifndef STATISTICS_H
#define STATISTICS_H

/**
 * statistics.h
 * 缓存侧信道攻击统计计算函数库
 * 
 * 功能：提供时间测量数据的统计分析函数
 * 包括：均值、标准差、百分位数、效应量、分离度等
 */

#include <stdint.h>

/* ==================== 基础统计函数 ==================== */

/**
 * 计算平均值（算术平均数）
 * @param data: 指向uint64_t数组的指针，存储时间测量数据
 * @param n: 样本数量（数组长度）
 * @return: 平均值，即所有数据之和除以样本数
 * 用途：描述数据集的中心趋势
 */
double calculate_mean(uint64_t *data, int n);

/**
 * 计算标准差（总体标准差）
 * @param data: 指向uint64_t数组的指针，存储时间测量数据
 * @param n: 样本数量
 * @param mean: 预先计算好的平均值
 * @return: 标准差，衡量数据的离散程度
 * 计算公式：sqrt(Σ(xi - mean)² / n)
 * 用途：描述数据的分散程度，值越大表示数据越分散
 */
double calculate_stddev(uint64_t *data, int n, double mean);

/**
 * 计算百分位数（使用线性插值法）
 * @param sorted_data: 已排序的uint64_t数组（升序）
 * @param n: 样本数量
 * @param p: 百分位（0.0到1.0之间，如0.5表示中位数）
 * @return: 对应百分位的值
 * 用途：描述数据分布的特定位置，如中位数(p=0.5)、四分位数(p=0.25, 0.75)等
 */
double calculate_percentile(uint64_t *sorted_data, int n, double p);

/* ==================== 效应量和区分度函数 ==================== */

/**
 * 计算Cohen's d效应量
 * @param mean1, mean2: 两组数据的均值
 * @param std1, std2: 两组数据的标准差
 * @return: Cohen's d值，衡量两组数据差异的大小
 * 计算公式：|mean1 - mean2| / pooled_std
 * 其中pooled_std = sqrt((std1² + std2²) / 2) 是合并标准差
 * 解释标准：
 *   d < 0.2: 可忽略的差异
 *   0.2 <= d < 0.5: 小效应
 *   0.5 <= d < 0.8: 中等效应
 *   d >= 0.8: 大效应
 * 用途：在侧信道攻击中，衡量缓存命中和未命中的可区分程度
 */
double calculate_cohens_d(double mean1, double mean2, double std1, double std2);

/**
 * 计算分离度（Separation Ratio）
 * @param mean1, mean2: 两组数据的均值
 * @param std1, std2: 两组数据的标准差
 * @return: 分离度值
 * 计算公式：|mean1 - mean2| / ((std1 + std2) / 2)
 * 用途：衡量两组分布的分离程度，值越大表示两组越容易区分
 * 在缓存侧信道攻击中，用于评估时间测量的可区分性
 */
double calculate_separation(double mean1, double mean2, double std1, double std2);

/* ==================== 高级统计函数（可选） ==================== */

/**
 * 计算变异系数（Coefficient of Variation, CV）
 * @param std: 标准差
 * @param mean: 均值
 * @return: 变异系数百分比
 * 计算公式：(std / mean) * 100%
 * 用途：衡量相对离散程度，消除量纲影响，便于不同数据集比较
 * 注意：当均值为0时返回0，避免除零错误
 */
double calculate_cv(double std, double mean);

/**
 * 计算偏度（Skewness）
 * @param data: 数据数组指针
 * @param n: 样本数量
 * @param mean: 预先计算的均值
 * @param std: 预先计算的标准差
 * @return: 偏度值
 * 计算公式：(1/n) * Σ((xi - mean) / std)³
 * 解释：
 *   偏度 > 0: 右偏（正偏），数据右尾较长
 *   偏度 < 0: 左偏（负偏），数据左尾较长
 *   偏度 ≈ 0: 对称分布
 * 用途：描述数据分布的不对称性
 * 注意：需要至少3个样本，标准差不能为0
 */
double calculate_skewness(uint64_t *data, int n, double mean, double std);

/**
 * 计算峰度（Kurtosis）
 * @param data: 数据数组指针
 * @param n: 样本数量
 * @param mean: 预先计算的均值
 * @param std: 预先计算的标准差
 * @return: 超额峰度值（已减3）
 * 计算公式：(1/n) * Σ((xi - mean) / std)⁴ - 3
 * 解释：
 *   峰度 > 0: 尖峰厚尾（比正态分布更集中）
 *   峰度 < 0: 平峰薄尾（比正态分布更分散）
 *   峰度 ≈ 0: 接近正态分布
 * 用途：描述数据分布的"尖峭"程度和尾部厚度
 * 注意：需要至少4个样本，标准差不能为0
 */
double calculate_kurtosis(uint64_t *data, int n, double mean, double std);

#endif /* STATISTICS_H */
