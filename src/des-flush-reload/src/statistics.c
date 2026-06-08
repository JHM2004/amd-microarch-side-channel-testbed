/**
 * statistics.c
 * 缓存侧信道攻击统计计算函数库实现
 * 
 * 实现了时间测量数据的统计分析函数
 */

#include <math.h>
#include <stdint.h>
#include "statistics.h"

/* ==================== 基础统计函数 ==================== */

double calculate_mean(uint64_t *data, int n) {
    double sum = 0;
    for (int i = 0; i < n; i++) {
        sum += data[i];
    }
    return sum / n;
}

double calculate_stddev(uint64_t *data, int n, double mean) {
    double sum_sq = 0;
    for (int i = 0; i < n; i++) {
        double diff = data[i] - mean;  // 每个数据点与均值的差
        sum_sq += diff * diff;          // 差的平方累加
    }
    return sqrt(sum_sq / n);            // 开平方根得到标准差
}

double calculate_percentile(uint64_t *sorted_data, int n, double p) {
    double idx = p * (n - 1);           // 计算理论索引位置
    int lower = (int)idx;               // 取下整，得到低索引
    int upper = lower + 1;              // 高索引
    if (upper >= n) return sorted_data[n - 1];  // 边界保护
    double frac = idx - lower;          // 小数部分，用于线性插值
    // 线性插值：在低值和高值之间按比例计算
    return sorted_data[lower] * (1 - frac) + sorted_data[upper] * frac;
}

/* ==================== 效应量和区分度函数 ==================== */

double calculate_cohens_d(double mean1, double mean2, double std1, double std2) {
    double pooled_std = sqrt((std1 * std1 + std2 * std2) / 2);
    if (pooled_std == 0) return 0;
    return fabs(mean1 - mean2) / pooled_std;
}

double calculate_separation(double mean1, double mean2, double std1, double std2) {
    if (std1 + std2 == 0) return 100.0;
    double separation = fabs(mean1 - mean2) / ((std1 + std2) / 2);
    return separation;
}

/* ==================== 高级统计函数（可选） ==================== */

double calculate_cv(double std, double mean) {
    if (mean == 0) return 0;
    return (std / mean) * 100.0;
}

double calculate_skewness(uint64_t *data, int n, double mean, double std) {
    if (std == 0 || n < 3) return 0;
    double sum_cubed = 0;
    for (int i = 0; i < n; i++) {
        double diff = (data[i] - mean) / std;  // 标准化
        sum_cubed += diff * diff * diff;        // 三次方累加
    }
    return sum_cubed / n;
}

double calculate_kurtosis(uint64_t *data, int n, double mean, double std) {
    if (std == 0 || n < 4) return 0;
    double sum_fourth = 0;
    for (int i = 0; i < n; i++) {
        double diff = (data[i] - mean) / std;  // 标准化
        sum_fourth += diff * diff * diff * diff; // 四次方累加
    }
    return sum_fourth / n - 3.0;  // 减3得到超额峰度
}
