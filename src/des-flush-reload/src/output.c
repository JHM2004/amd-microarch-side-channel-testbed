/**
 * output.c
 * DES Flush+Reload Attack 结果输出模块实现
 * 
 * 实现了校准和攻击结果的文件输出功能
 * 支持JSON和CSV格式
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "config.h"      // 全局配置常量
#include "output.h"
#include "statistics.h"

/* 比较函数实现（用于qsort排序uint64_t数组） */
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a;
    uint64_t y = *(const uint64_t *)b;
    if (x < y) return -1;
    if (x > y) return 1;
    return 0;
}

/**
 * 输出校准数据的CSV格式文件
 * @param filename: 基础文件名（不含扩展名）
 * @param hit_times: 缓存命中时间数组
 * @param miss_times: 缓存未命中时间数组
 * @param n: 样本数量
 * 功能：将时间测量数据导出为CSV格式，便于Python等工具分析
 * 输出格式：sample_id,type,time_cycles
 *   - sample_id: 样本序号
 *   - type: "hit"或"miss"表示缓存状态
 *   - time_cycles: 时间测量值（CPU周期）
 * 注意：最多输出5000个样本，避免文件过大
 */
void output_calibration_csv(const char *filename, 
                             uint64_t *hit_times, uint64_t *miss_times, int n) {
    char csv_filename[256];
    snprintf(csv_filename, sizeof(csv_filename), "%s.csv", filename);
    
    FILE *fp = fopen(csv_filename, "w");
    if (!fp) {
        perror("Failed to open CSV file");
        return;
    }
    
    // 写入CSV表头
    fprintf(fp, "sample_id,type,time_cycles\n");
    
    // 限制输出数量，避免文件过大（最多5000个样本）
    int limit = n > 5000 ? 5000 : n;
    
    // 输出缓存命中数据
    for (int i = 0; i < limit; i++) {
        fprintf(fp, "%d,hit,%lu\n", i, hit_times[i]);
    }
    
    // 输出缓存未命中数据
    for (int i = 0; i < limit; i++) {
        fprintf(fp, "%d,miss,%lu\n", i, miss_times[i]);
    }
    
    fclose(fp);
    printf("CSV data saved to: %s\n", csv_filename);
}

/**
 * 输出校准统计结果到JSON文件
 * @param filename: 输出文件名
 * @param hit_times: 缓存命中时间数组（原始数据）
 * @param miss_times: 缓存未命中时间数组（原始数据）
 * @param n: 样本数量
 * @param threshold: 缓存命中/未命中的判断阈值（CPU周期）
 * 功能：计算并输出完整的统计指标到JSON格式文件
 * 输出内容包括：
 *   1. sample_info: 样本基本信息（数量、重复次数、时间戳等）
 *   2. cache_hit_stats: 缓存命中的统计指标
 *   3. cache_miss_stats: 缓存未命中的统计指标
 *   4. threshold_info: 阈值信息和可区分性指标
 *   5. raw_data: 原始时间数据（前1000个样本）
 * 统计指标说明：
 *   - mean: 平均值，描述数据中心位置
 *   - stddev: 标准差，描述数据离散程度
 *   - min/max/range: 极值和范围
 *   - median/p25/p75/p95/p99: 分位数，描述分布形状
 *   - iqr: 四分位距，p75-p25，稳健的离散度度量
 *   - cohens_d: 效应量，衡量两组差异大小
 *   - separation_ratio: 分离度，衡量可区分性
 *   - classification_accuracy: 分类准确率评估
 */
void output_calibration_stats(const char *filename,
                               uint64_t *hit_times, uint64_t *miss_times, int n,
                               uint64_t threshold) {
    // 打开文件进行写入
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Failed to open stats file");
        return;
    }

    // 为排序操作创建临时数组（不修改原始数据）
    uint64_t *hit_sorted = malloc(n * sizeof(uint64_t));
    uint64_t *miss_sorted = malloc(n * sizeof(uint64_t));
    memcpy(hit_sorted, hit_times, n * sizeof(uint64_t));
    memcpy(miss_sorted, miss_times, n * sizeof(uint64_t));

    // 对数据进行排序，用于计算百分位数和极值
    // cmp_u64是比较函数，用于qsort对uint64_t数组排序
    qsort(hit_sorted, n, sizeof(uint64_t), cmp_u64);
    qsort(miss_sorted, n, sizeof(uint64_t), cmp_u64);

    // ========== 计算基本统计量 ==========
    // 计算均值和标准差
    double hit_mean = calculate_mean(hit_times, n);
    double miss_mean = calculate_mean(miss_times, n);
    double hit_std = calculate_stddev(hit_times, n, hit_mean);
    double miss_std = calculate_stddev(miss_times, n, miss_mean);

    // 计算百分位数（基于排序后的数据）
    // p25: 第一四分位数，p50: 中位数，p75: 第三四分位数
    // p95, p99: 95%和99%分位数，用于识别异常值
    double hit_p25 = calculate_percentile(hit_sorted, n, 0.25);
    double hit_p50 = calculate_percentile(hit_sorted, n, 0.50);
    double hit_p75 = calculate_percentile(hit_sorted, n, 0.75);
    double hit_p95 = calculate_percentile(hit_sorted, n, 0.95);
    double hit_p99 = calculate_percentile(hit_sorted, n, 0.99);

    double miss_p25 = calculate_percentile(miss_sorted, n, 0.25);
    double miss_p50 = calculate_percentile(miss_sorted, n, 0.50);
    double miss_p75 = calculate_percentile(miss_sorted, n, 0.75);
    double miss_p95 = calculate_percentile(miss_sorted, n, 0.95);
    double miss_p99 = calculate_percentile(miss_sorted, n, 0.99);

    // ========== 计算可区分性指标 ==========
    // Cohen's d: 衡量两组均值差异的效应量
    // separation: 衡量两组分布的分离程度
    double cohens_d = calculate_cohens_d(hit_mean, miss_mean, hit_std, miss_std);
    double separation = calculate_separation(hit_mean, miss_mean, hit_std, miss_std);

    // ========== 计算分类准确率 ==========
    // 统计有多少样本被正确分类
    // 命中样本应该低于阈值，未命中样本应该高于阈值
    int hit_below_threshold = 0, miss_below_threshold = 0;
    for (int i = 0; i < n; i++) {
        if (hit_times[i] < threshold) hit_below_threshold++;      // 正确分类的命中
        if (miss_times[i] < threshold) miss_below_threshold++;    // 错误分类的未命中
    }
    // 计算各类准确率（百分比）
    double hit_accuracy = (double)hit_below_threshold / n * 100.0;              // 命中率
    double miss_accuracy = (double)(n - miss_below_threshold) / n * 100.0;      // 未命中率
    double overall_accuracy = (hit_accuracy + miss_accuracy) / 2.0;             // 总体准确率

    // ========== 输出JSON格式统计结果 ==========
    fprintf(fp, "{\n");

    // 1. 样本信息部分
    fprintf(fp, "  \"sample_info\": {\n");
    fprintf(fp, "    \"total_samples\": %d,\n", n);                          // 总样本数
    fprintf(fp, "    \"measurement_repeats\": %d,\n", MEASUREMENT_REPEATS);   // 每次测量重复次数
    fprintf(fp, "    \"timestamp\": %ld,\n", (long)time(NULL));               // 时间戳
    fprintf(fp, "    \"calibration_rounds\": %d\n", CALIBRATION_ROUNDS);      // 校准轮数
    fprintf(fp, "  },\n");

    // 2. 缓存命中统计部分
    fprintf(fp, "  \"cache_hit_stats\": {\n");
    fprintf(fp, "    \"mean\": %.2f,\n", hit_mean);           // 平均值
    fprintf(fp, "    \"stddev\": %.2f,\n", hit_std);           // 标准差
    fprintf(fp, "    \"min\": %lu,\n", hit_sorted[0]);         // 最小值
    fprintf(fp, "    \"max\": %lu,\n", hit_sorted[n-1]);       // 最大值
    fprintf(fp, "    \"range\": %lu,\n", hit_sorted[n-1] - hit_sorted[0]); // 范围
    fprintf(fp, "    \"median\": %.2f,\n", hit_p50);           // 中位数
    fprintf(fp, "    \"p25\": %.2f,\n", hit_p25);              // 第一四分位数
    fprintf(fp, "    \"p75\": %.2f,\n", hit_p75);              // 第三四分位数
    fprintf(fp, "    \"p95\": %.2f,\n", hit_p95);              // 95%分位数
    fprintf(fp, "    \"p99\": %.2f,\n", hit_p99);              // 99%分位数
    fprintf(fp, "    \"iqr\": %.2f\n", hit_p75 - hit_p25);     // 四分位距
    fprintf(fp, "  },\n");

    // 3. 缓存未命中统计部分
    fprintf(fp, "  \"cache_miss_stats\": {\n");
    fprintf(fp, "    \"mean\": %.2f,\n", miss_mean);
    fprintf(fp, "    \"stddev\": %.2f,\n", miss_std);
    fprintf(fp, "    \"min\": %lu,\n", miss_sorted[0]);
    fprintf(fp, "    \"max\": %lu,\n", miss_sorted[n-1]);
    fprintf(fp, "    \"range\": %lu,\n", miss_sorted[n-1] - miss_sorted[0]);
    fprintf(fp, "    \"median\": %.2f,\n", miss_p50);
    fprintf(fp, "    \"p25\": %.2f,\n", miss_p25);
    fprintf(fp, "    \"p75\": %.2f,\n", miss_p75);
    fprintf(fp, "    \"p95\": %.2f,\n", miss_p95);
    fprintf(fp, "    \"p99\": %.2f,\n", miss_p99);
    fprintf(fp, "    \"iqr\": %.2f\n", miss_p75 - miss_p25);
    fprintf(fp, "  },\n");

    // 4. 阈值和可区分性信息部分
    fprintf(fp, "  \"threshold_info\": {\n");
    fprintf(fp, "    \"threshold\": %lu,\n", threshold);                      // 阈值
    fprintf(fp, "    \"mean_difference\": %.2f,\n", miss_mean - hit_mean);     // 均值差
    fprintf(fp, "    \"median_difference\": %.2f,\n", miss_p50 - hit_p50);     // 中位数差
    fprintf(fp, "    \"cohens_d\": %.4f,\n", cohens_d);                        // Cohen's d效应量
    fprintf(fp, "    \"separation_ratio\": %.4f,\n", separation);              // 分离度
    // discriminability: 根据cohens_d给出可区分性评级
    fprintf(fp, "    \"discriminability\": \"%s\",\n",
            cohens_d > 2.0 ? "excellent" : (cohens_d > 1.0 ? "good" : "poor"));
    fprintf(fp, "    \"classification_accuracy\": {\n");
    fprintf(fp, "      \"hit_accuracy_percent\": %.2f,\n", hit_accuracy);      // 命中准确率
    fprintf(fp, "      \"miss_accuracy_percent\": %.2f,\n", miss_accuracy);    // 未命中准确率
    fprintf(fp, "      \"overall_accuracy_percent\": %.2f\n", overall_accuracy);// 总体准确率
    fprintf(fp, "    }\n");
    fprintf(fp, "  },\n");

    // 5. 原始数据部分（限制前1000个样本，避免文件过大）
    fprintf(fp, "  \"raw_data\": {\n");
    fprintf(fp, "    \"hit_times\": [");
    for (int i = 0; i < n && i < 1000; i++) {
        fprintf(fp, "%s%lu", i > 0 ? "," : "", hit_times[i]);
        if (i % 100 == 99) fprintf(fp, "\n      ");  // 每100个换行，便于阅读
    }
    fprintf(fp, "],\n");
    fprintf(fp, "    \"miss_times\": [");
    for (int i = 0; i < n && i < 1000; i++) {
        fprintf(fp, "%s%lu", i > 0 ? "," : "", miss_times[i]);
        if (i % 100 == 99) fprintf(fp, "\n      ");
    }
    fprintf(fp, "]\n");
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");

    // 清理资源
    fclose(fp);
    free(hit_sorted);
    free(miss_sorted);

    printf("Statistics saved to: %s\n", filename);
}

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
                         int round_num) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        perror("Failed to open attack stats file");
        return;
    }
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"attack_round\": %d,\n", round_num);
    fprintf(fp, "  \"iterations_per_entry\": %d,\n", ATTACK_ITERATIONS / 64);
    fprintf(fp, "  \"sbox_results\": [\n");
    
    for (int sbox = 0; sbox < SBOX_COUNT; sbox++) {
        fprintf(fp, "    {\n");
        fprintf(fp, "      \"sbox_id\": %d,\n", sbox);
        fprintf(fp, "      \"detected_entry\": %d,\n", detected_entries[sbox]);
        
        // 找出最佳entry（命中次数最多的）
        int max_hits = 0;
        int best_entry = -1;
        for (int entry = 0; entry < 64; entry++) {
            if (hit_counts[sbox][entry] > max_hits) {
                max_hits = hit_counts[sbox][entry];
                best_entry = entry;
            }
        }
        
        fprintf(fp, "      \"best_entry\": %d,\n", best_entry);
        fprintf(fp, "      \"max_hits\": %d,\n", max_hits);
        fprintf(fp, "      \"hit_ratio\": %.4f,\n", (double)max_hits / (ATTACK_ITERATIONS / 64));
        
        // 输出命中分布数组
        fprintf(fp, "      \"hit_distribution\": [");
        for (int entry = 0; entry < 64; entry++) {
            fprintf(fp, "%s%d", entry > 0 ? "," : "", hit_counts[sbox][entry]);
        }
        fprintf(fp, "]\n");
        fprintf(fp, "    }%s\n", sbox < SBOX_COUNT - 1 ? "," : "");
    }
    
    fprintf(fp, "  ]\n");
    fprintf(fp, "}\n");
    fclose(fp);
    
    printf("Attack statistics saved to: %s\n", filename);
}
