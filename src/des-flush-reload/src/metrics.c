/**
 * metrics.c
 * DES Flush+Reload Attack - 量化指标分析实现
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include "metrics.h"
#include "statistics.h"

// 初始化指标结构
void metrics_init(AttackMetrics *metrics) {
    memset(metrics, 0, sizeof(AttackMetrics));
    metrics->total_fragments = 8;  // DES有8个S-box
}

// 初始化计时数据结构
void timing_data_init(TimingData *data, int capacity) {
    data->hit_times = (uint64_t*)malloc(capacity * sizeof(uint64_t));
    data->miss_times = (uint64_t*)malloc(capacity * sizeof(uint64_t));
    data->hit_count = 0;
    data->miss_count = 0;
    data->capacity = capacity;
}

// 释放计时数据
void timing_data_free(TimingData *data) {
    if (data->hit_times) free(data->hit_times);
    if (data->miss_times) free(data->miss_times);
    data->hit_count = 0;
    data->miss_count = 0;
}

// 添加命中时间
void timing_data_add_hit(TimingData *data, uint64_t time) {
    if (data->hit_count < data->capacity) {
        data->hit_times[data->hit_count++] = time;
    }
}

// 添加未命中时间
void timing_data_add_miss(TimingData *data, uint64_t time) {
    if (data->miss_count < data->capacity) {
        data->miss_times[data->miss_count++] = time;
    }
}

// 计算均值
static double calculate_mean_uint64(uint64_t *data, int count) {
    if (count == 0) return 0.0;
    uint64_t sum = 0;
    for (int i = 0; i < count; i++) {
        sum += data[i];
    }
    return (double)sum / count;
}

// 计算标准差
static double calculate_std_uint64(uint64_t *data, int count, double mean) {
    if (count <= 1) return 0.0;
    double sum_sq = 0.0;
    for (int i = 0; i < count; i++) {
        double diff = (double)data[i] - mean;
        sum_sq += diff * diff;
    }
    return sqrt(sum_sq / (count - 1));
}

// 查找最小值
static uint64_t find_min(uint64_t *data, int count) {
    if (count == 0) return 0;
    uint64_t min = data[0];
    for (int i = 1; i < count; i++) {
        if (data[i] < min) min = data[i];
    }
    return min;
}

// 查找最大值
static uint64_t find_max(uint64_t *data, int count) {
    if (count == 0) return 0;
    uint64_t max = data[0];
    for (int i = 1; i < count; i++) {
        if (data[i] > max) max = data[i];
    }
    return max;
}

// 计算泄露带宽
void metrics_calculate_bandwidth(AttackMetrics *metrics, double duration_sec, int bits_recovered) {
    metrics->attack_duration_ms = duration_sec * 1000.0;
    metrics->bits_per_attack = bits_recovered;
    
    if (duration_sec > 0) {
        metrics->leakage_bandwidth = bits_recovered / duration_sec;
    } else {
        metrics->leakage_bandwidth = 0.0;
    }
}

// 计算命中率
void metrics_calculate_hit_rate(AttackMetrics *metrics, int true_positives, int false_positives,
                                 int true_negatives, int false_negatives) {
    int total = true_positives + false_positives + true_negatives + false_negatives;
    int actual_positives = true_positives + false_negatives;
    int actual_negatives = true_negatives + false_positives;
    
    if (total > 0) {
        metrics->cache_hit_rate = (double)(true_positives + false_positives) / total;
    }
    
    if (actual_positives > 0) {
        metrics->true_positive_rate = (double)true_positives / actual_positives;
    }
    
    if (actual_negatives > 0) {
        metrics->false_positive_rate = (double)false_positives / actual_negatives;
    }
}

// 计算信噪比 (dB)
void metrics_calculate_snr(AttackMetrics *metrics, TimingData *data) {
    if (data->hit_count == 0 || data->miss_count == 0) {
        metrics->snr_db = 0.0;
        return;
    }
    
    double signal_mean = calculate_mean_uint64(data->hit_times, data->hit_count);
    double noise_mean = calculate_mean_uint64(data->miss_times, data->miss_count);
    double signal_std = calculate_std_uint64(data->hit_times, data->hit_count, signal_mean);
    double noise_std = calculate_std_uint64(data->miss_times, data->miss_count, noise_mean);
    
    metrics->signal_mean = signal_mean;
    metrics->noise_mean = noise_mean;
    metrics->signal_std = signal_std;
    metrics->noise_std = noise_std;
    
    // SNR = 20 * log10(noise_mean / signal_mean)
    // 这里用时间比值，命中时间越短越好
    if (signal_mean > 0) {
        double snr_linear = noise_mean / signal_mean;
        metrics->snr_db = 20.0 * log10(snr_linear);
    }
}

// 计算计时统计
void metrics_calculate_timing_stats(AttackMetrics *metrics, TimingData *data) {
    metrics->min_hit_time = find_min(data->hit_times, data->hit_count);
    metrics->max_hit_time = find_max(data->hit_times, data->hit_count);
    metrics->min_miss_time = find_min(data->miss_times, data->miss_count);
    metrics->max_miss_time = find_max(data->miss_times, data->miss_count);
    
    metrics->signal_mean = calculate_mean_uint64(data->hit_times, data->hit_count);
    metrics->noise_mean = calculate_mean_uint64(data->miss_times, data->miss_count);
    metrics->signal_std = calculate_std_uint64(data->hit_times, data->hit_count, metrics->signal_mean);
    metrics->noise_std = calculate_std_uint64(data->miss_times, data->miss_count, metrics->noise_mean);
}

// 综合计算所有指标
void metrics_compute_all(AttackMetrics *metrics, TimingData *data,
                         double duration_sec, int bits_recovered,
                         int tp, int fp, int tn, int fn) {
    metrics_calculate_timing_stats(metrics, data);
    metrics_calculate_snr(metrics, data);
    metrics_calculate_bandwidth(metrics, duration_sec, bits_recovered);
    metrics_calculate_hit_rate(metrics, tp, fp, tn, fn);
    
    // 计算恢复率
    if (metrics->total_fragments > 0) {
        metrics->recovery_rate = (double)metrics->recovered_fragments / metrics->total_fragments;
    }
}

// 打印指标摘要
void metrics_print_summary(AttackMetrics *metrics) {
    printf("\n========== Quantitative Metrics Summary ==========\n");
    printf("\n[Leakage Bandwidth]\n");
    printf("  Bandwidth:        %.2f bits/second\n", metrics->leakage_bandwidth);
    printf("  Bits per attack:  %.1f bits\n", metrics->bits_per_attack);
    printf("  Duration:         %.2f ms\n", metrics->attack_duration_ms);
    
    printf("\n[Hit Rate]\n");
    printf("  Cache hit rate:   %.2f%%\n", metrics->cache_hit_rate * 100);
    printf("  True positive:    %.2f%%\n", metrics->true_positive_rate * 100);
    printf("  False positive:   %.2f%%\n", metrics->false_positive_rate * 100);
    
    printf("\n[Signal-to-Noise Ratio]\n");
    printf("  SNR:              %.2f dB\n", metrics->snr_db);
    printf("  Signal mean:      %.2f cycles\n", metrics->signal_mean);
    printf("  Noise mean:       %.2f cycles\n", metrics->noise_mean);
    printf("  Signal std:       %.2f cycles\n", metrics->signal_std);
    printf("  Noise std:        %.2f cycles\n", metrics->noise_std);
    
    printf("\n[Timing Statistics]\n");
    printf("  Hit time range:   %lu - %lu cycles\n", 
           metrics->min_hit_time, metrics->max_hit_time);
    printf("  Miss time range:  %lu - %lu cycles\n",
           metrics->min_miss_time, metrics->max_miss_time);
    printf("  Threshold:        %lu cycles\n", metrics->threshold);
    
    printf("\n[Recovery Status]\n");
    printf("  Recovered:        %d/%d fragments\n", 
           metrics->recovered_fragments, metrics->total_fragments);
    printf("  Recovery rate:    %.2f%%\n", metrics->recovery_rate * 100);
    printf("==================================================\n\n");
}

// 保存为JSON
void metrics_save_json(AttackMetrics *metrics, const char *filename) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Failed to open %s for writing\n", filename);
        return;
    }
    
    fprintf(fp, "{\n");
    fprintf(fp, "  \"leakage_bandwidth\": %.4f,\n", metrics->leakage_bandwidth);
    fprintf(fp, "  \"bits_per_attack\": %.2f,\n", metrics->bits_per_attack);
    fprintf(fp, "  \"attack_duration_ms\": %.2f,\n", metrics->attack_duration_ms);
    fprintf(fp, "  \"cache_hit_rate\": %.4f,\n", metrics->cache_hit_rate);
    fprintf(fp, "  \"true_positive_rate\": %.4f,\n", metrics->true_positive_rate);
    fprintf(fp, "  \"false_positive_rate\": %.4f,\n", metrics->false_positive_rate);
    fprintf(fp, "  \"snr_db\": %.4f,\n", metrics->snr_db);
    fprintf(fp, "  \"signal_mean\": %.2f,\n", metrics->signal_mean);
    fprintf(fp, "  \"noise_mean\": %.2f,\n", metrics->noise_mean);
    fprintf(fp, "  \"signal_std\": %.2f,\n", metrics->signal_std);
    fprintf(fp, "  \"noise_std\": %.2f,\n", metrics->noise_std);
    fprintf(fp, "  \"min_hit_time\": %lu,\n", metrics->min_hit_time);
    fprintf(fp, "  \"max_hit_time\": %lu,\n", metrics->max_hit_time);
    fprintf(fp, "  \"min_miss_time\": %lu,\n", metrics->min_miss_time);
    fprintf(fp, "  \"max_miss_time\": %lu,\n", metrics->max_miss_time);
    fprintf(fp, "  \"threshold\": %lu,\n", metrics->threshold);
    fprintf(fp, "  \"recovered_fragments\": %d,\n", metrics->recovered_fragments);
    fprintf(fp, "  \"total_fragments\": %d,\n", metrics->total_fragments);
    fprintf(fp, "  \"recovery_rate\": %.4f\n", metrics->recovery_rate);
    fprintf(fp, "}\n");
    
    fclose(fp);
    printf("Metrics saved to: %s\n", filename);
}

// 保存为CSV（追加模式）
void metrics_save_csv(AttackMetrics *metrics, const char *filename, int round_num) {
    FILE *fp = fopen(filename, "a");
    if (!fp) {
        // 尝试创建新文件并写入表头
        fp = fopen(filename, "w");
        if (!fp) {
            fprintf(stderr, "Failed to open %s for writing\n", filename);
            return;
        }
        fprintf(fp, "round,leakage_bandwidth,bits_per_attack,duration_ms,"
                   "hit_rate,tp_rate,fp_rate,snr_db,signal_mean,noise_mean,"
                   "signal_std,noise_std,threshold,recovered,recovery_rate\n");
    }
    
    fprintf(fp, "%d,%.4f,%.2f,%.2f,%.4f,%.4f,%.4f,%.4f,%.2f,%.2f,%.2f,%.2f,%lu,%d,%.4f\n",
            round_num,
            metrics->leakage_bandwidth,
            metrics->bits_per_attack,
            metrics->attack_duration_ms,
            metrics->cache_hit_rate,
            metrics->true_positive_rate,
            metrics->false_positive_rate,
            metrics->snr_db,
            metrics->signal_mean,
            metrics->noise_mean,
            metrics->signal_std,
            metrics->noise_std,
            metrics->threshold,
            metrics->recovered_fragments,
            metrics->recovery_rate);
    
    fclose(fp);
}

// 计算分离质量（阈值在两个分布之间的位置）
double calculate_separation_quality(uint64_t threshold, double hit_mean, double miss_mean,
                                     double hit_std, double miss_std) {
    if (hit_std == 0 || miss_std == 0) return 0.0;
    
    // 计算阈值距离两个均值的相对位置
    double dist_to_hit = fabs((double)threshold - hit_mean) / hit_std;
    double dist_to_miss = fabs((double)threshold - miss_mean) / miss_std;
    
    // 理想情况下，阈值应该距离两个均值都足够远
    return (dist_to_hit + dist_to_miss) / 2.0;
}
