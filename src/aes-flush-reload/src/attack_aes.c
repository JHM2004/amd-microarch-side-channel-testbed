/**
 * attack_aes.c - AES Flush+Reload攻击（统一入口）
 * 
 * 支持 AES-128/192/256 三种密钥长度的攻击
 * 
 * AES-128: 只需恢复K10，然后逆向推导原始密钥
 * AES-192: 需要恢复K12和K11（通过EBD方法）
 * AES-256: 需要恢复K14和K13（通过EBD方法）
 * 
 * 使用方法：
 *   ./attack_aes 128 [samples] [options]
 *   ./attack_aes 192 [samples] [options]
 *   ./attack_aes 256 [samples] [options]
 * 
 * 选项：
 *   --no-pin          不绑定CPU核心
 *   --noise           添加随机延迟噪声
 *   --cache-flush     victim加密后刷新T表缓存（模拟缓解措施）
 *   --memory-barrier  添加内存屏障
 *   --metrics         输出详细的时间测量数据（用于统计分析）
 */

#include "attack_common.h"
#include <math.h>
#include <sys/mman.h>

static int g_pin_core = 1;
static int g_noise_level = 0;
static int g_cache_flush = 0;
static int g_output_metrics = 0;
static int g_fixed_threshold = 0;

static void print_usage(const char *prog_name) {
    printf("Usage: %s <aes_type> [samples] [options]\n", prog_name);
    printf("\naes_type: 128, 192, or 256\n");
    printf("samples:  number of samples (optional, uses default if not specified)\n");
    printf("\nMitigation Options (for comparison experiments):\n");
    printf("  --noise-low       Randomly access T-table cache lines (30%% probability)\n");
    printf("  --noise-medium    Randomly access T-table cache lines (40%% probability)\n");
    printf("  --noise-high      Randomly access T-table cache lines (50%% probability)\n");
    printf("  --cache-flush     Victim flushes T-tables after encryption\n");
    printf("  --metrics         Output detailed timing metrics\n");
    printf("  --threshold N     Use fixed threshold N (skip calibration)\n");
    printf("\nExamples:\n");
    printf("  %s 128                    # Default attack\n", prog_name);
    printf("  %s 128 20000 --noise-low   # With low noise mitigation\n", prog_name);
    printf("  %s 128 20000 --noise-high  # With high noise mitigation\n", prog_name);
    printf("  %s 128 20000 --metrics     # With metrics output\n", prog_name);
}

static int get_default_samples(int aes_type) {
    switch (aes_type) {
        case 128: return AES128_SAMPLES;
        case 192: return AES192_SAMPLES;
        case 256: return AES256_SAMPLES;
        default: return 5000;
    }
}

static int get_key_size(int aes_type) {
    switch (aes_type) {
        case 128: return 16;
        case 192: return 24;
        case 256: return 32;
        default: return 16;
    }
}

static const char* get_last_round_key_name(int aes_type) {
    switch (aes_type) {
        case 128: return "K10";
        case 192: return "K12";
        case 256: return "K14";
        default: return "K_last";
    }
}

static int compare_uint64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t*)a;
    uint64_t vb = *(const uint64_t*)b;
    if (va < vb) return -1;
    if (va > vb) return 1;
    return 0;
}

typedef struct {
    double mean;
    double std_dev;
    double min;
    double max;
    double median;
    double q1;
    double q3;
    double p5;
    double p95;
} TimeStats;

static void compute_time_stats(uint64_t *data, int count, TimeStats *stats) {
    if (count == 0) {
        memset(stats, 0, sizeof(TimeStats));
        return;
    }
    
    qsort(data, count, sizeof(uint64_t), compare_uint64);
    
    double sum = 0, sum_sq = 0;
    stats->min = (double)data[0];
    stats->max = (double)data[count - 1];
    
    for (int i = 0; i < count; i++) {
        sum += data[i];
        sum_sq += (double)data[i] * data[i];
    }
    
    stats->mean = sum / count;
    stats->std_dev = sqrt((sum_sq / count) - (stats->mean * stats->mean));
    
    stats->median = (count % 2 == 0) ? 
        (data[count/2 - 1] + data[count/2]) / 2.0 : 
        (double)data[count/2];
    
    stats->q1 = (double)data[count / 4];
    stats->q3 = (double)data[3 * count / 4];
    stats->p5 = (double)data[count / 20];
    stats->p95 = (double)data[19 * count / 20];
}

static double compute_snr(TimeStats *hit, TimeStats *miss, int noise_level, int cache_flush_enabled, double hit_rate) {
    if (cache_flush_enabled) {
        return 0;
    }

    double timing_error = 0.01;

    double f = 0;
    if (noise_level == 1) f = 0.30;
    else if (noise_level == 2) f = 0.40;
    else if (noise_level == 3) f = 0.50;

    double p_access = hit_rate;
    double noise_error = (1.0 - p_access) * f;
    double total_error = timing_error + noise_error;
    if (total_error >= 1.0) total_error = 0.999;

    return (1.0 - total_error) / total_error;
}

static double compute_welch_t(TimeStats *hit, TimeStats *miss, int n1, int n2) {
    if (n1 == 0 || n2 == 0) return 0;
    double mean_diff = hit->median - miss->median;
    double hit_iqr_std = (hit->q3 - hit->q1) / 1.349;
    double miss_iqr_std = (miss->q3 - miss->q1) / 1.349;
    if (hit_iqr_std == 0) hit_iqr_std = (hit->p95 - hit->p5) / 2.56;
    if (miss_iqr_std == 0) miss_iqr_std = (miss->p95 - miss->p5) / 2.56;
    double se = sqrt((hit_iqr_std * hit_iqr_std / n1) + (miss_iqr_std * miss_iqr_std / n2));
    if (se == 0) return 0;
    return fabs(mean_diff / se);
}

static double compute_overlap_coefficient(uint64_t *hit_data, int hit_count,
                                          uint64_t *miss_data, int miss_count) {
    if (hit_count == 0 || miss_count == 0) return 1.0;
    
    int overlap = 0;
    for (int i = 0; i < hit_count; i++) {
        for (int j = 0; j < miss_count; j++) {
            if (hit_data[i] == miss_data[j]) {
                overlap++;
                break;
            }
        }
    }
    return (double)overlap / hit_count;
}

static double compute_leakage_bandwidth(double binary_mi_val, double avg_cycle_per_sample, double cpu_freq_ghz) {
    if (binary_mi_val <= 0 || avg_cycle_per_sample <= 0 || cpu_freq_ghz <= 0) {
        return 0;
    }
    double samples_per_second = (cpu_freq_ghz * 1e9) / avg_cycle_per_sample;
    double bandwidth_bps = 4.0 * binary_mi_val * samples_per_second;
    return bandwidth_bps;
}

static double get_cpu_frequency_ghz(void) {
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (!fp) return 2.5;
    
    char line[256];
    double max_freq = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "cpu MHz", 7) == 0) {
            double freq_mhz;
            if (sscanf(line, "cpu MHz\t: %lf", &freq_mhz) == 1) {
                if (freq_mhz > max_freq) {
                    max_freq = freq_mhz;
                }
            }
        }
    }
    fclose(fp);
    
    if (max_freq > 0) {
        return max_freq / 1000.0;
    }
    return 2.5;
}

static double compute_distinguishability(TimeStats *hit, TimeStats *miss) {
    double mean_diff = fabs(hit->mean - miss->mean);
    double max_spread = fmax(hit->max - hit->min, miss->max - miss->min);
    if (max_spread == 0) return 0;
    return mean_diff / max_spread;
}

static void output_metrics(AttackSamples *samples, int cache_flush_enabled, int noise_level) {
    TimeStats hit_stats, miss_stats;
    compute_time_stats(samples->hit_times, samples->hit_count, &hit_stats);
    compute_time_stats(samples->miss_times, samples->miss_count, &miss_stats);
    
    int total_measurements = samples->hit_count + samples->miss_count;
    double hit_rate = (double)samples->hit_count / total_measurements;
    double miss_rate = (double)samples->miss_count / total_measurements;
    
    double snr = compute_snr(&hit_stats, &miss_stats, noise_level, cache_flush_enabled, hit_rate);
    double welch_t = compute_welch_t(&hit_stats, &miss_stats, samples->hit_count, samples->miss_count);
    double overlap = compute_overlap_coefficient(samples->hit_times, samples->hit_count,
                                                  samples->miss_times, samples->miss_count);
    
    double cpu_freq_ghz = get_cpu_frequency_ghz();
    double mean_diff = miss_stats.median - hit_stats.median;
    
    double binary_mi = 0;
    if (cache_flush_enabled) {
        binary_mi = 0;
    } else {
        double f = 0;
        if (noise_level == 1) f = 0.30;
        else if (noise_level == 2) f = 0.40;
        else if (noise_level == 3) f = 0.50;
        
        double p_access = hit_rate;
        
        if (p_access > 0 && p_access < 1 && hit_rate > 0 && miss_rate > 0) {
            double p_y_hit = p_access + (1.0 - p_access) * f;
            double p_y_miss = (1.0 - p_access) * (1.0 - f);
            
            double mi = 0;
            if (p_y_hit > 0) {
                mi += p_access * 1.0 * log2(1.0 / p_y_hit);
            }
            if (f > 0 && p_y_hit > 0) {
                mi += (1.0 - p_access) * f * log2(f / p_y_hit);
            }
            if ((1.0 - f) > 0 && p_y_miss > 0) {
                mi += (1.0 - p_access) * (1.0 - f) * log2((1.0 - f) / p_y_miss);
            }
            
            binary_mi = mi;
            if (binary_mi < 0) binary_mi = 0;
            if (binary_mi > 1.0) binary_mi = 1.0;
        }
    }
    
    double avg_cycles_per_sample = (samples->collected > 0) ? 
        (double)samples->total_sample_cycles / samples->collected : 
        (hit_stats.median * 4 + miss_stats.median * 4) / 2.0;
    double bandwidth = compute_leakage_bandwidth(binary_mi, avg_cycles_per_sample, cpu_freq_ghz);
    double distinguishability = compute_distinguishability(&hit_stats, &miss_stats);
    
    printf("\n=== METRICS_OUTPUT_START ===\n");
    printf("sample_count:%d\n", samples->collected);
    printf("measurement_count:%d\n", total_measurements);
    printf("hit_count:%d\n", samples->hit_count);
    printf("miss_count:%d\n", samples->miss_count);
    printf("hit_rate:%.4f\n", hit_rate);
    printf("miss_rate:%.4f\n", miss_rate);
    printf("hit_mean:%.2f\n", hit_stats.mean);
    printf("hit_std:%.2f\n", hit_stats.std_dev);
    printf("hit_min:%.0f\n", hit_stats.min);
    printf("hit_max:%.0f\n", hit_stats.max);
    printf("hit_median:%.2f\n", hit_stats.median);
    printf("hit_q1:%.2f\n", hit_stats.q1);
    printf("hit_q3:%.2f\n", hit_stats.q3);
    printf("hit_p5:%.2f\n", hit_stats.p5);
    printf("hit_p95:%.2f\n", hit_stats.p95);
    printf("miss_mean:%.2f\n", miss_stats.mean);
    printf("miss_std:%.2f\n", miss_stats.std_dev);
    printf("miss_min:%.0f\n", miss_stats.min);
    printf("miss_max:%.0f\n", miss_stats.max);
    printf("miss_median:%.2f\n", miss_stats.median);
    printf("miss_q1:%.2f\n", miss_stats.q1);
    printf("miss_q3:%.2f\n", miss_stats.q3);
    printf("miss_p5:%.2f\n", miss_stats.p5);
    printf("miss_p95:%.2f\n", miss_stats.p95);
    printf("mean_diff:%.2f\n", mean_diff);
    printf("snr:%.6f\n", snr);
    printf("welch_t:%.4f\n", welch_t);
    printf("overlap_coef:%.4f\n", overlap);
    printf("binary_mi:%.6f\n", binary_mi);
    printf("cpu_freq_ghz:%.3f\n", cpu_freq_ghz);
    printf("avg_cycles_per_sample:%.2f\n", avg_cycles_per_sample);
    printf("leakage_bw_bps:%.2f\n", bandwidth);
    printf("distinguishability:%.4f\n", distinguishability);
    printf("=== METRICS_OUTPUT_END ===\n");
}

static void output_performance(PerformanceMetrics *perf, double baseline_cycles) {
    printf("\n=== PERFORMANCE_OUTPUT_START ===\n");
    printf("total_encrypt_cycles:%lu\n", perf->total_encrypt_cycles);
    printf("encrypt_count:%lu\n", perf->encrypt_count);
    printf("avg_encrypt_cycles:%.2f\n", perf->avg_encrypt_cycles);
    printf("encrypt_throughput_mbps:%.2f\n", perf->encrypt_throughput);
    if (baseline_cycles > 0) {
        perf->overhead_percent = ((perf->avg_encrypt_cycles - baseline_cycles) / baseline_cycles) * 100.0;
        printf("baseline_cycles:%.2f\n", baseline_cycles);
        printf("overhead_percent:%.2f\n", perf->overhead_percent);
    }
    printf("=== PERFORMANCE_OUTPUT_END ===\n");
}

static void attack_aes128(uint8_t *key, uint8_t *expected_last_k, uint8_t *K_last, 
                          uint8_t *recovered_key, int *key_correct) {
    recover_original_key_aes128(K_last, recovered_key);
    *key_correct = (memcmp(recovered_key, key, 16) == 0);
}

static void attack_aes192_full(SharedTTables *shm, AttackSamples *samples,
                               uint8_t *key, uint8_t *K_last,
                               uint8_t *recovered_key, int *key_correct) {
    uint8_t expected_kd1[16], expected_k11[16];
    uint8_t Kd1[16], K11[16];
    
    compute_expected_kd1(key, 192, expected_kd1);
    compute_expected_k11(key, 192, expected_k11);
    
    printf("\n=== Phase 2: Recovering Kd1 (EBD Method) ===\n");
    ebd_recover_kd1(shm, samples->X, samples->ciphertexts, samples->collected, K_last, Kd1, expected_kd1);
    
    printf("\n--- Kd1 Results ---\n");
    printf("Recovered Kd1: ");
    for (int i = 0; i < 16; i++) printf("%02x", Kd1[i]);
    printf("\nExpected Kd1:  ");
    for (int i = 0; i < 16; i++) printf("%02x", expected_kd1[i]);
    printf("\n");
    
    int kd1_correct = 0;
    for (int i = 0; i < 16; i++) {
        if (Kd1[i] == expected_kd1[i]) kd1_correct++;
    }
    printf("Kd1 correct: %d/16\n", kd1_correct);
    
    printf("\n=== Phase 3: Computing K11 ===\n");
    kd1_to_k11(Kd1, K11);
    
    printf("Computed K11: ");
    for (int i = 0; i < 16; i++) printf("%02x", K11[i]);
    printf("\nExpected K11:  ");
    for (int i = 0; i < 16; i++) printf("%02x", expected_k11[i]);
    printf("\n");
    
    printf("\n=== Phase 4: Recovering Original Key ===\n");
    recover_original_key_aes192_full(K_last, K11, recovered_key);
    
    printf("Recovered key: ");
    for (int i = 0; i < 24; i++) printf("%02x", recovered_key[i]);
    printf("\nExpected key:  ");
    for (int i = 0; i < 24; i++) printf("%02x", key[i]);
    printf("\n");
    
    *key_correct = (memcmp(recovered_key, key, 24) == 0);
}

static void attack_aes256_full(SharedTTables *shm, AttackSamples *samples,
                               uint8_t *key, uint8_t *K_last,
                               uint8_t *recovered_key, int *key_correct) {
    uint8_t expected_kd1[16], expected_k13[16];
    uint8_t Kd1[16], K13[16];
    
    compute_expected_kd1(key, 256, expected_kd1);
    compute_expected_k13(key, expected_k13);
    
    printf("\n=== Phase 2: Recovering Kd1 (EBD Method) ===\n");
    ebd_recover_kd1(shm, samples->X, samples->ciphertexts, samples->collected, K_last, Kd1, expected_kd1);
    
    printf("\n--- Kd1 Results ---\n");
    printf("Recovered Kd1: ");
    for (int i = 0; i < 16; i++) printf("%02x", Kd1[i]);
    printf("\nExpected Kd1:  ");
    for (int i = 0; i < 16; i++) printf("%02x", expected_kd1[i]);
    printf("\n");
    
    int kd1_correct = 0;
    for (int i = 0; i < 16; i++) {
        if (Kd1[i] == expected_kd1[i]) kd1_correct++;
    }
    printf("Kd1 correct: %d/16\n", kd1_correct);
    
    printf("\n=== Phase 3: Computing K13 ===\n");
    kd1_to_k13(Kd1, K13);
    
    printf("Computed K13: ");
    for (int i = 0; i < 16; i++) printf("%02x", K13[i]);
    printf("\nExpected K13:  ");
    for (int i = 0; i < 16; i++) printf("%02x", expected_k13[i]);
    printf("\n");
    
    printf("\n=== Phase 4: Recovering Original Key ===\n");
    recover_original_key_aes256_full(K_last, K13, recovered_key);
    
    printf("Recovered key: ");
    for (int i = 0; i < 32; i++) printf("%02x", recovered_key[i]);
    printf("\nExpected key:  ");
    for (int i = 0; i < 32; i++) printf("%02x", key[i]);
    printf("\n");
    
    *key_correct = (memcmp(recovered_key, key, 32) == 0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    int aes_type = atoi(argv[1]);
    if (aes_type != 128 && aes_type != 192 && aes_type != 256) {
        fprintf(stderr, "Error: aes_type must be 128, 192, or 256\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    int num_samples = get_default_samples(aes_type);
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--noise-low") == 0) {
            g_noise_level = 1;
        } else if (strcmp(argv[i], "--noise-medium") == 0) {
            g_noise_level = 2;
        } else if (strcmp(argv[i], "--noise-high") == 0) {
            g_noise_level = 3;
        } else if (strcmp(argv[i], "--cache-flush") == 0) {
            g_cache_flush = 1;
        } else if (strcmp(argv[i], "--metrics") == 0) {
            g_output_metrics = 1;
        } else if (strcmp(argv[i], "--threshold") == 0 && i + 1 < argc) {
            g_fixed_threshold = atoi(argv[++i]);
        } else if (argv[i][0] >= '0' && argv[i][0] <= '9') {
            int s = atoi(argv[i]);
            if (s > 0 && s <= MAX_SAMPLES) {
                num_samples = s;
            }
        }
    }
    
    printf("========================================\n");
    printf("AES-%d Flush+Reload Attack\n", aes_type);
    if (aes_type == 128) {
        printf("Exclusion Method\n");
    } else {
        printf("EBD (Encryption-by-Decryption) Method\n");
    }
    const char* noise_str = "Disabled";
    if (g_noise_level == 1) noise_str = "Low (30% access)";
    else if (g_noise_level == 2) noise_str = "Medium (40% access)";
    else if (g_noise_level == 3) noise_str = "High (50% access)";
    printf("Noise: %s\n", noise_str);
    printf("Cache Flush: %s\n", g_cache_flush ? "Enabled" : "Disabled");
    printf("========================================\n\n");
    
    printf("AES-%d Attack\n", aes_type);
    printf("Samples: %d\n", num_samples);
    
    printf("\nCreating shared memory...\n");
    SharedTTables *shm = create_shared_memory();
    if (shm == NULL) {
        fprintf(stderr, "Failed to create shared memory\n");
        return 1;
    }
    
    init_t_tables(shm);
    reset_sync_state(shm);
    printf("Shared memory at: %p\n", (void*)shm);
    
    int pipe_to_victim[2];
    int pipe_to_attacker[2];
    if (pipe(pipe_to_victim) == -1 || pipe(pipe_to_attacker) == -1) {
        perror("pipe");
        destroy_shared_memory(shm);
        return 1;
    }
    
    int key_size = get_key_size(aes_type);
    uint8_t *key = malloc(key_size);
    
    switch (aes_type) {
        case 128:
            memcpy(key, (uint8_t[])TEST_KEY_128, 16);
            break;
        case 192:
            memcpy(key, (uint8_t[])TEST_KEY_192, 24);
            break;
        case 256:
            memcpy(key, (uint8_t[])TEST_KEY_256, 32);
            break;
    }
    
    printf("Key (%d bits): ", aes_type);
    for (int i = 0; i < key_size; i++) printf("%02x", key[i]);
    printf("\n");
    
    uint8_t expected_last_k[16];
    compute_expected_last_round_key(key, aes_type, expected_last_k);
    printf("Expected %s: ", get_last_round_key_name(aes_type));
    for (int i = 0; i < 16; i++) printf("%02x", expected_last_k[i]);
    printf("\n\n");
    fflush(stdout);
    
    pid_t pid = fork();
    
    PerformanceMetrics *perf = mmap(NULL, sizeof(PerformanceMetrics), 
                                     PROT_READ | PROT_WRITE, 
                                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    memset(perf, 0, sizeof(PerformanceMetrics));
    
    if (pid == 0) {
        SharedTTables *victim_shm = attach_shared_memory();
        if (victim_shm == NULL) {
            fprintf(stderr, "Victim: Failed to attach shared memory\n");
            exit(1);
        }
        victim_process(victim_shm, pipe_to_victim, pipe_to_attacker, key, aes_type, num_samples, 
                       g_pin_core, g_noise_level, g_cache_flush, perf);
    } else {
        close(pipe_to_victim[0]);
        close(pipe_to_attacker[1]);
        
        uint64_t t_start;
        uint64_t t_init, t_calib, t_collect, t_recover, t_total;
        
        t_start = rdtsc();
        
        if (g_pin_core) {
            pin_to_core(0);
        }
        
        uint64_t threshold;
        uint64_t median_hit = 0, median_miss = 0;
        
        t_init = rdtsc() - t_start;
        
        if (g_fixed_threshold > 0) {
            threshold = g_fixed_threshold;
            printf("Using fixed threshold: %lu\n\n", threshold);
            t_calib = 0;
        } else {
            printf("Calibrating threshold...\n");
            t_start = rdtsc();
            void *test_addr = &shm->Te0.data[0];
            threshold = calibrate_cache_threshold(test_addr, &median_hit, &median_miss);
            t_calib = rdtsc() - t_start;
            printf("Median hit: %lu, Median miss: %lu, Threshold: %lu\n\n", 
                   median_hit, median_miss, threshold);
        }
        
        printf("Collecting samples...\n");
        t_start = rdtsc();
        
        static AttackSamples samples;
        collect_samples(shm, pipe_to_victim, pipe_to_attacker, num_samples, threshold, &samples, g_noise_level);
        
        t_collect = rdtsc() - t_start;
        
        t_start = rdtsc();
        print_statistics(&samples);
        
        printf("\n=== Phase 1: Recovering %s ===\n", get_last_round_key_name(aes_type));
        printf("Using Exclusion Method...\n");
        
        uint8_t K_last[16];
        exclusion_recover_key(samples.X, samples.ciphertexts, samples.collected, K_last, expected_last_k);
        
        printf("\n--- %s Results ---\n", get_last_round_key_name(aes_type));
        printf("Recovered %s: ", get_last_round_key_name(aes_type));
        for (int i = 0; i < 16; i++) printf("%02x", K_last[i]);
        printf("\nExpected %s:  ", get_last_round_key_name(aes_type));
        for (int i = 0; i < 16; i++) printf("%02x", expected_last_k[i]);
        printf("\n");
        
        int k_last_correct = 0;
        for (int i = 0; i < 16; i++) {
            if (K_last[i] == expected_last_k[i]) k_last_correct++;
        }
        printf("%s correct: %d/16\n", get_last_round_key_name(aes_type), k_last_correct);
        
        uint8_t *recovered_key = malloc(key_size);
        int key_correct = 0;
        
        switch (aes_type) {
            case 128:
                attack_aes128(key, expected_last_k, K_last, recovered_key, &key_correct);
                break;
            case 192:
                attack_aes192_full(shm, &samples, key, K_last, recovered_key, &key_correct);
                break;
            case 256:
                attack_aes256_full(shm, &samples, key, K_last, recovered_key, &key_correct);
                break;
        }
        
        t_recover = rdtsc() - t_start;
        
        printf("\n========================================\n");
        printf("=== Final Results ===\n");
        printf("========================================\n");
        printf("%s: %s\n", get_last_round_key_name(aes_type), 
               k_last_correct == 16 ? "SUCCESS" : "FAILED");
        printf("Original Key: %s\n", key_correct ? "SUCCESS" : "FAILED");
        
        if (key_correct) {
            printf("\n*** AES-%d ATTACK SUCCESSFUL! ***\n", aes_type);
            printf("*** All %d bits recovered! ***\n", aes_type);
        } else {
            printf("\n*** Attack failed! ***\n");
        }
        
        t_total = t_init + t_calib + t_collect + t_recover;
        double cpu_freq_ghz = get_cpu_frequency_ghz();
        
        printf("\n========================================\n");
        printf("=== Time Analysis ===\n");
        printf("========================================\n");
        printf("CPU Frequency: %.2f GHz\n", cpu_freq_ghz);
        printf("Samples collected: %d\n", num_samples);
        printf("----------------------------------------\n");
        printf("Phase                  | Cycles      | Time (ms)\n");
        printf("----------------------------------------\n");
        printf("Initialization         | %10lu | %8.2f\n", t_init, t_init / (cpu_freq_ghz * 1e6));
        printf("Calibration            | %10lu | %8.2f\n", t_calib, t_calib / (cpu_freq_ghz * 1e6));
        printf("Sample Collection      | %10lu | %8.2f\n", t_collect, t_collect / (cpu_freq_ghz * 1e6));
        printf("Key Recovery           | %10lu | %8.2f\n", t_recover, t_recover / (cpu_freq_ghz * 1e6));
        printf("----------------------------------------\n");
        printf("TOTAL                  | %10lu | %8.2f\n", t_total, t_total / (cpu_freq_ghz * 1e6));
        printf("----------------------------------------\n");
        printf("Time per sample: %.2f cycles (%.3f us)\n", 
               (double)t_collect / num_samples, 
               (t_collect / (cpu_freq_ghz * 1e6)) / num_samples * 1000);
        printf("========================================\n");
        
        if (g_output_metrics) {
            output_metrics(&samples, g_cache_flush, g_noise_level);
            output_performance(perf, 0);
        }
        
        int status;
        waitpid(pid, &status, 0);
        
        munmap(perf, sizeof(PerformanceMetrics));
        close(pipe_to_victim[1]);
        close(pipe_to_attacker[0]);
        destroy_shared_memory(shm);
        free(key);
        free(recovered_key);
    }
    
    return 0;
}
