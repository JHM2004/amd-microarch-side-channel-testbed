/**
 * attack_common.h - AES Flush+Reload攻击共同接口
 * 
 * 包含所有AES变体（128/192/256）攻击的共同组件声明
 */

#ifndef ATTACK_COMMON_H
#define ATTACK_COMMON_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>

#include "aes.h"
#include "config.h"
#include "shared_mem.h"
#include "utils.h"

/* ==================== 外部变量声明 ==================== */

extern uint8_t sbox[256];
extern uint8_t inv_sbox[256];

/* ==================== 样本数据结构 ==================== */

typedef struct {
    int X[4][MAX_SAMPLES];
    uint8_t ciphertexts[MAX_SAMPLES][16];
    int no_access_count[4];
    int collected;
    uint64_t hit_times[MAX_SAMPLES * 4];
    uint64_t miss_times[MAX_SAMPLES * 4];
    int hit_count;
    int miss_count;
    int useful_samples;
    uint64_t total_sample_cycles;
} AttackSamples;

/* ==================== 性能测量数据结构 ==================== */

typedef struct {
    uint64_t total_encrypt_cycles;     // 总加密周期数
    uint64_t encrypt_count;             // 加密次数
    double avg_encrypt_cycles;          // 平均加密周期
    double encrypt_throughput;          // 加密吞吐量 (MB/s)
    double overhead_percent;            // 相对基准的性能开销百分比
} PerformanceMetrics;

/* ==================== GF(2^8)乘法 ==================== */

uint8_t gmul(uint8_t a, uint8_t b);

/* ==================== 辅助函数 ==================== */

void compute_expected_last_round_key(const uint8_t *key, int key_bits, uint8_t *k_last);

/* ==================== T表初始化 ==================== */

void init_t_tables(SharedTTables *shm);

/* ==================== Victim加密函数 ==================== */

void victim_encrypt(SharedTTables *victim_shm, AES_CTX *ctx, uint8_t *ciphertext);

/* ==================== 样本收集 ==================== */

void collect_samples(
    SharedTTables *shm,
    int pipe_to_victim[2],
    int pipe_to_attacker[2],
    int num_samples,
    uint64_t threshold,
    AttackSamples *samples,
    int noise_level
);

void print_statistics(AttackSamples *samples);

/* ==================== Victim进程 ==================== */

void victim_process(
    SharedTTables *victim_shm,
    int pipe_to_victim[2],
    int pipe_to_attacker[2],
    const uint8_t *key,
    int key_bits,
    int num_samples,
    int pin_core,
    int noise_level,
    int cache_flush,
    PerformanceMetrics *perf
);

/* ==================== 排除法密钥恢复 ==================== */

void exclusion_recover_key(
    int X[4][MAX_SAMPLES],
    uint8_t ciphertexts[MAX_SAMPLES][16],
    int num_samples,
    uint8_t K_last[16],
    uint8_t *expected_k
);

/* ==================== EBD攻击算法 ==================== */

void ebd_recover_kd1(
    SharedTTables *shm,
    int X[4][MAX_SAMPLES],
    uint8_t ciphertexts[MAX_SAMPLES][16],
    int num_samples,
    uint8_t K_last[16],
    uint8_t Kd1[16],
    uint8_t *expected_kd1
);

/* ==================== 密钥转换函数 ==================== */

void kd1_to_k11(uint8_t Kd1[16], uint8_t K11[16]);
void kd1_to_k13(uint8_t Kd1[16], uint8_t K13[16]);

/* ==================== 预期值计算函数 ==================== */

void compute_expected_kd1(const uint8_t *key, int key_bits, uint8_t *kd1);
void compute_expected_k11(const uint8_t *key, int key_bits, uint8_t *k11);
void compute_expected_k13(const uint8_t *key, uint8_t *k13);

/* ==================== 逆向密钥扩展 ==================== */

int recover_original_key_aes192_full(
    uint8_t K12[16],
    uint8_t K11[16],
    uint8_t original_key[24]
);

int recover_original_key_aes256_full(
    uint8_t K14[16],
    uint8_t K13[16],
    uint8_t original_key[32]
);

#endif
