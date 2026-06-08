#ifndef CONFIG_H
#define CONFIG_H

/**
 * config.h
 * AES Flush+Reload Cache Side-Channel Attack 全局配置
 *
 * 基于论文《Cache Misses and the Recovery of the Full AES 256 Key》实现
 */

/* ==================== 攻击参数配置 ==================== */

#define ATTACK_ITERATIONS          10000   // 攻击迭代次数（样本数）
#define CALIBRATION_ROUNDS         10000   // 校准轮数
#define CACHE_HIT_THRESHOLD        0       // 缓存命中阈值（0表示自动计算）
#define MAX_ROUNDS                 10      // 攻击轮数（用于投票）

// 三种AES变体样本量，逐级递增以保证基线100%成功率
#define AES128_SAMPLES             5000
#define AES192_SAMPLES             9000
#define AES256_SAMPLES             15000
#define MAX_SAMPLES                1000000

/* ==================== AES算法常量 ==================== */

#define AES_BLOCK_SIZE             16      // AES块大小（字节）
#define AES_KEY_SIZE_128           16      // AES-128密钥大小（字节）
#define AES_KEY_SIZE_192           24      // AES-192密钥大小（字节）
#define AES_KEY_SIZE_256           32      // AES-256密钥大小（字节）
#define AES_ROUNDS_128             10      // AES-128轮数
#define AES_ROUNDS_192             12      // AES-192轮数
#define AES_ROUNDS_256             14      // AES-256轮数

#define T_TABLE_SIZE               256     // T表大小（256个条目）
#define T_TABLE_ENTRY_SIZE         4       // 每个条目4字节（32位）
#define CACHE_LINE_SIZE            64      // 缓存行大小（字节）
#define T_ENTRIES_PER_CACHE_LINE   16      // 每缓存行16个T表项 (64/4)

/* ==================== T表监控配置 ==================== */

// 监控每个Te表的第0个缓存行（索引0-15）
#define MONITORED_CACHE_LINE       0

/* ==================== 测试数据 ==================== */

// 测试密钥（AES-128）
#define TEST_KEY_128               {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, \
                                    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}

// 测试密钥（AES-192）
#define TEST_KEY_192               {0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, \
                                    0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, \
                                    0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b}

// 测试密钥（AES-256）
#define TEST_KEY_256               {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, \
                                    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, \
                                    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, \
                                    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4}

// 测试明文
#define TEST_PLAINTEXT             {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, \
                                    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34}

#endif /* CONFIG_H */
