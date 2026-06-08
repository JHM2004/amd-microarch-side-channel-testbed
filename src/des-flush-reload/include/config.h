#ifndef CONFIG_H
#define CONFIG_H

/**
 * config.h
 * DES Flush+Reload Attack 全局配置常量
 * 
 * 集中存放所有配置宏定义，便于统一管理和修改
 */

/* ==================== 攻击参数配置 ==================== */

#define ATTACK_ITERATIONS          20000   // 攻击迭代次数
#define CALIBRATION_ROUNDS         10000   // 校准轮数
#define CACHE_HIT_THRESHOLD        0       // 缓存命中阈值（0表示自动计算）
#define MAX_CACHE_ROWS             4       // 最大缓存行数
#define SBOX_COUNT                 8       // S-box数量
#define SBOX_ENTRIES_PER_CACHE_LINE 16    // 每个缓存行的S-box条目数
#define MEASUREMENT_REPEATS        3       // 每次测量重复次数

/* ==================== DES算法常量 ==================== */

#define DES_BLOCK_SIZE             64      // DES块大小（位）
#define DES_KEY_SIZE               64      // DES密钥大小（位）
#define SBOX_INPUT_SIZE            6       // S-box输入大小（位）
#define SBOX_OUTPUT_SIZE           4       // S-box输出大小（位）
#define SBOX_TOTAL_ENTRIES         64      // S-box总条目数（2^6）
#define DES_ROUNDS                 16      // DES轮数
#define DES_HALF_BLOCK_SIZE        32      // DES半块大小（位）
#define E_EXTENSION_SIZE           48      // E扩展后的大小（位）

/* ==================== 测试数据 ==================== */

#define KEY_TEST_1                 0x133457799BBCDFF1ULL    // 测试密钥
#define TEST_PLAINTEXT             0x0123456789ABCDEFULL    // 测试明文

#endif /* CONFIG_H */
