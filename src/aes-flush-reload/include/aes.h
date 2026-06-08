/**
 * aes.h - AES算法接口定义
 * 
 * 支持AES-128/192/256加密和解密
 * 使用T表优化实现
 */

#ifndef AES_H
#define AES_H

#include <stdint.h>
#include "config.h"

#ifdef _WIN32
    #define AES_API __declspec(dllexport)
#else
    #define AES_API __attribute__((visibility("default")))
#endif

// AES上下文
typedef struct {
    uint32_t rk[60];     // 轮密钥
    int rounds;          // 轮数
    int key_len;         // 密钥长度（字节）
} AES_CTX;

// T表结构
typedef struct {
    uint32_t data[T_TABLE_SIZE];
} TTable;

// ==================== AES核心函数 ====================

AES_API int AES_set_encrypt_key(const uint8_t *userKey, int bits, AES_CTX *ctx);
AES_API int AES_set_decrypt_key(const uint8_t *userKey, int bits, AES_CTX *ctx);
AES_API void AES_encrypt(const uint8_t *in, uint8_t *out, const AES_CTX *ctx);
AES_API void AES_decrypt(const uint8_t *in, uint8_t *out, const AES_CTX *ctx);

// ==================== 高级接口 ====================

AES_API void aes_encrypt_full(const uint8_t *plaintext, uint8_t *ciphertext,
                               const uint8_t *key, int key_bits);
AES_API void aes_decrypt_full(const uint8_t *ciphertext, uint8_t *plaintext,
                               const uint8_t *key, int key_bits);

// ==================== 密钥恢复辅助函数 ====================

AES_API int recover_original_key_aes128(const uint8_t *K_last, uint8_t *original_key);
AES_API int recover_original_key_aes192(const uint8_t *K_last, uint8_t *original_key);
AES_API int recover_original_key_aes256(const uint8_t *K_last, uint8_t *original_key);

// ==================== T表辅助函数 ====================

static inline uint8_t get_te_byte(TTable *te, int idx, int row) {
    return (te->data[idx] >> (24 - row * 8)) & 0xFF;
}

static inline uint8_t get_td_byte(TTable *td, int idx, int row) {
    return (td->data[idx] >> (24 - row * 8)) & 0xFF;
}

#endif // AES_H
