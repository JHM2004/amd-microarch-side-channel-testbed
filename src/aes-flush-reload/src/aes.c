/**
 * aes.c - AES算法实现（共享内存版本）
 * 
 * 基于OpenSSL的T表实现，用于Flush+Reload缓存侧信道攻击研究
 * 使用POSIX共享内存实现跨进程T表共享
 * 
 * 核心数据结构说明：
 * - sbox/inv_sbox: S盒和逆S盒，AES的非线性变换核心
 * - rcon: 轮常量，用于密钥扩展
 * - TTable: T表，将SubBytes+ShiftRows+MixColumns合并为查表操作
 * - AES_CTX: AES上下文，存储轮密钥和轮数信息
 * - SharedTTables: 共享内存结构，存储所有T表供跨进程访问
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "aes.h"
#include "config.h"
#include "shared_mem.h"

// ==================== S盒（Substitution Box）====================
/**
 * sbox[256] - AES加密用的S盒（替换盒）
 * 
 * 作用：实现AES的SubBytes操作，将每个字节映射为另一个字节
 * 原理：基于GF(2^8)有限域上的乘法逆元和仿射变换
 * 用途：加密时对每个字节进行非线性替换
 * 
 * 例如：sbox[0x00] = 0x63, sbox[0x01] = 0x7c, ...
 * 这是AES安全性的核心来源，提供了非线性特性
 */
uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/**
 * inv_sbox[256] - AES解密用的逆S盒
 * 
 * 作用：实现AES解密的InvSubBytes操作，是sbox的逆变换
 * 原理：inv_sbox[sbox[x]] = x，即可以还原原始字节
 * 用途：解密时将密文字节还原为原始字节
 * 
 * 例如：inv_sbox[0x63] = 0x00, inv_sbox[0x7c] = 0x01, ...
 */
uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/**
 * rcon[11] - 轮常量（Round Constants）
 * 
 * 作用：用于AES密钥扩展算法，为每轮密钥生成提供不同的常量
 * 原理：rcon[i] = x^(i-1) in GF(2^8)，其中x=0x02
 * 用途：在密钥扩展的RotWord操作后与结果异或
 * 
 * 值的含义：
 * - rcon[0] = 0x00000000 (未使用)
 * - rcon[1] = 0x01000000 (第1轮)
 * - rcon[2] = 0x02000000 (第2轮)
 * - ...
 * - rcon[10] = 0x36000000 (第10轮)
 * 
 * 注意：每个rcon只有最高字节有效，低3字节为0
 */
const uint32_t rcon[11] = {
    0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

// ==================== 共享内存T表指针 ====================
/**
 * g_shared_tables - 全局共享内存T表指针
 * 
 * 作用：指向POSIX共享内存中的T表结构，实现跨进程T表共享
 * 原理：多个进程通过共享内存访问同一物理内存地址
 * 用途：Flush+Reload攻击的核心，victim和attacker共享同一T表
 * 
 * 初始化：通过aes_init_shared_memory()函数初始化
 * 清理：通过aes_cleanup_shared_memory()函数清理
 */
static SharedTTables *g_shared_tables = NULL;

// ==================== T表生成辅助函数 ====================

/**
 * gmul() - GF(2^8)有限域乘法
 * @a: 第一个操作数
 * @b: 第二个操作数
 * 返回：a * b 在GF(2^8)上的结果
 * 
 * 作用：实现AES MixColumns操作所需的伽罗瓦域乘法
 * 原理：使用"俄罗斯农民乘法"算法，处理约减多项式x^8 + x^4 + x^3 + x + 1
 * 用途：计算T表中的值（如gmul(s, 2), gmul(s, 3)等）
 */
static uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        uint8_t hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;  // 约减多项式
        b >>= 1;
    }
    return p;
}

/**
 * generate_te_tables_to() - 生成加密T表
 * @te0, te1, te2, te3: 输出的四个T表指针
 * 
 * 作用：生成AES加密用的4个T表（Te0-Te3）
 * 
 * T表原理：将SubBytes、ShiftRows、MixColumns三个操作合并为一个查表操作
 * 
 * T表计算公式：
 * - Te0[i] = [S[i]·2, S[i], S[i], S[i]·3] = {02·S[i], S[i], S[i], {03}·S[i]}
 * - Te1[i] = Te0[i]循环右移1字节
 * - Te2[i] = Te0[i]循环右移2字节
 * - Te3[i] = Te0[i]循环右移3字节
 * 
 * 使用方式：
 * 每轮加密：t = Te0[s0>>24] ^ Te1[s1>>16] ^ Te2[s2>>8] ^ Te3[s3]
 * 这相当于：SubBytes + ShiftRows + MixColumns 三个操作
 * 
 * Flush+Reload攻击目标：攻击者通过监控这些T表的缓存访问来推断密钥
 */
static void generate_te_tables_to(TTable *te0, TTable *te1, TTable *te2, TTable *te3) {
    for (int i = 0; i < 256; i++) {
        uint8_t s = sbox[i];
        te0->data[i] = (gmul(s, 2) << 24) | (s << 16) | (s << 8) | gmul(s, 3);
        te1->data[i] = (gmul(s, 3) << 24) | (gmul(s, 2) << 16) | (s << 8) | s;
        te2->data[i] = (s << 24) | (gmul(s, 3) << 16) | (gmul(s, 2) << 8) | s;
        te3->data[i] = (s << 24) | (s << 16) | (gmul(s, 3) << 8) | gmul(s, 2);
    }
}

/**
 * generate_td_tables_to() - 生成解密T表
 * @td0, td1, td2, td3: 输出的四个解密T表指针
 * @td4: 输出的逆S表指针
 * 
 * 作用：生成AES解密用的4个T表（Td0-Td3）和逆S表（Td4）
 * 
 * Td表原理：将InvSubBytes、InvShiftRows、InvMixColumns合并为查表操作
 * 
 * Td表计算公式：
 * - Td0[i] = [{0e}·S^-1[i], {09}·S^-1[i], {0d}·S^-1[i], {0b}·S^-1[i]]
 * - Td1, Td2, Td3 是 Td0 的循环移位版本
 * - Td4[i] = S^-1[i] (逆S盒)
 */
static void generate_td_tables_to(TTable *td0, TTable *td1, TTable *td2, TTable *td3, uint8_t *td4) {
    for (int i = 0; i < 256; i++) {
        uint8_t s = inv_sbox[i];
        td0->data[i] = (gmul(s, 0x0e) << 24) | (gmul(s, 0x09) << 16) | (gmul(s, 0x0d) << 8) | gmul(s, 0x0b);
        td1->data[i] = (gmul(s, 0x0b) << 24) | (gmul(s, 0x0e) << 16) | (gmul(s, 0x09) << 8) | gmul(s, 0x0d);
        td2->data[i] = (gmul(s, 0x0d) << 24) | (gmul(s, 0x0b) << 16) | (gmul(s, 0x0e) << 8) | gmul(s, 0x09);
        td3->data[i] = (gmul(s, 0x09) << 24) | (gmul(s, 0x0d) << 16) | (gmul(s, 0x0b) << 8) | gmul(s, 0x0e);
        td4[i] = s;
    }
}

// ==================== 共享内存管理 ====================

/**
 * aes_init_shared_memory() - 初始化共享内存T表
 * @is_creator: 1表示创建者（victim），0表示附加者（attacker）
 * 返回：0成功，-1失败
 * 
 * 作用：创建或附加共享内存，初始化T表
 * 
 * 创建者（is_creator=1）：
 * 1. 创建POSIX共享内存对象
 * 2. 生成所有T表
 * 3. 设置initialized标志
 * 
 * 附加者（is_creator=0）：
 * 1. 附加到已存在的共享内存
 * 2. 等待T表初始化完成
 */
int aes_init_shared_memory(int is_creator) {
    if (g_shared_tables != NULL) {
        return 0;
    }
    
    if (is_creator) {
        g_shared_tables = create_shared_memory();
        if (g_shared_tables == NULL) {
            fprintf(stderr, "Failed to create shared memory\n");
            return -1;
        }
        
        if (!g_shared_tables->initialized) {
            generate_te_tables_to(&g_shared_tables->Te0, &g_shared_tables->Te1,
                                  &g_shared_tables->Te2, &g_shared_tables->Te3);
            generate_td_tables_to(&g_shared_tables->Td0, &g_shared_tables->Td1,
                                  &g_shared_tables->Td2, &g_shared_tables->Td3,
                                  g_shared_tables->Td4);
            g_shared_tables->initialized = 1;
        }
        printf("Shared memory created and T-tables initialized\n");
    } else {
        g_shared_tables = attach_shared_memory();
        if (g_shared_tables == NULL) {
            fprintf(stderr, "Failed to attach shared memory\n");
            return -1;
        }
        
        if (!g_shared_tables->initialized) {
            fprintf(stderr, "Warning: T-tables not initialized by creator\n");
        }
        printf("Attached to shared memory\n");
    }
    
    return 0;
}

/**
 * aes_cleanup_shared_memory() - 清理共享内存
 * @is_creator: 1表示创建者，0表示附加者
 * 
 * 作用：释放共享内存资源
 * 创建者会销毁共享内存，附加者只是分离
 */
void aes_cleanup_shared_memory(int is_creator) {
    if (g_shared_tables != NULL) {
        if (is_creator) {
            destroy_shared_memory(g_shared_tables);
        } else {
            detach_shared_memory(g_shared_tables);
        }
        g_shared_tables = NULL;
    }
}

// ==================== 获取T表地址 ====================
/**
 * get_te0/te1/te2/te3() - 获取加密T表指针
 * 返回：对应的T表指针，未初始化时返回NULL
 * 
 * 用途：供加密函数访问共享内存中的T表
 */
TTable* get_te0(void) { 
    return g_shared_tables ? &g_shared_tables->Te0 : NULL; 
}

TTable* get_te1(void) { 
    return g_shared_tables ? &g_shared_tables->Te1 : NULL; 
}

TTable* get_te2(void) { 
    return g_shared_tables ? &g_shared_tables->Te2 : NULL; 
}

TTable* get_te3(void) { 
    return g_shared_tables ? &g_shared_tables->Te3 : NULL; 
}

/**
 * get_td0/td1/td2/td3() - 获取解密T表指针
 * 返回：对应的T表指针，未初始化时返回NULL
 */
TTable* get_td0(void) { 
    return g_shared_tables ? &g_shared_tables->Td0 : NULL; 
}

TTable* get_td1(void) { 
    return g_shared_tables ? &g_shared_tables->Td1 : NULL; 
}

TTable* get_td2(void) { 
    return g_shared_tables ? &g_shared_tables->Td2 : NULL; 
}

TTable* get_td3(void) { 
    return g_shared_tables ? &g_shared_tables->Td3 : NULL; 
}

/**
 * get_td4() - 获取逆S表指针
 * 返回：逆S表指针，未初始化时返回NULL
 */
uint8_t* get_td4(void) { 
    return g_shared_tables ? g_shared_tables->Td4 : NULL; 
}

// ==================== 密钥调度 ====================

/**
 * rot_word() - 字循环移位
 * @x: 32位输入字
 * 返回：循环左移8位后的字
 * 
 * 作用：密钥扩展中的RotWord操作
 * 例如：[A,B,C,D] -> [B,C,D,A]
 */
static uint32_t rot_word(uint32_t x) {
    return (x << 8) | (x >> 24);
}

/**
 * sub_word() - 字替换
 * @x: 32位输入字
 * 返回：每个字节经过S盒替换后的字
 * 
 * 作用：密钥扩展中的SubWord操作
 * 对32位字的每个字节分别应用S盒
 */
static uint32_t sub_word(uint32_t x) {
    return ((uint32_t)sbox[x >> 24] << 24) |
           ((uint32_t)sbox[(x >> 16) & 0xff] << 16) |
           ((uint32_t)sbox[(x >> 8) & 0xff] << 8) |
           (uint32_t)sbox[x & 0xff];
}

/**
 * AES_set_encrypt_key() - 设置加密密钥
 * @userKey: 用户密钥（16/24/32字节）
 * @bits: 密钥位数（128/192/256）
 * @ctx: AES上下文输出
 * 返回：0成功，-1失败
 * 
 * 作用：从用户密钥生成所有轮密钥
 * 
 * 密钥扩展算法：
 * 1. 将用户密钥复制到前Nk个字
 * 2. 对每个后续字：
 *    - 如果i是Nk的倍数：temp = SubWord(RotWord(temp)) ^ Rcon[i/Nk]
 *    - 如果Nk>6且i%Nk==4：temp = SubWord(temp)
 *    - W[i] = W[i-Nk] ^ temp
 * 
 * 生成的轮密钥数量：
 * - AES-128: 10轮 + 1 = 44个字（176字节）
 * - AES-192: 12轮 + 1 = 52个字（208字节）
 * - AES-256: 14轮 + 1 = 60个字（240字节）
 */
int AES_set_encrypt_key(const uint8_t *userKey, int bits, AES_CTX *ctx) {
    int i;
    uint32_t *rk = ctx->rk;

    if (bits == 128) {
        ctx->rounds = 10;
        ctx->key_len = 16;
    } else if (bits == 192) {
        ctx->rounds = 12;
        ctx->key_len = 24;
    } else if (bits == 256) {
        ctx->rounds = 14;
        ctx->key_len = 32;
    } else {
        return -1;
    }

    for (i = 0; i < ctx->key_len / 4; i++) {
        rk[i] = ((uint32_t)userKey[4*i] << 24) |
                ((uint32_t)userKey[4*i+1] << 16) |
                ((uint32_t)userKey[4*i+2] << 8) |
                (uint32_t)userKey[4*i+3];
    }

    int nk = ctx->key_len / 4;
    for (i = nk; i < (ctx->rounds + 1) * 4; i++) {
        uint32_t temp = rk[i-1];
        if (i % nk == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[i/nk];
        } else if (nk > 6 && i % nk == 4) {
            temp = sub_word(temp);
        }
        rk[i] = rk[i-nk] ^ temp;
    }

    return 0;
}

/**
 * inv_mix_column() - 对单个32位字应用InvMixColumns变换
 * @w: 输入的32位字（代表状态矩阵的一列）
 * 返回：变换后的32位字
 * 
 * 作用：对单个列应用InvMixColumns变换
 * 原理：每个32位字代表状态矩阵的一列，需要独立变换
 * 
 * InvMixColumns矩阵：
 * | 0e 0b 0d 09 |
 * | 09 0e 0b 0d |
 * | 0d 09 0e 0b |
 * | 0b 0d 09 0e |
 */
static uint32_t inv_mix_column(uint32_t w) {
    uint8_t b0 = (w >> 24) & 0xff;
    uint8_t b1 = (w >> 16) & 0xff;
    uint8_t b2 = (w >> 8) & 0xff;
    uint8_t b3 = w & 0xff;
    
    return ((uint32_t)(gmul(b0, 0x0e) ^ gmul(b1, 0x0b) ^ gmul(b2, 0x0d) ^ gmul(b3, 0x09)) << 24) |
           ((uint32_t)(gmul(b0, 0x09) ^ gmul(b1, 0x0e) ^ gmul(b2, 0x0b) ^ gmul(b3, 0x0d)) << 16) |
           ((uint32_t)(gmul(b0, 0x0d) ^ gmul(b1, 0x09) ^ gmul(b2, 0x0e) ^ gmul(b3, 0x0b)) << 8) |
           ((uint32_t)(gmul(b0, 0x0b) ^ gmul(b1, 0x0d) ^ gmul(b2, 0x09) ^ gmul(b3, 0x0e)));
}

/**
 * AES_set_decrypt_key() - 设置解密密钥
 * @userKey: 用户密钥
 * @bits: 密钥位数
 * @ctx: AES上下文输出
 * 返回：0成功，-1失败
 * 
 * 作用：生成解密用的轮密钥
 * 
 * 原理：解密密钥是加密密钥的逆序，中间轮密钥需要经过InvMixColumns
 * 
 * 解密轮密钥顺序：
 * - 第0轮：加密的第Nr轮密钥
 * - 第Nr轮：加密的第0轮密钥
 * - 中间轮：加密密钥经过InvMixColumns变换
 * 
 * 注意：每个32位字代表状态矩阵的一列，需要独立应用InvMixColumns
 */
int AES_set_decrypt_key(const uint8_t *userKey, int bits, AES_CTX *ctx) {
    AES_CTX encrypt_ctx;
    if (AES_set_encrypt_key(userKey, bits, &encrypt_ctx) != 0) {
        return -1;
    }

    ctx->rounds = encrypt_ctx.rounds;
    ctx->key_len = encrypt_ctx.key_len;

    int nr = ctx->rounds;
    uint32_t *rk = ctx->rk;
    uint32_t *erk = encrypt_ctx.rk;

    for (int i = 0; i <= nr; i++) {
        uint32_t temp = erk[(nr - i) * 4];
        uint32_t temp1 = erk[(nr - i) * 4 + 1];
        uint32_t temp2 = erk[(nr - i) * 4 + 2];
        uint32_t temp3 = erk[(nr - i) * 4 + 3];

        if (i > 0 && i < nr) {
            temp = inv_mix_column(temp);
            temp1 = inv_mix_column(temp1);
            temp2 = inv_mix_column(temp2);
            temp3 = inv_mix_column(temp3);
        }

        rk[i*4] = temp;
        rk[i*4+1] = temp1;
        rk[i*4+2] = temp2;
        rk[i*4+3] = temp3;
    }

    return 0;
}

// ==================== 加密/解密 ====================

/**
 * AES_encrypt() - AES加密函数
 * @in: 16字节明文输入
 * @out: 16字节密文输出
 * @ctx: AES上下文（包含轮密钥）
 * 
 * 作用：使用T表优化的AES加密
 * 
 * 加密流程：
 * 1. 初始轮密钥加：state = plaintext ^ K0
 * 2. Nr-1轮主循环：
 *    - SubBytes + ShiftRows + MixColumns + AddRoundKey
 *    - 使用T表一次查表完成前三个操作
 * 3. 最后一轮（无MixColumns）：
 *    - SubBytes + ShiftRows + AddRoundKey
 *    - 直接使用S盒
 * 
 * 注意：最后一轮使用直接S盒而非T表，这是标准AES实现
 */
void AES_encrypt(const uint8_t *in, uint8_t *out, const AES_CTX *ctx) {
    if (g_shared_tables == NULL) {
        fprintf(stderr, "Error: Shared memory not initialized\n");
        return;
    }

    TTable *Te0 = &g_shared_tables->Te0;
    TTable *Te1 = &g_shared_tables->Te1;
    TTable *Te2 = &g_shared_tables->Te2;
    TTable *Te3 = &g_shared_tables->Te3;

    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    int r;

    s0 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    s1 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | (uint32_t)in[7];
    s2 = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | (uint32_t)in[11];
    s3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | (uint32_t)in[15];

    s0 ^= ctx->rk[0];
    s1 ^= ctx->rk[1];
    s2 ^= ctx->rk[2];
    s3 ^= ctx->rk[3];

    for (r = 1; r < ctx->rounds; r++) {
        t0 = Te0->data[(s0 >> 24) & 0xff] ^ Te1->data[(s1 >> 16) & 0xff] ^
             Te2->data[(s2 >> 8) & 0xff] ^ Te3->data[s3 & 0xff] ^ ctx->rk[r*4];
        t1 = Te0->data[(s1 >> 24) & 0xff] ^ Te1->data[(s2 >> 16) & 0xff] ^
             Te2->data[(s3 >> 8) & 0xff] ^ Te3->data[s0 & 0xff] ^ ctx->rk[r*4+1];
        t2 = Te0->data[(s2 >> 24) & 0xff] ^ Te1->data[(s3 >> 16) & 0xff] ^
             Te2->data[(s0 >> 8) & 0xff] ^ Te3->data[s1 & 0xff] ^ ctx->rk[r*4+2];
        t3 = Te0->data[(s3 >> 24) & 0xff] ^ Te1->data[(s0 >> 16) & 0xff] ^
             Te2->data[(s1 >> 8) & 0xff] ^ Te3->data[s2 & 0xff] ^ ctx->rk[r*4+3];

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    t0 = ((uint32_t)sbox[(s0 >> 24) & 0xff] << 24) |
         ((uint32_t)sbox[(s1 >> 16) & 0xff] << 16) |
         ((uint32_t)sbox[(s2 >> 8) & 0xff] << 8) |
         (uint32_t)sbox[s3 & 0xff];
    t1 = ((uint32_t)sbox[(s1 >> 24) & 0xff] << 24) |
         ((uint32_t)sbox[(s2 >> 16) & 0xff] << 16) |
         ((uint32_t)sbox[(s3 >> 8) & 0xff] << 8) |
         (uint32_t)sbox[s0 & 0xff];
    t2 = ((uint32_t)sbox[(s2 >> 24) & 0xff] << 24) |
         ((uint32_t)sbox[(s3 >> 16) & 0xff] << 16) |
         ((uint32_t)sbox[(s0 >> 8) & 0xff] << 8) |
         (uint32_t)sbox[s1 & 0xff];
    t3 = ((uint32_t)sbox[(s3 >> 24) & 0xff] << 24) |
         ((uint32_t)sbox[(s0 >> 16) & 0xff] << 16) |
         ((uint32_t)sbox[(s1 >> 8) & 0xff] << 8) |
         (uint32_t)sbox[s2 & 0xff];

    t0 ^= ctx->rk[ctx->rounds*4];
    t1 ^= ctx->rk[ctx->rounds*4+1];
    t2 ^= ctx->rk[ctx->rounds*4+2];
    t3 ^= ctx->rk[ctx->rounds*4+3];

    out[0] = (t0 >> 24) & 0xff; out[1] = (t0 >> 16) & 0xff;
    out[2] = (t0 >> 8) & 0xff; out[3] = t0 & 0xff;
    out[4] = (t1 >> 24) & 0xff; out[5] = (t1 >> 16) & 0xff;
    out[6] = (t1 >> 8) & 0xff; out[7] = t1 & 0xff;
    out[8] = (t2 >> 24) & 0xff; out[9] = (t2 >> 16) & 0xff;
    out[10] = (t2 >> 8) & 0xff; out[11] = t2 & 0xff;
    out[12] = (t3 >> 24) & 0xff; out[13] = (t3 >> 16) & 0xff;
    out[14] = (t3 >> 8) & 0xff; out[15] = t3 & 0xff;
}

/**
 * AES_decrypt() - AES解密函数
 * @in: 16字节密文输入
 * @out: 16字节明文输出
 * @ctx: AES上下文（包含解密轮密钥）
 * 
 * 作用：使用T表优化的AES解密
 * 
 * 解密流程：加密的逆过程
 * 1. 初始轮密钥加
 * 2. Nr-1轮主循环（使用Td表）
 * 3. 最后一轮（使用逆S盒）
 */
void AES_decrypt(const uint8_t *in, uint8_t *out, const AES_CTX *ctx) {
    if (g_shared_tables == NULL) {
        fprintf(stderr, "Error: Shared memory not initialized\n");
        return;
    }

    TTable *Td0 = &g_shared_tables->Td0;
    TTable *Td1 = &g_shared_tables->Td1;
    TTable *Td2 = &g_shared_tables->Td2;
    TTable *Td3 = &g_shared_tables->Td3;

    uint32_t s0, s1, s2, s3;
    uint32_t t0, t1, t2, t3;
    int r;

    s0 = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    s1 = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | (uint32_t)in[7];
    s2 = ((uint32_t)in[8] << 24) | ((uint32_t)in[9] << 16) | ((uint32_t)in[10] << 8) | (uint32_t)in[11];
    s3 = ((uint32_t)in[12] << 24) | ((uint32_t)in[13] << 16) | ((uint32_t)in[14] << 8) | (uint32_t)in[15];

    s0 ^= ctx->rk[0];
    s1 ^= ctx->rk[1];
    s2 ^= ctx->rk[2];
    s3 ^= ctx->rk[3];

    for (r = 1; r < ctx->rounds; r++) {
        t0 = Td0->data[(s0 >> 24) & 0xff] ^ Td1->data[(s3 >> 16) & 0xff] ^
             Td2->data[(s2 >> 8) & 0xff] ^ Td3->data[s1 & 0xff] ^ ctx->rk[r*4];
        t1 = Td0->data[(s1 >> 24) & 0xff] ^ Td1->data[(s0 >> 16) & 0xff] ^
             Td2->data[(s3 >> 8) & 0xff] ^ Td3->data[s2 & 0xff] ^ ctx->rk[r*4+1];
        t2 = Td0->data[(s2 >> 24) & 0xff] ^ Td1->data[(s1 >> 16) & 0xff] ^
             Td2->data[(s0 >> 8) & 0xff] ^ Td3->data[s3 & 0xff] ^ ctx->rk[r*4+2];
        t3 = Td0->data[(s3 >> 24) & 0xff] ^ Td1->data[(s2 >> 16) & 0xff] ^
             Td2->data[(s1 >> 8) & 0xff] ^ Td3->data[s0 & 0xff] ^ ctx->rk[r*4+3];

        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    t0 = ((uint32_t)inv_sbox[(s0 >> 24) & 0xff] << 24) |
         ((uint32_t)inv_sbox[(s3 >> 16) & 0xff] << 16) |
         ((uint32_t)inv_sbox[(s2 >> 8) & 0xff] << 8) |
         (uint32_t)inv_sbox[s1 & 0xff];
    t1 = ((uint32_t)inv_sbox[(s1 >> 24) & 0xff] << 24) |
         ((uint32_t)inv_sbox[(s0 >> 16) & 0xff] << 16) |
         ((uint32_t)inv_sbox[(s3 >> 8) & 0xff] << 8) |
         (uint32_t)inv_sbox[s2 & 0xff];
    t2 = ((uint32_t)inv_sbox[(s2 >> 24) & 0xff] << 24) |
         ((uint32_t)inv_sbox[(s1 >> 16) & 0xff] << 16) |
         ((uint32_t)inv_sbox[(s0 >> 8) & 0xff] << 8) |
         (uint32_t)inv_sbox[s3 & 0xff];
    t3 = ((uint32_t)inv_sbox[(s3 >> 24) & 0xff] << 24) |
         ((uint32_t)inv_sbox[(s2 >> 16) & 0xff] << 16) |
         ((uint32_t)inv_sbox[(s1 >> 8) & 0xff] << 8) |
         (uint32_t)inv_sbox[s0 & 0xff];

    t0 ^= ctx->rk[ctx->rounds*4];
    t1 ^= ctx->rk[ctx->rounds*4+1];
    t2 ^= ctx->rk[ctx->rounds*4+2];
    t3 ^= ctx->rk[ctx->rounds*4+3];

    out[0] = (t0 >> 24) & 0xff; out[1] = (t0 >> 16) & 0xff;
    out[2] = (t0 >> 8) & 0xff; out[3] = t0 & 0xff;
    out[4] = (t1 >> 24) & 0xff; out[5] = (t1 >> 16) & 0xff;
    out[6] = (t1 >> 8) & 0xff; out[7] = t1 & 0xff;
    out[8] = (t2 >> 24) & 0xff; out[9] = (t2 >> 16) & 0xff;
    out[10] = (t2 >> 8) & 0xff; out[11] = t2 & 0xff;
    out[12] = (t3 >> 24) & 0xff; out[13] = (t3 >> 16) & 0xff;
    out[14] = (t3 >> 8) & 0xff; out[15] = t3 & 0xff;
}

/**
 * aes_encrypt_full() - 完整的AES加密（一次性调用）
 * @in: 明文
 * @out: 密文
 * @key: 密钥
 * @key_bits: 密钥位数
 * 
 * 作用：便捷函数，一次调用完成密钥设置和加密
 */
void aes_encrypt_full(const uint8_t *in, uint8_t *out, const uint8_t *key, int key_bits) {
    AES_CTX ctx;
    AES_set_encrypt_key(key, key_bits, &ctx);
    AES_encrypt(in, out, &ctx);
}

/**
 * aes_decrypt_full() - 完整的AES解密（一次性调用）
 */
void aes_decrypt_full(const uint8_t *in, uint8_t *out, const uint8_t *key, int key_bits) {
    AES_CTX ctx;
    AES_set_decrypt_key(key, key_bits, &ctx);
    AES_decrypt(in, out, &ctx);
}

/**
 * AES_key_expansion() - 导出轮密钥
 * @key: 用户密钥
 * @key_bits: 密钥位数
 * @rk: 轮密钥输出数组
 * 
 * 作用：将所有轮密钥导出到指定数组
 * 用于密钥恢复验证
 */
void AES_key_expansion(const uint8_t *key, int key_bits, uint32_t *rk) {
    AES_CTX ctx;
    AES_set_encrypt_key(key, key_bits, &ctx);
    memcpy(rk, ctx.rk, (ctx.rounds + 1) * 4 * sizeof(uint32_t));
}

/**
 * verify_kd1_candidate() - 验证Kd1候选值（占位函数）
 */
int verify_kd1_candidate(uint8_t *K14, uint8_t *Kd1_candidate) {
    (void)K14;
    (void)Kd1_candidate;
    return 1;
}

/**
 * recover_kd1_from_k13() - 从K13恢复Kd1
 * @K13: AES-256的第13轮密钥
 * @Kd1_out: 输出的解密第1轮密钥
 * 返回：0成功
 * 
 * 作用：用于AES-256攻击的第二阶段
 * 
 * 原理：
 * Kd1 = InvMixColumns(K13)
 * Kd1是AES-256解密的第一轮密钥
 * 
 * 注意：AES-256密钥扩展中，K13不能仅从K14推导（需要K11），
 * 因此K13必须通过EBD方法独立恢复。
 */
int recover_kd1_from_k13(const uint8_t *K13, uint8_t *Kd1_out) {
    uint32_t k13[4];
    for (int i = 0; i < 4; i++) {
        k13[i] = ((uint32_t)K13[4*i] << 24) | ((uint32_t)K13[4*i+1] << 16) |
                  ((uint32_t)K13[4*i+2] << 8) | (uint32_t)K13[4*i+3];
    }

    for (int col = 0; col < 4; col++) {
        uint8_t x0 = (k13[0] >> (24 - col*8)) & 0xff;
        uint8_t x1 = (k13[1] >> (24 - col*8)) & 0xff;
        uint8_t x2 = (k13[2] >> (24 - col*8)) & 0xff;
        uint8_t x3 = (k13[3] >> (24 - col*8)) & 0xff;

        uint32_t res = ((uint32_t)gmul(x0, 0x0e) ^ gmul(x1, 0x0b) ^ gmul(x2, 0x0d) ^ gmul(x3, 0x09)) << 24 |
                       ((uint32_t)gmul(x0, 0x09) ^ gmul(x1, 0x0e) ^ gmul(x2, 0x0b) ^ gmul(x3, 0x0d)) << 16 |
                       ((uint32_t)gmul(x0, 0x0d) ^ gmul(x1, 0x09) ^ gmul(x2, 0x0e) ^ gmul(x3, 0x0b)) << 8 |
                       ((uint32_t)gmul(x0, 0x0b) ^ gmul(x1, 0x0d) ^ gmul(x2, 0x09) ^ gmul(x3, 0x0e));

        Kd1_out[col*4] = (res >> 24) & 0xff;
        Kd1_out[col*4 + 1] = (res >> 16) & 0xff;
        Kd1_out[col*4 + 2] = (res >> 8) & 0xff;
        Kd1_out[col*4 + 3] = res & 0xff;
    }

    return 0;
}

/**
 * recover_original_key_aes128() - 从K10逆向恢复原始密钥K0
 * @K_last: 最后一轮密钥K10（16字节）
 * @original_key: 输出的原始密钥K0（16字节）
 * 
 * 原理：逆向密钥扩展
 * 
 * 正向扩展：W[i] = W[i-4] ^ SubWord(RotWord(W[i-1])) ^ Rcon[i/4]  (当i%4==0)
 * 逆向推导：W[i-4] = W[i] ^ SubWord(RotWord(W[i-1])) ^ Rcon[i/4]
 * 
 * 从W[43]逆向推导到W[0]
 */
int recover_original_key_aes128(const uint8_t *K_last, uint8_t *original_key) {
    uint32_t W[44];
    
    // 将K10复制到W[40..43]
    for (int i = 0; i < 4; i++) {
        W[40 + i] = ((uint32_t)K_last[4*i] << 24) | 
                    ((uint32_t)K_last[4*i+1] << 16) |
                    ((uint32_t)K_last[4*i+2] << 8) | 
                    (uint32_t)K_last[4*i+3];
    }
    
    // 逆向推导：从W[43]到W[0]
    for (int i = 43; i >= 4; i--) {
        uint32_t temp = W[i-1];
        
        // 如果i是4的倍数，需要特殊处理
        if (i % 4 == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[i/4];
        }
        
        W[i-4] = W[i] ^ temp;
    }
    
    // 输出原始密钥K0 = W[0..3]
    for (int i = 0; i < 4; i++) {
        original_key[4*i] = (W[i] >> 24) & 0xff;
        original_key[4*i+1] = (W[i] >> 16) & 0xff;
        original_key[4*i+2] = (W[i] >> 8) & 0xff;
        original_key[4*i+3] = W[i] & 0xff;
    }
    
    return 0;
}

/**
 * recover_original_key_aes192() - 从K12逆向恢复原始密钥
 * @K_last: 最后一轮密钥K12（16字节）
 * @original_key: 输出的原始密钥（24字节）
 * 
 * AES-192密钥扩展：Nk=6, Nr=12
 * W[0..5] = 原始密钥（24字节）
 * K12 = W[48..51]
 */
int recover_original_key_aes192(const uint8_t *K_last, uint8_t *original_key) {
    uint32_t W[52];
    
    // 将K12复制到W[48..51]
    for (int i = 0; i < 4; i++) {
        W[48 + i] = ((uint32_t)K_last[4*i] << 24) | 
                    ((uint32_t)K_last[4*i+1] << 16) |
                    ((uint32_t)K_last[4*i+2] << 8) | 
                    (uint32_t)K_last[4*i+3];
    }
    
    // 逆向推导：从W[51]到W[0]
    for (int i = 51; i >= 6; i--) {
        uint32_t temp = W[i-1];
        
        // 如果i是6的倍数，需要特殊处理
        if (i % 6 == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[i/6];
        }
        
        W[i-6] = W[i] ^ temp;
    }
    
    // 输出原始密钥（24字节）= W[0..5]
    for (int i = 0; i < 6; i++) {
        original_key[4*i] = (W[i] >> 24) & 0xff;
        original_key[4*i+1] = (W[i] >> 16) & 0xff;
        original_key[4*i+2] = (W[i] >> 8) & 0xff;
        original_key[4*i+3] = W[i] & 0xff;
    }
    
    return 0;
}

/**
 * recover_original_key_aes256() - 从K14逆向恢复原始密钥
 * @K_last: 最后一轮密钥K14（16字节）
 * @original_key: 输出的原始密钥（32字节）
 * 
 * AES-256密钥扩展：Nk=8, Nr=14
 * W[0..7] = 原始密钥（32字节）
 * K14 = W[56..59]
 * 
 * 注意：AES-256的密钥扩展更复杂
 * 当i%8==0: temp = SubWord(RotWord(W[i-1])) ^ Rcon[i/8]
 * 当i%8==4: temp = SubWord(W[i-1])
 */
int recover_original_key_aes256(const uint8_t *K_last, uint8_t *original_key) {
    uint32_t W[60];
    
    // 将K14复制到W[56..59]
    for (int i = 0; i < 4; i++) {
        W[56 + i] = ((uint32_t)K_last[4*i] << 24) | 
                    ((uint32_t)K_last[4*i+1] << 16) |
                    ((uint32_t)K_last[4*i+2] << 8) | 
                    (uint32_t)K_last[4*i+3];
    }
    
    // 逆向推导：从W[59]到W[0]
    for (int i = 59; i >= 8; i--) {
        uint32_t temp = W[i-1];
        
        // 如果i是8的倍数
        if (i % 8 == 0) {
            temp = sub_word(rot_word(temp)) ^ rcon[i/8];
        }
        // 如果i%8==4
        else if (i % 8 == 4) {
            temp = sub_word(temp);
        }
        
        W[i-8] = W[i] ^ temp;
    }
    
    // 输出原始密钥（32字节）= W[0..7]
    for (int i = 0; i < 8; i++) {
        original_key[4*i] = (W[i] >> 24) & 0xff;
        original_key[4*i+1] = (W[i] >> 16) & 0xff;
        original_key[4*i+2] = (W[i] >> 8) & 0xff;
        original_key[4*i+3] = W[i] & 0xff;
    }
    
    return 0;
}
