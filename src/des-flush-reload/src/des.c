/**
 * des.c - DES 加密算法实现
 * 
 * 本文件实现了完整的 DES (Data Encryption Standard) 加密算法
 * 包含标准 DES 的所有组件：初始置换、轮函数、S-box 替换、密钥调度等
 * 
 * 特别设计用于缓存侧信道攻击研究：
 * - S-box 采用特殊内存布局（每条目 64 字节对齐）
 * - 提供只执行第一轮的函数用于攻击测试
 * - 导出函数供外部程序（spy.c）动态链接调用
 */

#include <stdio.h> 
#include <stdint.h>

#include "des.h"  // DES算法定义和置换表

/**
 * S[8] - 8个S-box查找表（标准DES）
 * 
 * DES使用8个不同的S-box，每个S-box：
 * - 输入：6位（0-63）
 * - 输出：4位（0-15）
 * - 存储：64个条目，每个条目64字节对齐
 * 
 * 布局原理：
 * - 每个条目占64字节 = 1个缓存行
 * - 攻击者通过检测哪个缓存行被访问，推断访问了哪个条目
 * 
 * 重要：S定义在des.c中，确保只有一个实例
 * 其他文件通过get_sboxes()函数获取S的地址
 */
SBox S[8] = {
    // S-box 1：标准DES S1
    {ENTRY(14), ENTRY(4), ENTRY(13), ENTRY(1), ENTRY(2), ENTRY(15), ENTRY(11), ENTRY(8),
     ENTRY(3), ENTRY(10), ENTRY(6), ENTRY(12), ENTRY(5), ENTRY(9), ENTRY(0), ENTRY(7),
     ENTRY(0), ENTRY(15), ENTRY(7), ENTRY(4), ENTRY(14), ENTRY(2), ENTRY(13), ENTRY(1),
     ENTRY(10), ENTRY(6), ENTRY(12), ENTRY(11), ENTRY(9), ENTRY(5), ENTRY(3), ENTRY(8),
     ENTRY(4), ENTRY(1), ENTRY(14), ENTRY(8), ENTRY(13), ENTRY(6), ENTRY(2), ENTRY(11),
     ENTRY(15), ENTRY(12), ENTRY(9), ENTRY(7), ENTRY(3), ENTRY(10), ENTRY(5), ENTRY(0),
     ENTRY(15), ENTRY(12), ENTRY(8), ENTRY(2), ENTRY(4), ENTRY(9), ENTRY(1), ENTRY(7),
     ENTRY(5), ENTRY(11), ENTRY(3), ENTRY(14), ENTRY(10), ENTRY(0), ENTRY(6), ENTRY(13)},
    
    // S-box 2：标准DES S2
    {ENTRY(15), ENTRY(1), ENTRY(8), ENTRY(14), ENTRY(6), ENTRY(11), ENTRY(3), ENTRY(4),
     ENTRY(9), ENTRY(7), ENTRY(2), ENTRY(13), ENTRY(12), ENTRY(0), ENTRY(5), ENTRY(10),
     ENTRY(3), ENTRY(13), ENTRY(4), ENTRY(7), ENTRY(15), ENTRY(2), ENTRY(8), ENTRY(14),
     ENTRY(12), ENTRY(0), ENTRY(1), ENTRY(10), ENTRY(6), ENTRY(9), ENTRY(11), ENTRY(5),
     ENTRY(0), ENTRY(14), ENTRY(7), ENTRY(11), ENTRY(10), ENTRY(4), ENTRY(13), ENTRY(1),
     ENTRY(5), ENTRY(8), ENTRY(12), ENTRY(6), ENTRY(9), ENTRY(3), ENTRY(2), ENTRY(15),
     ENTRY(13), ENTRY(8), ENTRY(10), ENTRY(1), ENTRY(3), ENTRY(15), ENTRY(4), ENTRY(2),
     ENTRY(11), ENTRY(6), ENTRY(7), ENTRY(12), ENTRY(0), ENTRY(5), ENTRY(14), ENTRY(9)},
    
    // S-box 3：标准DES S3
    {ENTRY(10), ENTRY(0), ENTRY(9), ENTRY(14), ENTRY(6), ENTRY(3), ENTRY(15), ENTRY(5),
     ENTRY(1), ENTRY(13), ENTRY(12), ENTRY(7), ENTRY(11), ENTRY(4), ENTRY(2), ENTRY(8),
     ENTRY(13), ENTRY(7), ENTRY(0), ENTRY(9), ENTRY(3), ENTRY(4), ENTRY(6), ENTRY(10),
     ENTRY(2), ENTRY(8), ENTRY(5), ENTRY(14), ENTRY(12), ENTRY(11), ENTRY(15), ENTRY(1),
     ENTRY(13), ENTRY(6), ENTRY(4), ENTRY(9), ENTRY(8), ENTRY(15), ENTRY(3), ENTRY(0),
     ENTRY(11), ENTRY(1), ENTRY(2), ENTRY(12), ENTRY(5), ENTRY(10), ENTRY(14), ENTRY(7),
     ENTRY(1), ENTRY(10), ENTRY(13), ENTRY(0), ENTRY(6), ENTRY(9), ENTRY(8), ENTRY(7),
     ENTRY(4), ENTRY(15), ENTRY(14), ENTRY(3), ENTRY(11), ENTRY(5), ENTRY(2), ENTRY(12)},
    
    // S-box 4：标准DES S4
    {ENTRY(7), ENTRY(13), ENTRY(14), ENTRY(3), ENTRY(0), ENTRY(6), ENTRY(9), ENTRY(10),
     ENTRY(1), ENTRY(2), ENTRY(8), ENTRY(5), ENTRY(11), ENTRY(12), ENTRY(4), ENTRY(15),
     ENTRY(13), ENTRY(8), ENTRY(11), ENTRY(5), ENTRY(6), ENTRY(15), ENTRY(0), ENTRY(3),
     ENTRY(4), ENTRY(7), ENTRY(2), ENTRY(12), ENTRY(1), ENTRY(10), ENTRY(14), ENTRY(9),
     ENTRY(10), ENTRY(6), ENTRY(9), ENTRY(0), ENTRY(12), ENTRY(11), ENTRY(7), ENTRY(13),
     ENTRY(15), ENTRY(1), ENTRY(3), ENTRY(14), ENTRY(5), ENTRY(2), ENTRY(8), ENTRY(4),
     ENTRY(3), ENTRY(15), ENTRY(0), ENTRY(6), ENTRY(10), ENTRY(1), ENTRY(13), ENTRY(8),
     ENTRY(9), ENTRY(4), ENTRY(5), ENTRY(11), ENTRY(12), ENTRY(7), ENTRY(2), ENTRY(14)},
    
    // S-box 5：标准DES S5
    {ENTRY(2), ENTRY(12), ENTRY(4), ENTRY(1), ENTRY(7), ENTRY(10), ENTRY(11), ENTRY(6),
     ENTRY(8), ENTRY(5), ENTRY(3), ENTRY(15), ENTRY(13), ENTRY(0), ENTRY(14), ENTRY(9),
     ENTRY(14), ENTRY(11), ENTRY(2), ENTRY(12), ENTRY(4), ENTRY(7), ENTRY(13), ENTRY(1),
     ENTRY(5), ENTRY(0), ENTRY(15), ENTRY(10), ENTRY(3), ENTRY(9), ENTRY(8), ENTRY(6),
     ENTRY(4), ENTRY(2), ENTRY(1), ENTRY(11), ENTRY(10), ENTRY(13), ENTRY(7), ENTRY(8),
     ENTRY(15), ENTRY(9), ENTRY(12), ENTRY(5), ENTRY(6), ENTRY(3), ENTRY(0), ENTRY(14),
     ENTRY(11), ENTRY(8), ENTRY(12), ENTRY(7), ENTRY(1), ENTRY(14), ENTRY(2), ENTRY(13),
     ENTRY(6), ENTRY(15), ENTRY(0), ENTRY(9), ENTRY(10), ENTRY(4), ENTRY(5), ENTRY(3)},
    
    // S-box 6：标准DES S6
    {ENTRY(12), ENTRY(1), ENTRY(10), ENTRY(15), ENTRY(9), ENTRY(2), ENTRY(6), ENTRY(8),
     ENTRY(0), ENTRY(13), ENTRY(3), ENTRY(4), ENTRY(14), ENTRY(7), ENTRY(5), ENTRY(11),
     ENTRY(10), ENTRY(15), ENTRY(4), ENTRY(2), ENTRY(7), ENTRY(12), ENTRY(9), ENTRY(5),
     ENTRY(6), ENTRY(1), ENTRY(13), ENTRY(14), ENTRY(0), ENTRY(11), ENTRY(3), ENTRY(8),
     ENTRY(9), ENTRY(14), ENTRY(15), ENTRY(5), ENTRY(2), ENTRY(8), ENTRY(12), ENTRY(3),
     ENTRY(7), ENTRY(0), ENTRY(4), ENTRY(10), ENTRY(1), ENTRY(13), ENTRY(11), ENTRY(6),
     ENTRY(4), ENTRY(3), ENTRY(2), ENTRY(12), ENTRY(9), ENTRY(5), ENTRY(15), ENTRY(10),
     ENTRY(11), ENTRY(14), ENTRY(1), ENTRY(7), ENTRY(6), ENTRY(0), ENTRY(8), ENTRY(13)},
    
    // S-box 7：标准DES S7
    {ENTRY(4), ENTRY(11), ENTRY(2), ENTRY(14), ENTRY(15), ENTRY(0), ENTRY(8), ENTRY(13),
     ENTRY(3), ENTRY(12), ENTRY(9), ENTRY(7), ENTRY(5), ENTRY(10), ENTRY(6), ENTRY(1),
     ENTRY(13), ENTRY(0), ENTRY(11), ENTRY(7), ENTRY(4), ENTRY(9), ENTRY(1), ENTRY(10),
     ENTRY(14), ENTRY(3), ENTRY(5), ENTRY(12), ENTRY(2), ENTRY(15), ENTRY(8), ENTRY(6),
     ENTRY(1), ENTRY(4), ENTRY(11), ENTRY(13), ENTRY(12), ENTRY(3), ENTRY(7), ENTRY(14),
     ENTRY(10), ENTRY(15), ENTRY(6), ENTRY(8), ENTRY(0), ENTRY(5), ENTRY(9), ENTRY(2),
     ENTRY(6), ENTRY(11), ENTRY(13), ENTRY(8), ENTRY(1), ENTRY(4), ENTRY(10), ENTRY(7),
     ENTRY(9), ENTRY(5), ENTRY(0), ENTRY(15), ENTRY(14), ENTRY(2), ENTRY(3), ENTRY(12)},
    
    // S-box 8：标准DES S8
    {ENTRY(13), ENTRY(2), ENTRY(8), ENTRY(4), ENTRY(6), ENTRY(15), ENTRY(11), ENTRY(1),
     ENTRY(10), ENTRY(9), ENTRY(3), ENTRY(14), ENTRY(5), ENTRY(0), ENTRY(12), ENTRY(7),
     ENTRY(1), ENTRY(15), ENTRY(13), ENTRY(8), ENTRY(10), ENTRY(3), ENTRY(7), ENTRY(4),
     ENTRY(12), ENTRY(5), ENTRY(6), ENTRY(11), ENTRY(0), ENTRY(14), ENTRY(9), ENTRY(2),
     ENTRY(7), ENTRY(11), ENTRY(4), ENTRY(1), ENTRY(9), ENTRY(12), ENTRY(14), ENTRY(2),
     ENTRY(0), ENTRY(6), ENTRY(10), ENTRY(13), ENTRY(15), ENTRY(3), ENTRY(5), ENTRY(8),
     ENTRY(2), ENTRY(1), ENTRY(14), ENTRY(7), ENTRY(4), ENTRY(10), ENTRY(8), ENTRY(13),
     ENTRY(15), ENTRY(12), ENTRY(9), ENTRY(0), ENTRY(3), ENTRY(5), ENTRY(6), ENTRY(11)}
};

/**
 * permute - 通用置换函数
 * 
 * 功能：按照置换表对输入数据进行位重排
 * 
 * 参数：
 *   input      - 输入数据
 *   table      - 置换表（每个元素表示取输入的第几位）
 *   size       - 置换表大小（输出位数）
 *   input_bits - 输入数据的位数
 * 
 * 返回值：置换后的输出数据
 * 
 * 算法：
 * 1. 遍历置换表的每个位置 i
 * 2. table[i] 表示输出第 i 位应该取输入的第 table[i] 位
 * 3. 从输入中提取该位，添加到输出的最低位
 * 4. 输出整体左移，为新位腾出位置
 * 
 * 示例：
 *   输入：0b1010 (input_bits=4)
 *   表：{4, 2} (size=2，表示取第 4 位和第 2 位)
 *   输出：0b10 (取第 4 位的 1 和第 2 位的 0)
 */
static uint64_t permute(uint64_t input, const uint8_t *table, uint8_t size, uint8_t input_bits) {
    uint64_t output = 0;  // 初始化输出为 0
    
    // 遍历置换表的每个条目
    for (uint8_t i = 0; i < size; i++) {
        // 计算需要提取的位在输入中的偏移量
        // table[i] 是 1-based 索引（DES 标准），需要转换为 0-based
        uint8_t shift = input_bits - table[i];
        
        // 提取该位：(input >> shift) & 1
        // 将提取的位添加到输出的最低位
        uint64_t bit = (input >> shift) & 1;
        
        // 输出左移一位，为新位腾出位置，然后 OR 上新位
        output = (output << 1) | bit;
    }
    return output;
}

/**
 * expand - E 扩展函数
 * 
 * 功能：将 32 位的 R 扩展为 48 位
 * 
 * 参数：
 *   input - 32 位输入（右半部分 R）
 * 
 * 返回值：48 位扩展后的输出
 * 
 * 算法：
 * 1. 使用 E 表定义的规则，从 32 位输入中选择 48 位
 * 2. 某些输入位会被多次使用（如位 1 出现在输出位 2 和 48）
 * 3. 扩展后的数据将与 48 位轮密钥进行异或
 * 
 * 注意：虽然返回值是 uint64_t，但只有低 48 位有效
 */
static uint64_t expand(uint32_t input) {
    uint64_t output = 0;  // 初始化输出为 0
    
    // 遍历 E 表的 48 个条目
    for (uint8_t i = 0; i < 48; i++) {
        // E[i] 表示输出第 i 位取自输入的第 E[i] 位
        // 转换为 0-based 索引：bit_pos = E[i] - 1
        uint8_t bit_pos = E[i] - 1;
        
        // 计算在 32 位输入中的偏移量（MSB 为位 31）
        uint8_t shift = 31 - bit_pos;
        
        // 提取该位并添加到输出
        output = (output << 1) | (((uint64_t)input >> shift) & 1);
    }
    return output;
}

/**
 * s_box_substitution - S-box 替换函数（核心操作，侧信道攻击目标）
 * 
 * 功能：将 48 位输入通过 8 个 S-box 替换为 32 位输出
 * 
 * 参数：
 *   input - 48 位输入（E 扩展后的数据与轮密钥异或的结果）
 * 
 * 返回值：32 位替换后的输出
 * 
 * 算法：
 * 1. 将 48 位输入分为 8 个 6 位块（每个 S-box 处理一个块）
 * 2. 对每个 6 位块：
 *    - 提取行号：第 1 位和第 6 位（0-3）
 *    - 提取列号：中间 4 位（0-15）
 *    - 计算 S-box 索引：row * 16 + col（0-63）
 *    - 查表获取 4 位输出值
 * 3. 将 8 个 4 位输出拼接成 32 位结果
 * 
 * 侧信道攻击关键点：
 * - 访问 S[i].data[index][0] 会将该内存位置加载到缓存
 * - 攻击者通过监控缓存访问模式，推断访问了哪个 index
 * - 从而恢复 6 位输入（与轮密钥相关）
 */
static uint32_t s_box_substitution(uint64_t input) {
    uint32_t output = 0;  // 初始化 32 位输出为 0
    
    // 处理 8 个 S-box
    for (uint8_t i = 0; i < 8; i++) {
        // 提取第 i 个 6 位块（从高位到低位）
        // 第 0 个块在最高位（位 47-42），第 7 个块在最低位（位 5-0）
        uint8_t block = (input >> (42 - i * 6)) & 0x3F;  // 0x3F = 0b111111
        
        // 提取行号：6 位块的第 1 位（最高位）和第 6 位（最低位）
        // row = bit1 << 1 | bit6，范围 0-3
        uint8_t row = (((block >> 5) & 0x1) << 1) | (block & 0x1);
        
        // 提取列号：中间 4 位（位 5-2）
        // col 范围 0-15
        uint8_t col = (block >> 1) & 0xF;  // 0xF = 0b1111
        
        // 计算在 S-box 表中的索引：row * 16 + col（0-63）
        uint8_t index = row * 16 + col;
        
        // 关键操作：访问 S-box 条目
        // S[i].data[index][0] 访问第 i 个 S-box 的第 index 个条目的第 0 个元素
        // 这个访问会被加载到 CPU 缓存，成为侧信道攻击的目标
        uint8_t s_val = S[i].data[index][0];
        
        // 将 4 位 S-box 输出添加到结果的最低位
        // 先左移 4 位腾出空间，然后 OR 上新值
        output = (output << 4) | s_val;
    }
    return output;
}

/**
 * p_permute - P 盒置换函数
 * 
 * 功能：对 S-box 替换后的 32 位输出进行位重排
 * 
 * 参数：
 *   input - 32 位输入（S-box 替换的输出）
 * 
 * 返回值：32 位置换后的输出
 * 
 * 算法：
 * 1. 按照 P 表的定义，从 32 位输入中选择 32 位
 * 2. 提供扩散效果：使输出位依赖于多个 S-box 的输出
 * 
 * 用途：在轮函数 f 的最后一步执行，增加密码的扩散性
 */
static uint32_t p_permute(uint32_t input) {
    uint32_t output = 0;  // 初始化输出为 0
    
    // 遍历 P 表的 32 个条目
    for (uint8_t i = 0; i < 32; i++) {
        // P[i] 表示输出第 i 位取自输入的第 P[i] 位
        // 计算偏移量（MSB 为位 32）
        uint8_t shift = 32 - P[i];
        
        // 提取该位并添加到输出
        output = (output << 1) | ((input >> shift) & 1);
    }
    return output;
}

/**
 * des_f - DES 轮函数（Feistel 网络的核心）
 * 
 * 功能：计算一轮 DES 的 f 函数值
 * 
 * 参数：
 *   R - 32 位右半部分输入
 *   K - 48 位轮密钥
 * 
 * 返回值：32 位 f 函数输出
 * 
 * 算法步骤：
 * 1. E 扩展：将 32 位 R 扩展为 48 位
 * 2. 轮密钥加：与 48 位轮密钥进行异或
 * 3. S-box 替换：48 位 -> 32 位（非线性变换，侧信道攻击目标）
 * 4. P 盒置换：32 位 -> 32 位（扩散）
 * 
 * 数学表达：f(R, K) = P(S(E(R) ⊕ K))
 * 其中 ⊕ 表示异或运算
 */
static uint32_t des_f(uint32_t R, uint64_t K) {
    // 步骤 1：E 扩展，32 位 -> 48 位
    uint64_t expanded = expand(R);
    
    // 步骤 2：与轮密钥异或（轮密钥加）
    // 注意：K 虽然是 uint64_t，但只有低 48 位有效
    uint64_t xored = expanded ^ K;
    
    // 步骤 3：S-box 替换，48 位 -> 32 位
    // 这是非线性变换，提供密码的强度
    // 也是侧信道攻击的关键目标（通过缓存监控推断输入）
    uint32_t substituted = s_box_substitution(xored);
    
    // 步骤 4：P 盒置换，提供扩散
    return p_permute(substituted);
}

/**
 * generate_round_keys - 轮密钥生成函数（密钥调度算法）
 * 
 * 功能：从 64 位主密钥生成 16 个 48 位轮密钥
 * 
 * 参数：
 *   key         - 64 位主密钥（包含 8 位奇偶校验）
 *   round_keys  - 输出数组，存储生成的 16 个轮密钥
 * 
 * 算法步骤：
 * 1. PC-1 置换：64 位 -> 56 位，去掉奇偶校验位
 * 2. 将 56 位分为 C0（高 28 位）和 D0（低 28 位）
 * 3. 对于 i = 1 到 16：
 *    a. Ci = 循环左移(Ci-1, SHIFTS[i-1])
 *    b. Di = 循环左移(Di-1, SHIFTS[i-1])
 *    c. 拼接 Ci 和 Di 得到 56 位
 *    d. PC-2 置换：56 位 -> 48 位，得到轮密钥 Ki
 * 
 * 侧信道攻击关联：
 * - 攻击目标是恢复 K1（第一轮轮密钥）
 * - 从 K1 可以反推 48 位密钥信息
 * - 剩余 8 位需要暴力枚举
 */
static void generate_round_keys(uint64_t key, uint64_t round_keys[16]) {
    // 步骤 1：PC-1 置换，64 位 -> 56 位
    // 去掉 8 个奇偶校验位，重新排列剩余 56 位
    uint64_t permuted = permute(key, PC1, 56, 64);
    
    // 步骤 2：将 56 位分为 C 和 D 两个 28 位寄存器
    // C：高 28 位（位 56-29）
    uint32_t C = (permuted >> 28) & 0xFFFFFFF;  // 0xFFFFFFF = 28 个 1
    // D：低 28 位（位 28-1）
    uint32_t D = permuted & 0xFFFFFFF;
    
    // 步骤 3：生成 16 个轮密钥
    for (uint8_t i = 0; i < 16; i++) {
        // 获取当前轮的左移位数（1 或 2）
        uint8_t shift = SHIFTS[i];
        
        // 循环左移 C 寄存器
        // 左移 shift 位，将移出的位放到右侧
        C = ((C << shift) | (C >> (28 - shift))) & 0xFFFFFFF;
        
        // 循环左移 D 寄存器
        D = ((D << shift) | (D >> (28 - shift))) & 0xFFFFFFF;
        
        // 拼接 C 和 D 得到 56 位（CiDi）
        uint64_t CD = ((uint64_t)C << 28) | D;
        
        // PC-2 置换：56 位 -> 48 位，丢弃 8 位
        // 结果存储为当前轮的轮密钥
        round_keys[i] = permute(CD, PC2, 48, 56);
    }
}

/**
 * des_encrypt - 完整 DES 加密函数
 * 
 * 功能：执行完整的 16 轮 DES 加密
 * 
 * 参数：
 *   plaintext   - 64 位明文输入
 *   key         - 64 位密钥（包含 8 位奇偶校验）
 *   ciphertext  - 输出参数，64 位密文结果
 * 
 * 算法步骤：
 * 1. 生成 16 个轮密钥
 * 2. 初始置换（IP）：64 位 -> 64 位
 * 3. 将结果分为 L0（高 32 位）和 R0（低 32 位）
 * 4. 16 轮 Feistel 网络迭代：
 *    Li = Ri-1
 *    Ri = Li-1 ⊕ f(Ri-1, Ki)
 * 5. 逆初始置换（IP^-1）：64 位 -> 64 位密文
 * 
 * 注意：DES 最后一轮后不交换 L 和 R，所以直接拼接 R16L16
 */
void des_encrypt(uint64_t plaintext, uint64_t key, uint64_t *ciphertext) {
    // 步骤 1：生成 16 个轮密钥
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);
    
    // 步骤 2：初始置换 IP
    uint64_t ip = permute(plaintext, IP, 64, 64);
    
    // 步骤 3：分为 L0 和 R0
    uint32_t L = (uint32_t)(ip >> 32);  // 高 32 位
    uint32_t R = (uint32_t)(ip & 0xFFFFFFFF);  // 低 32 位
    
    // 步骤 4：16 轮 Feistel 迭代
    for (uint8_t i = 0; i < 16; i++) {
        // 保存当前的 R 作为下一轮的 L
        uint32_t temp = R;
        
        // 计算新的 R：L ⊕ f(R, K)
        // f 是轮函数，包含 E 扩展、轮密钥加、S-box、P 置换
        R = L ^ des_f(R, round_keys[i]);
        
        // 更新 L 为原来的 R
        L = temp;
    }
    
    // 步骤 5：最后一轮后不交换，直接拼接 R16（高）和 L16（低）
    uint64_t pre_output = ((uint64_t)R << 32) | (uint64_t)L;
    
    // 步骤 6：逆初始置换，得到最终密文
    *ciphertext = permute(pre_output, IP_INV, 64, 64);
}

/**
 * des_encrypt_first_round - 只执行 DES 第一轮（用于侧信道攻击）
 * 
 * 功能：执行 DES 的初始置换和第一轮加密，然后返回结果
 * 
 * 参数：
 *   plaintext - 64 位明文输入
 *   key       - 64 位密钥
 *   result    - 输出参数，第一轮后的 64 位结果（L1R1）
 * 
 * 算法：
 * 与完整加密相同，但只执行第一轮后停止
 * 结果格式：高 32 位是 L1，低 32 位是 R1
 * 
 * 用途：
 * - 侧信道攻击中，只执行第一轮可以简化分析
 * - 攻击者通过监控第一轮的 S-box 访问，恢复 K1
 * - 避免后续轮次的干扰
 */
void des_encrypt_first_round(uint64_t plaintext, uint64_t key, uint64_t *result) {
    // 生成所有轮密钥（虽然只用第 0 个）
    uint64_t round_keys[16];
    generate_round_keys(key, round_keys);
    
    // 初始置换
    uint64_t ip = permute(plaintext, IP, 64, 64);
    
    // 分为 L0 和 R0
    uint32_t L = (uint32_t)(ip >> 32);
    uint32_t R = (uint32_t)(ip & 0xFFFFFFFF);
    
    // 只执行第一轮
    uint32_t temp = R;
    R = L ^ des_f(R, round_keys[0]);  // 使用 K1（round_keys[0]）
    L = temp;
    
    // 返回 L1 和 R1 的拼接
    *result = ((uint64_t)L << 32) | (uint64_t)R;
}

/**
 * get_sboxes - 导出 S-box 数组地址
 * 
 * 功能：返回 S-box 数组的起始地址，供外部程序使用
 * 
 * 返回值：指向 S[0] 的指针（SBox* 类型）
 * 
 * 用途：
 * - spy.c 通过动态链接调用此函数
 * - 获取 S-box 的内存地址后，可以对其执行 Flush+Reload 操作
 * - 这是实现缓存侧信道攻击的关键
 * 
 * 注意：返回的是静态数组的地址，生命周期与程序相同
 */
SBox* get_sboxes(void) {
    return &S[0];  // 返回 S-box 数组的起始地址
}

/**
 * des_encrypt_full - 导出完整加密函数
 * 
 * 功能：对外提供完整 DES 加密的接口
 * 
 * 参数：
 *   plaintext   - 64 位明文
 *   key         - 64 位密钥
 *   ciphertext  - 输出参数，64 位密文
 * 
 * 用途：
 * - spy.c 通过动态链接调用此函数
 * - 用于验证恢复的密钥是否正确
 * - 与 des_encrypt 功能相同，只是包装为导出函数
 */
void des_encrypt_full(uint64_t plaintext, uint64_t key, uint64_t *ciphertext) {
    des_encrypt(plaintext, key, ciphertext);
}

/**
 * main - 测试主函数
 * 
 * 功能：验证 DES 实现的正确性
 * 
 * 测试用例：
 * 1. NIST 标准测试向量：
 *    明文：0x0123456789ABCDEF
 *    密钥：0x133457799BBCDFF1
 *    期望密文：0x85E813540F0AB405
 * 
 * 2. 全零测试：
 *    明文：0x0000000000000000
 *    密钥：0x0000000000000000
 *    期望密文：0x8CA64DE9C1B123A7
 * 
 * 返回值：
 *   0 - 所有测试通过
 *   1 - 有测试失败
 */
#ifdef DES_STANDALONE_TEST
int main() {
    // ========== 测试 1：NIST 标准测试向量 ==========
    uint64_t key = 0x133457799BBCDFF1ULL;       // NIST 标准测试密钥
    uint64_t plaintext = 0x0123456789ABCDEFULL; // NIST 标准测试明文
    uint64_t expected = 0x85E813540F0AB405ULL;  // NIST 标准期望密文
    
    uint64_t ciphertext;
    des_encrypt(plaintext, key, &ciphertext);
    
    printf("=== DES Test ===\n");
    printf("Plaintext:  %016lX\n", (unsigned long)plaintext);
    printf("Key:        %016lX\n", (unsigned long)key);
    printf("Ciphertext: %016lX\n", (unsigned long)ciphertext);
    printf("Expected:   %016lX\n", (unsigned long)expected);
    printf("Result:     %s\n\n", (ciphertext == expected) ? "✅ PASS" : "❌ FAIL");

    // ========== 测试 2：全零测试 ==========
    des_encrypt(0ULL, 0ULL, &ciphertext);
    printf("Zero Test:  %016lX (expect: 8CA64DE9C1B123A7)\n", (unsigned long)ciphertext);
    printf("Result:     %s\n", (ciphertext == 0x8CA64DE9C1B123A7ULL) ? "✅ PASS" : "❌ FAIL");
    
    // 返回测试结果：0 表示通过，1 表示失败
    return (ciphertext == 0x8CA64DE9C1B123A7ULL) ? 0 : 1;
}
#endif
