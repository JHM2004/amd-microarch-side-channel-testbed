/**
 * main.c
 * DES Flush+Reload Attack - 程序入口
 * 
 * 功能：
 * 1. 加载DES库
 * 2. 执行密钥重建测试
 * 3. 执行侧信道攻击
 * 4. 清理资源
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// 包含模块头文件
#include "config.h"
#include "spy.h"
#include "utils/des_loader.h"

int main(int argc, char *argv[]) {
    // 检查命令行参数
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_libdes.so>\n", argv[0]);
        fprintf(stderr, "Example: %s ./build/libdes.so\n", argv[0]);
        return 1;
    }
    
    const char *lib_path = argv[1];
    
    // ========== 步骤1: 加载DES库 ==========
    printf("Loading DES library from: %s\n", lib_path);
    if (load_des_library(lib_path) != 0) {
        fprintf(stderr, "Error: Failed to load DES library from %s\n", lib_path);
        return 1;
    }
    
    // 获取S-boxes地址（用于攻击）
    g_sboxes = get_sboxes_func();
    if (!g_sboxes) {
        fprintf(stderr, "Error: Failed to get S-boxes from library\n");
        unload_des_library();
        return 1;
    }
    printf("Successfully loaded DES library\n");
    printf("S-boxes located at: %p\n\n", (void*)g_sboxes);
    
    // ========== 步骤2: 密钥重建测试 ==========
    // printf("========================================\n");
    // printf("Running key reconstruction test...\n");
    // printf("========================================\n");
    
    // if (!test_key_reconstruction()) {
    //     fprintf(stderr, "Error: Key reconstruction test failed\n");
    //     unload_des_library();
    //     return 1;
    // }
    // printf("\nKey reconstruction test passed!\n");
    
    // ========== 步骤3: 执行侧信道攻击 ==========
    printf("\n========================================\n");
    printf("Starting DES Flush+Reload Attack\n");
    printf("========================================\n");
    
    #define MAX_RETRY_ATTEMPTS 10
    bool attack_success = false;
    int attempt = 0;
    
    while (!attack_success && attempt < MAX_RETRY_ATTEMPTS) {
        attempt++;
        printf("\n>>> Attack attempt %d/%d <<<\n", attempt, MAX_RETRY_ATTEMPTS);
        
        attack_success = attack_des_full(KEY_TEST_1);
        
        if (!attack_success && attempt < MAX_RETRY_ATTEMPTS) {
            printf("\nAttack failed, retrying...\n");
        }
    }
    
    // ========== 步骤4: 输出最终结果 ==========
    printf("\n========================================\n");
    if (attack_success) {
        printf("✅ Attack succeeded after %d attempt(s)\n", attempt);
    } else {
        printf("❌ Attack failed after %d attempts\n", MAX_RETRY_ATTEMPTS);
    }
    printf("========================================\n");
    
    // ========== 步骤5: 清理资源 ==========
    unload_des_library();
    
    printf("\n=== Results saved to results/ directory ===\n");
    return attack_success ? 0 : 1;
}
