/**
 * des_loader.c
 * DES库加载工具模块实现
 * 
 * 实现了动态加载DES共享库的功能
 */

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>

#include "des.h"
#include "utils/des_loader.h"

/* 全局变量定义 */
void *lib_handle = NULL;
des_encrypt_first_round_t des_encrypt_first_round_func = NULL;
des_encrypt_full_t des_encrypt_full_func = NULL;
get_sboxes_t get_sboxes_func = NULL;

/**
 * 加载DES共享库
 * @param lib_path: 共享库文件路径
 * @return: 成功返回0，失败返回-1
 * 功能：
 *   1. 使用dlopen加载共享库
 *   2. 使用dlsym解析des_encrypt_first_round符号
 *   3. 使用dlsym解析des_encrypt_full符号
 *   4. 使用dlsym解析get_sboxes符号
 *   5. 获取S-boxes指针
 *   6. 预加载S-box数据到缓存
 */
int load_des_library(const char *lib_path) {
    // 使用RTLD_LAZY延迟绑定，RTLD_GLOBAL使符号全局可见
    lib_handle = dlopen(lib_path, RTLD_LAZY | RTLD_GLOBAL);
    if (!lib_handle) {
        fprintf(stderr, "Error loading library: %s\n", dlerror());
        return -1;
    }
    
    // 解析des_encrypt_first_round符号（第一轮加密函数）
    des_encrypt_first_round_func = (des_encrypt_first_round_t)dlsym(lib_handle, "des_encrypt_first_round");
    // 解析des_encrypt_full符号（完整加密函数）
    des_encrypt_full_func = (des_encrypt_full_t)dlsym(lib_handle, "des_encrypt_full");
    // 解析get_sboxes符号（获取S-boxes指针）
    get_sboxes_func = (get_sboxes_t)dlsym(lib_handle, "get_sboxes");
    
    // 检查所有符号是否成功解析
    if (!des_encrypt_first_round_func || !des_encrypt_full_func || !get_sboxes_func) {
        fprintf(stderr, "Error resolving symbols: %s\n", dlerror());
        dlclose(lib_handle);
        return -1;
    }
    
    // 获取S-boxes指针
    SBox *sboxes = get_sboxes_func();
    if (!sboxes) {
        fprintf(stderr, "Error getting S-boxes\n");
        dlclose(lib_handle);
        return -1;
    }
    
    printf("Successfully loaded DES library, S-boxes at %p\n", (void*)sboxes);
    
    // 预加载S-box数据到缓存，确保后续访问更快
    // 访问每个S-box的第一个元素，触发页面加载
    for (int i = 0; i < 8; i++) {  // 假设有8个S-box
        volatile uint32_t tmp = sboxes[i].data[0][0];
        (void)tmp;  // 抑制未使用变量警告
    }
    
    return 0;
}

/**
 * 卸载DES共享库
 * 功能：
 *   1. 关闭共享库句柄
 *   2. 重置全局指针为NULL
 */
void unload_des_library() {
    if (lib_handle) {
        dlclose(lib_handle);
        lib_handle = NULL;
        des_encrypt_first_round_func = NULL;
        des_encrypt_full_func = NULL;
        get_sboxes_func = NULL;
    }
}
