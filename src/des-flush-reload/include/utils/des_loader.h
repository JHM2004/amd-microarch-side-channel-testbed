#ifndef DES_LOADER_H
#define DES_LOADER_H

/**
 * des_loader.h
 * DES库加载工具模块
 * 
 * 功能：动态加载DES共享库，解析符号
 * 
 * 注意：使用此头文件的源文件需要先包含 des.h
 */

#include <stdint.h>

/* 函数指针类型定义（用于动态加载） */
typedef void (*des_encrypt_first_round_t)(const uint64_t, const uint64_t, uint64_t*);
typedef void (*des_encrypt_full_t)(const uint64_t, const uint64_t, uint64_t*);
typedef struct SBox* (*get_sboxes_t)();

/* 全局变量声明（在des_loader.c中定义） */
extern void *lib_handle;
extern des_encrypt_first_round_t des_encrypt_first_round_func;
extern des_encrypt_full_t des_encrypt_full_func;
extern get_sboxes_t get_sboxes_func;

/**
 * 加载DES共享库
 * @param lib_path: 共享库文件路径
 * @return: 成功返回0，失败返回-1
 * 功能：加载libdes.so，解析des_encrypt_first_round、des_encrypt_full、get_sboxes符号
 */
int load_des_library(const char *lib_path);

/**
 * 卸载DES共享库
 * 功能：关闭共享库句柄，清理资源
 */
void unload_des_library();

#endif /* DES_LOADER_H */
