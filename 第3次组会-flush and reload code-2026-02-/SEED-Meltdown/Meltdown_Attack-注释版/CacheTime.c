// 包含标准输入输出头文件
#include <stdio.h>
// 包含标准库头文件，提供内存分配等函数
#include <stdlib.h>
// 包含标准整数类型头文件，提供uint8_t、uint64_t等类型
#include <stdint.h>
// 包含SSE2指令集头文件，提供_mm_clflush函数
#include <emmintrin.h>
// 包含x86平台特定的内联函数头文件，提供__rdtscp函数
#include <x86intrin.h>

// 定义一个10行×4096字节的数组，每个元素1字节
// 每行4096字节是为了确保它们位于不同的内存页和缓存行
uint8_t array[10*4096];

// 主函数，argc是参数个数，argv是参数字符串数组
int main(int argc, const char **argv) {
  // 定义一个整型变量junk，用于rdtscp函数的参数
  int junk=0;
  // 声明两个64位无符号整数，用于存储时间戳（寄存器建议，优化器可能忽略）
  register uint64_t time1, time2;
  // 声明一个易失性指针，指向uint8_t类型，防止编译器优化
  volatile uint8_t *addr;
  // 循环变量
  int i;
  
  // 初始化数组：将每行（间隔4096字节）的第一个字节设置为1
  for(i=0; i<10; i++) array[i*4096]=1;

  // 从CPU缓存中刷新数组：强制将每行数据从缓存清除到内存
  for(i=0; i<10; i++) _mm_clflush(&array[i*4096]);

  // 访问数组中的两个特定位置：这将把这两行数据加载回缓存
  array[3*4096] = 100;  // 设置第3行的值为100，会将其加载到缓存
  array[7*4096] = 200;  // 设置第7行的值为200，会将其加载到缓存

  // 循环测量访问每行数据所需的时间
  for(i=0; i<10; i++) {
    // 获取当前行的地址
    addr = &array[i*4096];
    // 读取时间戳计数器（序列化版本），返回CPU周期计数
    time1 = __rdtscp(&junk);                
    // 访问内存地址，触发实际的内存读取操作
    // 由于addr是volatile，编译器不会优化掉这个读取
    junk = *addr;
    // 再次读取时间戳并计算差值，得到访问该内存位置所需的CPU周期数
    time2 = __rdtscp(&junk) - time1;       
    // 打印访问时间：如果数据在缓存中，时间较短；如果不在，需要从内存加载，时间较长
    printf("Access time for array[%d*4096]: %d CPU cycles\n",i, (int)time2);
  }
  // 程序正常结束
  return 0;
}