// 包含标准输入输出头文件
#include <stdio.h>
// 包含非局部跳转头文件，提供sigsetjmp和siglongjmp函数
#include <setjmp.h>
// 包含信号处理头文件，提供信号相关函数和宏
#include <signal.h>

// 定义非局部跳转缓冲区，用于保存程序执行环境
static sigjmp_buf jbuf;

// SIGSEGV信号处理函数
static void catch_segv()
{
  // 使用siglongjmp跳转回sigsetjmp设置的位置
  // 第二个参数1是返回值，会传递给sigsetjmp
  siglongjmp(jbuf, 1);                         
}

// 主函数
int main()
{ 
  // 定义内核数据地址（示例地址，实际需要从dmesg获取）
  unsigned long kernel_data_addr = 0xf93ed000;

  // 注册SIGSEGV（段错误）信号处理函数
  // 当程序访问非法内存时，会触发此信号并执行catch_segv
  signal(SIGSEGV, catch_segv);                     

  // 设置跳转点，第一次调用返回0，后续通过siglongjmp返回1
  if (sigsetjmp(jbuf, 1) == 0) {                
     // 尝试访问内核地址空间的数据
     // 这会触发SIGSEGV信号，因为用户程序无权访问内核内存
     char kernel_data = *(char*)kernel_data_addr; 

     // 如果上面的访问成功（实际不会成功），则执行这里
     // 打印获取到的内核数据
     printf("Kernel data at address %lu is: %c\n", 
                    kernel_data_addr, kernel_data);
  }
  else {
     // 如果通过siglongjmp跳转回来，sigsetjmp返回1，执行这里
     printf("Memory access violation!\n");
  }

  // 程序继续执行，不会因为段错误而崩溃
  printf("Program continues to execute.\n");
  return 0;
}