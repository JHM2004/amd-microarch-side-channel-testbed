// 包含Linux内核模块开发所需的头文件
#include <linux/module.h>    // 模块编程基础头文件
#include <linux/kernel.h>    // 内核函数和宏定义
#include <linux/init.h>      // 模块初始化和清理宏
#include <linux/vmalloc.h>   // 虚拟内存分配函数
#include <linux/version.h>   // 内核版本信息
#include <linux/proc_fs.h>   // proc文件系统支持
#include <linux/seq_file.h>  // 序列文件操作
#include <linux/uaccess.h>   // 用户空间和内核空间数据拷贝

// 定义秘密数据数组，包含8个字符
static char secret[8] = {'P','A','S','S','W','O','R','D'};
// 指向/proc文件系统条目的指针
static struct proc_dir_entry *secret_entry;
// 内核缓冲区指针，用于临时存储秘密数据
static char* secret_buffer;

// /proc文件打开操作的回调函数
static int test_proc_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,0,0)
   // Linux 4.0及更早版本：使用PDE(inode)->data获取私有数据
   return single_open(file, NULL, PDE(inode)->data);
#else
   // Linux 4.0以后版本：使用PDE_DATA(inode)获取私有数据
   return single_open(file, NULL, PDE_DATA(inode));
#endif
}

// /proc文件读取操作的回调函数
static ssize_t read_proc(struct file *filp, char *buffer, 
                         size_t length, loff_t *offset)
{
   // 将秘密数据复制到内核缓冲区（但不会返回给用户空间）
   // 这个操作会导致secret数据被加载到CPU缓存中
   memcpy(secret_buffer, &secret, 8);              
   // 返回读取的字节数
   return 8;
}

// 定义/proc文件的文件操作结构体
static const struct file_operations test_proc_fops =
{
   .owner = THIS_MODULE,     // 拥有该结构的模块
   .open = test_proc_open,   // 文件打开时的回调函数
   .read = read_proc,        // 文件读取时的回调函数
   .llseek = seq_lseek,      // 文件定位操作
   .release = single_release, // 文件释放时的回调函数
};

// 内核模块初始化函数
static __init int test_proc_init(void)
{
   // 在内核日志中打印秘密数据的地址（满足Meltdown攻击第一个条件）
   printk("secret data address:%p\n", &secret);      

   // 分配8字节的内核虚拟内存空间
   secret_buffer = (char*)vmalloc(8);

   // 在/proc文件系统中创建名为"secret_data"的只读条目
   // 0444表示只读权限，NULL表示在/proc根目录下
   // test_proc_fops定义了对该条目的操作，最后一个NULL是私有数据
   secret_entry = proc_create_data("secret_data", 
                  0444, NULL, &test_proc_fops, NULL);
   
   // 如果成功创建，返回0表示成功
   if (secret_entry) return 0;

   // 创建失败，返回内存不足错误码
   return -ENOMEM;
}

// 内核模块清理函数
static __exit void test_proc_cleanup(void)
{
   // 移除/proc文件系统中的"secret_data"条目
   remove_proc_entry("secret_data", NULL);
}

// 指定模块的初始化函数
module_init(test_proc_init);
// 指定模块的清理函数
module_exit(test_proc_cleanup);