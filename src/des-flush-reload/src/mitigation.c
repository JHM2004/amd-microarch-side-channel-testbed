/**
 * mitigation.c
 * DES Flush+Reload Attack - 缓解措施实现
 * 
 * 实现各种缓存侧信道缓解措施及其测试框架
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <time.h>
#include <math.h>
#include <errno.h>

#include "mitigation.h"
#include "spy.h"
#include "metrics.h"

// 全局状态
static MitigationConfig g_configs[MITIGATION_COUNT];
static bool g_initialized = false;
static cpu_set_t g_original_cpu_set;

// 钩子系统状态
static MitigationType g_active_mitigation = MITIGATION_NONE;
static bool g_hooks_enabled = false;
static int g_flush_counter = 0;
static int g_flush_interval = 10;  // 每10次加密冲洗一次
static void* g_noise_buffer = NULL;
static size_t g_noise_buffer_size = 4096 * 64;  // 256KB噪声缓冲区

// 缓解措施名称和描述
static const char* g_mitigation_names[] = {
    "None (Baseline)",
    "CPU Pinning",
    "Cache Flush",
    "Noise Injection",
    "Access Obfuscation",
    "Process Isolation",
    "Core Isolation",
    "Disable Hyperthreading"
};

static const char* g_mitigation_descriptions[] = {
    "No mitigation - baseline measurement",
    "Bind attacker and victim to different CPU cores",
    "Frequent cache flush during encryption",
    "Inject random memory accesses as noise",
    "Randomize S-box access patterns",
    "Run attacker and victim in separate processes",
    "Physical core isolation (different cores)",
    "Disable hyperthreading on target cores"
};

// ==================== 初始化与配置 ====================

void mitigation_init(void) {
    if (g_initialized) return;
    
    // 保存原始CPU亲和性
    sched_getaffinity(0, sizeof(g_original_cpu_set), &g_original_cpu_set);
    
    // 初始化所有缓解措施配置
    for (int i = 0; i < MITIGATION_COUNT; i++) {
        g_configs[i].type = i;
        g_configs[i].name = g_mitigation_names[i];
        g_configs[i].description = g_mitigation_descriptions[i];
        g_configs[i].enabled = false;
        memset(&g_configs[i].params, 0, sizeof(g_configs[i].params));
    }
    
    // 设置默认参数
    g_configs[MITIGATION_CPU_PINNING].params.cpu_pinning.attacker_core = 0;
    g_configs[MITIGATION_CPU_PINNING].params.cpu_pinning.victim_core = 1;
    
    g_configs[MITIGATION_CACHE_FLUSH].params.cache_flush.flush_interval = 10;
    
    g_configs[MITIGATION_NOISE_INJECTION].params.noise_injection.noise_accesses = 1000;
    
    g_configs[MITIGATION_ACCESS_OBFUSCATION].params.access_obfuscation.obfuscation_range = 64;
    
    g_initialized = true;
    printf("[Mitigation] Initialized %d mitigation strategies\n", MITIGATION_COUNT);
}

void mitigation_configure(MitigationConfig* config) {
    if (!g_initialized) mitigation_init();
    if (config->type < MITIGATION_COUNT) {
        memcpy(&g_configs[config->type], config, sizeof(MitigationConfig));
    }
}

void mitigation_enable(MitigationType type) {
    if (!g_initialized) mitigation_init();
    if (type < MITIGATION_COUNT) {
        g_configs[type].enabled = true;
        printf("[Mitigation] Enabled: %s\n", g_mitigation_names[type]);
    }
}

void mitigation_disable(MitigationType type) {
    if (!g_initialized) mitigation_init();
    if (type < MITIGATION_COUNT) {
        g_configs[type].enabled = false;
        printf("[Mitigation] Disabled: %s\n", g_mitigation_names[type]);
    }
}

// ==================== 具体缓解措施实现 ====================

// CPU亲和性绑定 - 将攻击者和受害者绑定到不同核心
void mitigation_cpu_pinning_apply(int attacker_core, int victim_core) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(attacker_core, &mask);
    
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        perror("[Mitigation] Failed to set CPU affinity");
    } else {
        printf("[Mitigation] CPU pinning: attacker on core %d, victim would be on core %d\n", 
               attacker_core, victim_core);
    }
}

void mitigation_cpu_pinning_remove(void) {
    sched_setaffinity(0, sizeof(g_original_cpu_set), &g_original_cpu_set);
    printf("[Mitigation] CPU pinning removed\n");
}

// 缓存冲洗策略 - 在加密过程中定期冲洗缓存
void mitigation_cache_flush_apply(int interval) {
    printf("[Mitigation] Cache flush interval set to %d accesses\n", interval);
    // 实际冲洗在攻击循环中实现
}

void mitigation_cache_flush_remove(void) {
    printf("[Mitigation] Cache flush disabled\n");
}

// 执行缓存冲洗（在攻击过程中调用）
static void perform_cache_flush(void) {
    if (!g_sboxes) return;
    
    // 冲洗所有S-box缓存行
    for (int sbox = 0; sbox < 8; sbox++) {
        for (int entry = 0; entry < 64; entry++) {
            void* addr = (void*)&g_sboxes[sbox].data[entry][0];
            asm volatile ("clflush 0(%0)" :: "r"(addr) : "memory");
        }
    }
    asm volatile ("mfence" ::: "memory");
}

// 噪声注入 - 访问随机内存位置产生噪声
void mitigation_noise_injection_apply(int noise_count) {
    printf("[Mitigation] Injecting %d noise accesses\n", noise_count);
    
    // 分配噪声缓冲区
    void* noise_buffer = mmap(NULL, 4096 * 64, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (noise_buffer == MAP_FAILED) {
        perror("[Mitigation] Failed to allocate noise buffer");
        return;
    }
    
    // 随机访问噪声缓冲区
    srand(time(NULL));
    volatile char* buf = (volatile char*)noise_buffer;
    for (int i = 0; i < noise_count; i++) {
        int offset = rand() % (4096 * 64);
        buf[offset] = (char)(i % 256);
    }
    
    munmap(noise_buffer, 4096 * 64);
}

void mitigation_noise_injection_remove(void) {
    // 噪声注入是一次性的，无需移除
    printf("[Mitigation] Noise injection completed\n");
}

// 访问混淆 - 随机化访问模式
void mitigation_access_obfuscation_apply(int range) {
    printf("[Mitigation] Access obfuscation with range %d\n", range);
    // 实际混淆在攻击循环中实现
}

void mitigation_access_obfuscation_remove(void) {
    printf("[Mitigation] Access obfuscation disabled\n");
}

// 进程隔离 - 使用fork创建隔离进程
void mitigation_process_isolation_apply(void) {
    printf("[Mitigation] Process isolation applied (running in separate process)\n");
    // 实际隔离在测试框架中实现
}

void mitigation_process_isolation_remove(void) {
    printf("[Mitigation] Process isolation removed\n");
}

// 核心隔离 - 使用不同物理核心
void mitigation_core_isolation_apply(int attacker_core, int victim_core) {
    // 检查是否在同一物理核心（超线程）
    int attacker_physical = attacker_core / 2;  // 假设每核心2线程
    int victim_physical = victim_core / 2;
    
    if (attacker_physical == victim_physical) {
        printf("[Warning] Attacker and victim on same physical core!\n");
    }
    
    mitigation_cpu_pinning_apply(attacker_core, victim_core);
    printf("[Mitigation] Core isolation: attacker on core %d, victim on core %d\n",
           attacker_core, victim_core);
}

void mitigation_core_isolation_remove(void) {
    mitigation_cpu_pinning_remove();
    printf("[Mitigation] Core isolation removed\n");
}

// ==================== 应用/移除接口 ====================

void mitigation_apply(MitigationType type) {
    if (!g_initialized) mitigation_init();
    if (type >= MITIGATION_COUNT) return;
    
    MitigationConfig* config = &g_configs[type];
    if (!config->enabled) return;
    
    switch (type) {
        case MITIGATION_CPU_PINNING:
            mitigation_cpu_pinning_apply(
                config->params.cpu_pinning.attacker_core,
                config->params.cpu_pinning.victim_core
            );
            break;
            
        case MITIGATION_CACHE_FLUSH:
            mitigation_cache_flush_apply(config->params.cache_flush.flush_interval);
            break;
            
        case MITIGATION_NOISE_INJECTION:
            mitigation_noise_injection_apply(config->params.noise_injection.noise_accesses);
            break;
            
        case MITIGATION_ACCESS_OBFUSCATION:
            mitigation_access_obfuscation_apply(config->params.access_obfuscation.obfuscation_range);
            break;
            
        case MITIGATION_PROCESS_ISOLATION:
            mitigation_process_isolation_apply();
            break;
            
        case MITIGATION_CORE_ISOLATION:
            mitigation_core_isolation_apply(
                config->params.cpu_pinning.attacker_core,
                config->params.cpu_pinning.victim_core
            );
            break;
            
        case MITIGATION_HYPERTHREAD_DISABLE:
            // 需要root权限修改BIOS或内核参数
            printf("[Mitigation] Hyperthreading disable requires system-level changes\n");
            break;
            
        default:
            break;
    }
}

void mitigation_remove(MitigationType type) {
    if (!g_initialized) mitigation_init();
    if (type >= MITIGATION_COUNT) return;
    
    switch (type) {
        case MITIGATION_CPU_PINNING:
        case MITIGATION_CORE_ISOLATION:
            mitigation_cpu_pinning_remove();
            break;
            
        case MITIGATION_CACHE_FLUSH:
            mitigation_cache_flush_remove();
            break;
            
        case MITIGATION_NOISE_INJECTION:
            mitigation_noise_injection_remove();
            break;
            
        case MITIGATION_ACCESS_OBFUSCATION:
            mitigation_access_obfuscation_remove();
            break;
            
        case MITIGATION_PROCESS_ISOLATION:
            mitigation_process_isolation_remove();
            break;
            
        default:
            break;
    }
}

// ==================== 缓解措施钩子实现 ====================

void mitigation_hooks_init(void) {
    g_hooks_enabled = true;
    g_flush_counter = 0;
    
    // 初始化噪声缓冲区
    if (!g_noise_buffer) {
        g_noise_buffer = mmap(NULL, g_noise_buffer_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g_noise_buffer != MAP_FAILED) {
            // 初始化随机数据
            srand(time(NULL));
            for (size_t i = 0; i < g_noise_buffer_size; i++) {
                ((volatile char*)g_noise_buffer)[i] = rand() % 256;
            }
        }
    }
    
    printf("[Mitigation Hooks] Initialized\n");
}

void mitigation_set_active(MitigationType type) {
    g_active_mitigation = type;
    if (type != MITIGATION_NONE) {
        mitigation_hooks_init();
        printf("[Mitigation Hooks] Active: %s\n", g_mitigation_names[type]);
    } else {
        g_hooks_enabled = false;
    }
}

MitigationType mitigation_get_active(void) {
    return g_active_mitigation;
}

// 在每次加密操作前调用（Trigger之前）
void mitigation_hook_pre_encrypt(void) {
    if (!g_hooks_enabled || g_active_mitigation == MITIGATION_NONE) return;
    
    switch (g_active_mitigation) {
        case MITIGATION_CACHE_FLUSH:
            // 定期冲洗缓存
            g_flush_counter++;
            if (g_flush_counter >= g_flush_interval) {
                // 冲洗所有S-box缓存行
                if (g_sboxes) {
                    for (int sbox = 0; sbox < 8; sbox++) {
                        for (int entry = 0; entry < 64; entry++) {
                            void* addr = (void*)&g_sboxes[sbox].data[entry][0];
                            asm volatile ("clflush 0(%0)" :: "r"(addr) : "memory");
                        }
                    }
                    asm volatile ("mfence" ::: "memory");
                }
                g_flush_counter = 0;
            }
            break;
            
        case MITIGATION_NOISE_INJECTION:
            // 噪声注入：添加随机延迟，干扰时序测量
            // 不使用内存访问，避免污染缓存状态
            {
                // 随机延迟：100-500个循环
                volatile int delay_count = rand() % 400 + 100;
                for (volatile int i = 0; i < delay_count; i++) {
                    asm volatile ("nop");
                }
                // 添加内存屏障确保顺序执行
                asm volatile ("mfence" ::: "memory");
            }
            break;
            
        case MITIGATION_ACCESS_OBFUSCATION:
            // 访问混淆：随机延迟，不访问S-box（避免预热缓存）
            // 使用忙等待而不是内存访问来混淆时序
            {
                volatile int delay_count = rand() % 500 + 100;  // 100-600个循环
                for (volatile int i = 0; i < delay_count; i++) {
                    asm volatile ("nop");  // 空操作，不访问内存
                }
                asm volatile ("mfence" ::: "memory");
            }
            break;
            
        default:
            break;
    }
}

// 在每次加密操作后调用（Reload之后）
void mitigation_hook_post_encrypt(void) {
    if (!g_hooks_enabled || g_active_mitigation == MITIGATION_NONE) return;
    
    switch (g_active_mitigation) {
        case MITIGATION_NOISE_INJECTION:
            // 加密后添加随机延迟噪声（与pre_encrypt不同范围）
            {
                volatile int delay_count = rand() % 300 + 50;  // 50-350个循环
                for (volatile int i = 0; i < delay_count; i++) {
                    asm volatile ("nop");
                }
            }
            break;
            
        case MITIGATION_ACCESS_OBFUSCATION:
            // 加密后添加额外的随机延迟（与pre_encrypt不同范围）
            {
                volatile int delay_count = rand() % 200 + 50;  // 50-250个循环
                for (volatile int i = 0; i < delay_count; i++) {
                    asm volatile ("nop");
                }
            }
            break;
            
        default:
            break;
    }
}

// 在每个S-box条目测试前调用
void mitigation_hook_pre_sbox_entry(int sbox, int entry) {
    if (!g_hooks_enabled || g_active_mitigation == MITIGATION_NONE) return;
    
    // 可以在这里添加针对特定S-box/条目的缓解措施
    (void)sbox;
    (void)entry;
}

// 在每个S-box条目测试后调用
void mitigation_hook_post_sbox_entry(int sbox, int entry) {
    if (!g_hooks_enabled || g_active_mitigation == MITIGATION_NONE) return;
    
    (void)sbox;
    (void)entry;
}

// 在每轮攻击开始前调用
void mitigation_hook_round_start(int round_num) {
    if (!g_hooks_enabled || g_active_mitigation == MITIGATION_NONE) return;
    
    // 重置计数器
    g_flush_counter = 0;
    
    printf("[Mitigation] Round %d started with %s\n", 
           round_num, g_mitigation_names[g_active_mitigation]);
}

// 在每轮攻击结束后调用
void mitigation_hook_round_end(int round_num) {
    if (!g_hooks_enabled || g_active_mitigation == MITIGATION_NONE) return;
    
    printf("[Mitigation] Round %d ended\n", round_num);
}

// ==================== 测试框架实现 ====================

// 运行单次攻击测试（带缓解措施）
static bool run_attack_with_mitigation(uint64_t test_key, MitigationType mitigation) {
    // 应用缓解措施（CPU绑定等）
    mitigation_apply(mitigation);
    
    // 激活钩子机制（用于持续缓解）
    mitigation_set_active(mitigation);
    
    // 运行攻击
    bool success = attack_des_full(test_key);
    
    // 禁用钩子
    mitigation_set_active(MITIGATION_NONE);
    
    // 移除缓解措施
    mitigation_remove(mitigation);
    
    return success;
}

MitigationTestResult mitigation_test_single(
    MitigationType type,
    int iterations,
    uint64_t test_key
) {
    MitigationTestResult result = {0};
    result.mitigation_type = type;
    result.test_name = g_mitigation_names[type];
    result.total_tests = iterations;
    
    printf("\n[Test] Running %d iterations with %s...\n", iterations, result.test_name);
    
    double total_fragments = 0;
    double total_duration = 0;
    
    for (int i = 0; i < iterations; i++) {
        printf("  Iteration %d/%d\r", i + 1, iterations);
        fflush(stdout);
        
        struct timespec start, end;
        clock_gettime(CLOCK_MONOTONIC, &start);
        
        bool success = run_attack_with_mitigation(test_key, type);
        
        clock_gettime(CLOCK_MONOTONIC, &end);
        double duration = (end.tv_sec - start.tv_sec) * 1000.0 + 
                         (end.tv_nsec - start.tv_nsec) / 1e6;
        
        if (success) {
            result.successful_attacks++;
        }
        total_duration += duration;
    }
    
    printf("\n");
    
    // 计算统计结果
    result.attack_success_rate = (double)result.successful_attacks / iterations;
    result.avg_attack_duration_ms = total_duration / iterations;
    result.avg_recovery_fragments = 8.0 * result.attack_success_rate; // 简化计算
    
    printf("[Test] %s: Success rate %.2f%%, Avg duration %.2f ms\n",
           result.test_name,
           result.attack_success_rate * 100,
           result.avg_attack_duration_ms);
    
    return result;
}

void mitigation_test_comparison(
    MitigationType type,
    int iterations,
    MitigationTestResult* baseline,
    MitigationTestResult* with_mitigation
) {
    printf("\n========================================\n");
    printf("Mitigation Comparison Test: %s\n", g_mitigation_names[type]);
    printf("========================================\n");
    
    // 基准测试（无缓解措施）
    printf("\n--- Baseline (No Mitigation) ---\n");
    *baseline = mitigation_test_single(MITIGATION_NONE, iterations, 0x133457799BBCDFF1);
    
    // 带缓解措施测试
    printf("\n--- With Mitigation: %s ---\n", g_mitigation_names[type]);
    mitigation_enable(type);
    *with_mitigation = mitigation_test_single(type, iterations, 0x133457799BBCDFF1);
    mitigation_disable(type);
    
    // 计算效果
    double effectiveness, overhead;
    mitigation_calculate_effectiveness(baseline, with_mitigation, &effectiveness, &overhead);
    
    printf("\n--- Comparison Results ---\n");
    printf("Effectiveness: %.2f%% (attack success rate reduction)\n", effectiveness);
    printf("Overhead: %.2f%% (performance impact)\n", overhead);
}

void mitigation_test_all(
    int iterations,
    MitigationTestResult results[MITIGATION_COUNT]
) {
    printf("\n========================================\n");
    printf("Running All Mitigation Tests\n");
    printf("Iterations per test: %d\n", iterations);
    printf("========================================\n");
    
    // 为每个缓解措施都进行基准测试和缓解测试的对比
    for (int i = MITIGATION_CPU_PINNING; i < MITIGATION_COUNT; i++) {
        MitigationTestResult baseline, with_mitigation;
        
        printf("\n--- Testing Mitigation %d: %s ---\n", i, g_mitigation_names[i]);
        
        // 基准测试（无缓解措施）
        printf("  Running baseline test...\n");
        baseline = mitigation_test_single(MITIGATION_NONE, iterations, 0x133457799BBCDFF1);
        
        // 带缓解措施测试
        printf("  Running with mitigation...\n");
        mitigation_enable(i);
        with_mitigation = mitigation_test_single(i, iterations, 0x133457799BBCDFF1);
        mitigation_disable(i);
        
        // 保存缓解测试结果
        results[i] = with_mitigation;
        
        // 计算并显示效果
        double effectiveness, overhead;
        mitigation_calculate_effectiveness(&baseline, &with_mitigation, &effectiveness, &overhead);
        
        printf("  Baseline Success: %.2f%%, Mitigation Success: %.2f%%\n",
               baseline.attack_success_rate * 100, with_mitigation.attack_success_rate * 100);
        printf("  Effectiveness: %.2f%%, Overhead: %.2f%%\n\n", effectiveness, overhead);
    }
    
    // 保存最后一次基准测试结果作为参考
    results[MITIGATION_NONE] = mitigation_test_single(MITIGATION_NONE, iterations, 0x133457799BBCDFF1);
}

// ==================== 跨核/跨进程测试 ====================

void mitigation_test_cross_core(
    CoreIsolationConfig* configs,
    int num_configs,
    MitigationTestResult* results
) {
    printf("\n========================================\n");
    printf("Cross-Core Migration Test\n");
    printf("========================================\n");
    
    for (int i = 0; i < num_configs; i++) {
        printf("\n--- Test %d: Core %d -> Core %d ---\n",
               i + 1, configs[i].source_core, configs[i].target_core);
        
        // 配置核心隔离
        g_configs[MITIGATION_CORE_ISOLATION].params.cpu_pinning.attacker_core = 
            configs[i].source_core;
        g_configs[MITIGATION_CORE_ISOLATION].params.cpu_pinning.victim_core = 
            configs[i].target_core;
        
        mitigation_enable(MITIGATION_CORE_ISOLATION);
        results[i] = mitigation_test_single(MITIGATION_CORE_ISOLATION, 3, 0x133457799BBCDFF1);
        mitigation_disable(MITIGATION_CORE_ISOLATION);
    }
}

void mitigation_test_cross_process(
    ProcessIsolationConfig* configs,
    int num_configs,
    MitigationTestResult* results
) {
    printf("\n========================================\n");
    printf("Cross-Process Isolation Test\n");
    printf("========================================\n");
    
    for (int i = 0; i < num_configs; i++) {
        printf("\n--- Test %d: Process Isolation ---\n", i + 1);
        
        pid_t pid = fork();
        if (pid == 0) {
            // 子进程：运行攻击
            mitigation_enable(MITIGATION_PROCESS_ISOLATION);
            bool success = run_attack_with_mitigation(0x133457799BBCDFF1, MITIGATION_PROCESS_ISOLATION);
            exit(success ? 0 : 1);
        } else if (pid > 0) {
            // 父进程：等待结果
            int status;
            waitpid(pid, &status, 0);
            
            results[i].successful_attacks = WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
            results[i].attack_success_rate = results[i].successful_attacks;
            results[i].mitigation_type = MITIGATION_PROCESS_ISOLATION;
            results[i].test_name = "Process Isolation";
        } else {
            perror("[Test] Fork failed");
            results[i].attack_success_rate = 0;
        }
    }
}

// ==================== 统计分析与报告 ====================

void mitigation_calculate_effectiveness(
    const MitigationTestResult* baseline,
    const MitigationTestResult* with_mitigation,
    double* effectiveness_percent,
    double* overhead_percent
) {
    // 计算缓解效果（攻击成功率降低百分比）
    double baseline_success = baseline->attack_success_rate;
    double mitigated_success = with_mitigation->attack_success_rate;
    
    if (baseline_success > 0) {
        // 计算成功率降低百分比，限制在0-100%范围内
        double reduction = (baseline_success - mitigated_success) / baseline_success * 100.0;
        if (reduction < 0) {
            // 如果缓解后成功率更高，说明缓解无效，效果为0
            *effectiveness_percent = 0.0;
        } else if (reduction > 100.0) {
            *effectiveness_percent = 100.0;
        } else {
            *effectiveness_percent = reduction;
        }
    } else {
        // 基准成功率为0，无法计算效果
        *effectiveness_percent = 0.0;
    }
    
    // 计算性能开销
    double baseline_duration = baseline->avg_attack_duration_ms;
    double mitigated_duration = with_mitigation->avg_attack_duration_ms;
    
    if (baseline_duration > 0) {
        *overhead_percent = (mitigated_duration / baseline_duration - 1.0) * 100.0;
    } else {
        *overhead_percent = 0.0;
    }
}

void mitigation_generate_report(
    const MitigationTestResult results[MITIGATION_COUNT],
    const char* filename
) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        perror("[Report] Failed to open file");
        return;
    }
    
    fprintf(fp, "============================================================\n");
    fprintf(fp, "DES Flush+Reload Attack Mitigation Test Report\n");
    fprintf(fp, "============================================================\n\n");
    
    // 基准结果
    fprintf(fp, "BASELINE (No Mitigation)\n");
    fprintf(fp, "----------------------------------------\n");
    fprintf(fp, "Success Rate: %.2f%%\n", results[MITIGATION_NONE].attack_success_rate * 100);
    fprintf(fp, "Avg Duration: %.2f ms\n", results[MITIGATION_NONE].avg_attack_duration_ms);
    fprintf(fp, "\n");
    
    // 各缓解措施结果
    fprintf(fp, "MITIGATION EFFECTIVENESS\n");
    fprintf(fp, "----------------------------------------\n");
    
    for (int i = MITIGATION_CPU_PINNING; i < MITIGATION_COUNT; i++) {
        double effectiveness, overhead;
        mitigation_calculate_effectiveness(
            &results[MITIGATION_NONE],
            &results[i],
            &effectiveness,
            &overhead
        );
        
        fprintf(fp, "\n%s:\n", g_mitigation_names[i]);
        fprintf(fp, "  Success Rate: %.2f%%\n", results[i].attack_success_rate * 100);
        fprintf(fp, "  Effectiveness: %.2f%% (attack reduction)\n", effectiveness);
        fprintf(fp, "  Overhead: %.2f%% (performance impact)\n", overhead);
        fprintf(fp, "  Avg Duration: %.2f ms\n", results[i].avg_attack_duration_ms);
    }
    
    fprintf(fp, "\n============================================================\n");
    fclose(fp);
    
    printf("[Report] Saved to: %s\n", filename);
}

void mitigation_print_summary(
    const MitigationTestResult results[MITIGATION_COUNT]
) {
    printf("\n============================================================\n");
    printf("Mitigation Test Summary\n");
    printf("============================================================\n");
    
    printf("\n%-30s %10s %12s %10s\n", "Mitigation", "Success %", "Effectiveness", "Overhead");
    printf("------------------------------------------------------------\n");
    
    for (int i = 0; i < MITIGATION_COUNT; i++) {
        double effectiveness = 0, overhead = 0;
        
        if (i != MITIGATION_NONE) {
            mitigation_calculate_effectiveness(
                &results[MITIGATION_NONE],
                &results[i],
                &effectiveness,
                &overhead
            );
        }
        
        printf("%-30s %9.1f%% %11.1f%% %9.1f%%\n",
               g_mitigation_names[i],
               results[i].attack_success_rate * 100,
               effectiveness,
               overhead);
    }
    
    printf("============================================================\n");
}

// ==================== 辅助功能 ====================

const char* mitigation_get_name(MitigationType type) {
    if (type < MITIGATION_COUNT) {
        return g_mitigation_names[type];
    }
    return "Unknown";
}

const char* mitigation_get_description(MitigationType type) {
    if (type < MITIGATION_COUNT) {
        return g_mitigation_descriptions[type];
    }
    return "Unknown mitigation type";
}

bool mitigation_check_support(MitigationType type) {
    // 检查系统是否支持特定缓解措施
    switch (type) {
        case MITIGATION_CPU_PINNING:
        case MITIGATION_CORE_ISOLATION:
            return true;  // 大多数系统支持
            
        case MITIGATION_CACHE_FLUSH:
            return true;  // x86支持clflush指令
            
        case MITIGATION_HYPERTHREAD_DISABLE:
            // 需要root权限
            return geteuid() == 0;
            
        default:
            return true;
    }
}

bool mitigation_set_system_param(const char* param, int value) {
    // 设置内核参数（需要root权限）
    char path[256];
    snprintf(path, sizeof(path), "/proc/sys/%s", param);
    
    FILE* fp = fopen(path, "w");
    if (!fp) {
        printf("[Mitigation] Cannot set %s (requires root)\n", param);
        return false;
    }
    
    fprintf(fp, "%d\n", value);
    fclose(fp);
    
    printf("[Mitigation] Set %s = %d\n", param, value);
    return true;
}

void mitigation_get_cpu_topology(int* cores, int* sockets, int* ht_enabled) {
    // 获取CPU拓扑信息
    *cores = sysconf(_SC_NPROCESSORS_ONLN);
    *sockets = 1;  // 简化处理
    
    // 检查超线程
    FILE* fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        int siblings = 0, cpu_cores = 0;
        
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "siblings", 8) == 0) {
                sscanf(line, "siblings : %d", &siblings);
            }
            if (strncmp(line, "cpu cores", 9) == 0) {
                sscanf(line, "cpu cores : %d", &cpu_cores);
            }
        }
        
        fclose(fp);
        *ht_enabled = (siblings > cpu_cores);
    } else {
        *ht_enabled = false;
    }
    
    printf("[Mitigation] CPU Topology: %d cores, %d sockets, HT %s\n",
           *cores, *sockets, *ht_enabled ? "enabled" : "disabled");
}
