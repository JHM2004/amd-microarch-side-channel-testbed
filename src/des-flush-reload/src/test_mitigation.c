/**
 * test_mitigation.c
 * DES Flush+Reload Attack - 缓解措施验证测试主程序
 * 
 * 功能：
 * - 测试各种缓解措施的效果
 * - 对比开启/关闭缓解措施的攻击成功率
 * - 验证跨核/跨进程可迁移性
 * - 生成详细的测试报告
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "mitigation.h"
#include "utils/des_loader.h"
#include "spy.h"

// 外部声明
extern SBox *g_sboxes;
extern get_sboxes_t get_sboxes_func;

// 测试配置
#define DEFAULT_ITERATIONS 25  // 设置为25轮以获得统计显著结果
#define TEST_KEY 0x133457799BBCDFF1

// 打印使用说明
static void print_usage(const char* program) {
    printf("Usage: %s [options]\n", program);
    printf("\nOptions:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -a, --all               Test all mitigation strategies\n");
    printf("  -c, --compare TYPE      Compare specific mitigation (1-7)\n");
    printf("  -i, --iterations N      Number of iterations (default: %d)\n", DEFAULT_ITERATIONS);
    printf("  -x, --cross-core        Test cross-core migration\n");
    printf("  -p, --cross-process     Test cross-process isolation\n");
    printf("  -r, --report FILE       Save report to file\n");
    printf("\nMitigation Types:\n");
    printf("  1 - CPU Pinning\n");
    printf("  2 - Cache Flush\n");
    printf("  3 - Noise Injection\n");
    printf("  4 - Access Obfuscation\n");
    printf("  5 - Process Isolation\n");
    printf("  6 - Core Isolation\n");
    printf("  7 - Disable Hyperthreading\n");
}

// 测试所有缓解措施
static void test_all_mitigations(int iterations) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║       DES Flush+Reload Attack Mitigation Test Suite       ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    // 获取CPU拓扑
    int cores, sockets, ht_enabled;
    mitigation_get_cpu_topology(&cores, &sockets, &ht_enabled);
    printf("\nSystem Info: %d cores, HT %s\n", cores, ht_enabled ? "enabled" : "disabled");
    
    // 初始化缓解措施系统
    mitigation_init();
    
    // 分配结果数组
    MitigationTestResult results[MITIGATION_COUNT];
    memset(results, 0, sizeof(results));
    
    // 运行所有测试
    mitigation_test_all(iterations, results);
    
    // 打印摘要
    mitigation_print_summary(results);
    
    // 生成报告
    mitigation_generate_report(results, "results/mitigation_report.txt");
    
    printf("\n✅ All tests completed. Report saved to results/mitigation_report.txt\n");
}

// 对比测试特定缓解措施
static void test_comparison(int mitigation_type, int iterations) {
    if (mitigation_type < 1 || mitigation_type >= MITIGATION_COUNT) {
        printf("Error: Invalid mitigation type %d\n", mitigation_type);
        return;
    }
    
    MitigationTestResult baseline, with_mitigation;
    
    mitigation_init();
    mitigation_test_comparison(mitigation_type, iterations, &baseline, &with_mitigation);
    
    // 打印详细对比
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║              Detailed Comparison Results                  ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\nBaseline (No Mitigation):\n");
    printf("  Success Rate: %.2f%%\n", baseline.attack_success_rate * 100);
    printf("  Avg Duration: %.2f ms\n", baseline.avg_attack_duration_ms);
    
    printf("\nWith %s:\n", mitigation_get_name(mitigation_type));
    printf("  Success Rate: %.2f%%\n", with_mitigation.attack_success_rate * 100);
    printf("  Avg Duration: %.2f ms\n", with_mitigation.avg_attack_duration_ms);
    
    double effectiveness, overhead;
    mitigation_calculate_effectiveness(&baseline, &with_mitigation, &effectiveness, &overhead);
    
    printf("\nMitigation Effectiveness:\n");
    printf("  Attack Reduction: %.2f%%\n", effectiveness);
    printf("  Performance Overhead: %.2f%%\n", overhead);
    
    if (effectiveness > 50.0) {
        printf("  ✅ Effective mitigation\n");
    } else if (effectiveness > 20.0) {
        printf("  ⚠️  Partial mitigation\n");
    } else {
        printf("  ❌ Ineffective mitigation\n");
    }
}

// 跨核可迁移性测试
static void test_cross_core_migration(void) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║           Cross-Core Migration Test                       ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    int cores, sockets, ht_enabled;
    mitigation_get_cpu_topology(&cores, &sockets, &ht_enabled);
    
    // 定义测试配置
    CoreIsolationConfig configs[] = {
        {0, 0, true, true},    // 同核心（超线程）
        {0, 1, true, true},    // 相邻核心
        {0, cores/2, true, false}, // 跨CCX（如果有多核）
    };
    int num_configs = (cores >= 2) ? 3 : 1;
    
    MitigationTestResult results[3];
    mitigation_init();
    mitigation_test_cross_core(configs, num_configs, results);
    
    printf("\n");
    printf("Cross-Core Migration Results:\n");
    printf("------------------------------\n");
    for (int i = 0; i < num_configs; i++) {
        printf("Core %d -> Core %d: Success Rate %.2f%%\n",
               configs[i].source_core, configs[i].target_core,
               results[i].attack_success_rate * 100);
    }
    
    // 分析可迁移性
    printf("\nMigration Analysis:\n");
    if (results[0].attack_success_rate > 0.8) {
        printf("  ⚠️  Attack works within same core (HT vulnerability)\n");
    }
    if (num_configs > 1 && results[1].attack_success_rate > 0.5) {
        printf("  ⚠️  Attack works across adjacent cores\n");
    }
    if (num_configs > 2 && results[2].attack_success_rate > 0.3) {
        printf("  ⚠️  Attack works across CCX boundaries\n");
    }
}

// 跨进程隔离测试
static void test_cross_process_isolation(void) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║          Cross-Process Isolation Test                     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    ProcessIsolationConfig configs[] = {
        {true, true, 0},   // 同用户，同命名空间
        {true, false, 0},  // 同用户，不同命名空间
        {false, false, 0}, // 不同用户
    };
    
    MitigationTestResult results[3];
    mitigation_init();
    mitigation_test_cross_process(configs, 3, results);
    
    printf("\n");
    printf("Cross-Process Isolation Results:\n");
    printf("---------------------------------\n");
    printf("Same user, same namespace:   %.2f%% success\n", results[0].attack_success_rate * 100);
    printf("Same user, diff namespace:   %.2f%% success\n", results[1].attack_success_rate * 100);
    printf("Different user:              %.2f%% success\n", results[2].attack_success_rate * 100);
    
    printf("\nIsolation Analysis:\n");
    if (results[0].attack_success_rate > 0.5) {
        printf("  ⚠️  Attack works within same process context\n");
    }
    if (results[2].attack_success_rate < 0.3) {
        printf("  ✅ Different users provide some isolation\n");
    }
}

int main(int argc, char* argv[]) {
    int iterations = DEFAULT_ITERATIONS;
    int compare_type = -1;
    int mode = 0;  // 0=all, 1=compare, 2=cross-core, 3=cross-process
    
    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--all") == 0) {
            mode = 0;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--compare") == 0) {
            mode = 1;
            if (i + 1 < argc) {
                compare_type = atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--iterations") == 0) {
            if (i + 1 < argc) {
                iterations = atoi(argv[++i]);
                if (iterations < 1) iterations = 1;
                if (iterations > 10) iterations = 10;  // 限制最大迭代次数
            }
        } else if (strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--cross-core") == 0) {
            mode = 2;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--cross-process") == 0) {
            mode = 3;
        }
    }
    
    // 检查root权限
    if (geteuid() != 0) {
        printf("Warning: Some tests require root privileges. Run with sudo.\n");
    }
    
    // 加载DES库
    if (load_des_library("./build/libdes.so") != 0) {
        fprintf(stderr, "Failed to load DES library\n");
        return 1;
    }
    
    // 获取S-boxes指针
    if (get_sboxes_func) {
        g_sboxes = get_sboxes_func();
        printf("S-boxes loaded at %p\n", (void*)g_sboxes);
    }
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║     DES Flush+Reload Attack Mitigation Test Framework     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    printf("\nTest Configuration:\n");
    printf("  Iterations: %d\n", iterations);
    printf("  Test Key: 0x%016lX\n", (unsigned long)TEST_KEY);
    printf("\n");
    
    // 执行测试
    switch (mode) {
        case 0:
            test_all_mitigations(iterations);
            break;
        case 1:
            if (compare_type > 0) {
                test_comparison(compare_type, iterations);
            } else {
                printf("Error: Mitigation type required for comparison test\n");
                print_usage(argv[0]);
            }
            break;
        case 2:
            test_cross_core_migration();
            break;
        case 3:
            test_cross_process_isolation();
            break;
        default:
            test_all_mitigations(iterations);
            break;
    }
    
    // 清理
    unload_des_library();
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════╗\n");
    printf("║                    Test Complete                          ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");
    
    return 0;
}
