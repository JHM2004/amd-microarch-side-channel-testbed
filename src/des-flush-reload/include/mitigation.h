/**
 * mitigation.h
 * DES Flush+Reload Attack - 缓解措施验证框架
 * 
 * 功能：
 * - 定义各种缓存侧信道缓解措施
 * - 提供缓解措施效果测试接口
 * - 支持跨核/跨进程隔离测试
 */

#ifndef MITIGATION_H
#define MITIGATION_H

#include <stdint.h>
#include <stdbool.h>
#include <sched.h>

// 缓解措施类型枚举
typedef enum {
    MITIGATION_NONE = 0,           // 无缓解措施（基准测试）
    MITIGATION_CPU_PINNING,        // CPU亲和性绑定（受害者与攻击者分离）
    MITIGATION_CACHE_FLUSH,        // 频繁缓存冲洗
    MITIGATION_NOISE_INJECTION,    // 噪声注入
    MITIGATION_ACCESS_OBFUSCATION, // 访问混淆（随机访问模式）
    MITIGATION_PROCESS_ISOLATION,  // 进程隔离（不同进程空间）
    MITIGATION_CORE_ISOLATION,     // 核心隔离（不同物理核心）
    MITIGATION_HYPERTHREAD_DISABLE,// 禁用超线程
    MITIGATION_COUNT               // 缓解措施数量
} MitigationType;

// 缓解措施配置结构
typedef struct {
    MitigationType type;
    const char* name;
    const char* description;
    bool enabled;
    // 特定缓解措施的参数
    union {
        struct {
            int attacker_core;
            int victim_core;
        } cpu_pinning;
        struct {
            int flush_interval;  // 每N次访问冲洗一次
        } cache_flush;
        struct {
            int noise_accesses;  // 注入的噪声访问次数
        } noise_injection;
        struct {
            int obfuscation_range; // 混淆访问范围
        } access_obfuscation;
    } params;
} MitigationConfig;

// 测试结果结构
typedef struct {
    MitigationType mitigation_type;
    const char* test_name;
    
    // 攻击效果指标
    double attack_success_rate;      // 攻击成功率
    double avg_recovery_fragments;   // 平均恢复片段数
    double avg_leakage_bandwidth;    // 平均泄露带宽
    
    // 性能指标
    double avg_attack_duration_ms;   // 平均攻击时间
    double overhead_percent;         // 缓解措施开销百分比
    
    // 统计显著性
    double p_value;                  // 与基准对比的p值
    bool statistically_significant;  // 是否统计显著
    
    // 详细数据
    int total_tests;
    int successful_attacks;
    double confidence_interval_95;   // 95%置信区间
} MitigationTestResult;

// 跨核测试配置
typedef struct {
    int source_core;      // 攻击者核心
    int target_core;      // 受害者核心
    bool same_socket;     // 是否在同一CPU插槽
    bool same_ccx;        // 是否在同一CCX（AMD）或L3域（Intel）
} CoreIsolationConfig;

// 跨进程测试配置
typedef struct {
    bool same_user;       // 是否同一用户
    bool same_namespace;  // 是否同一命名空间
    int nice_level;       // 进程优先级
} ProcessIsolationConfig;

// ==================== 缓解措施控制接口 ====================

// 初始化缓解措施系统
void mitigation_init(void);

// 配置特定缓解措施
void mitigation_configure(MitigationConfig* config);

// 启用/禁用缓解措施
void mitigation_enable(MitigationType type);
void mitigation_disable(MitigationType type);

// 应用缓解措施（在攻击前调用）
void mitigation_apply(MitigationType type);

// 移除缓解措施（在攻击后调用）
void mitigation_remove(MitigationType type);

// ==================== 具体缓解措施实现 ====================

// CPU亲和性绑定
void mitigation_cpu_pinning_apply(int attacker_core, int victim_core);
void mitigation_cpu_pinning_remove(void);

// 缓存冲洗策略
void mitigation_cache_flush_apply(int interval);
void mitigation_cache_flush_remove(void);

// 噪声注入
void mitigation_noise_injection_apply(int noise_count);
void mitigation_noise_injection_remove(void);

// 访问混淆
void mitigation_access_obfuscation_apply(int range);
void mitigation_access_obfuscation_remove(void);

// 进程隔离
void mitigation_process_isolation_apply(void);
void mitigation_process_isolation_remove(void);

// 核心隔离
void mitigation_core_isolation_apply(int attacker_core, int victim_core);
void mitigation_core_isolation_remove(void);

// ==================== 缓解措施钩子（在攻击过程中调用）====================

// 初始化钩子系统
void mitigation_hooks_init(void);

// 在每次加密操作前调用（Trigger之前）
void mitigation_hook_pre_encrypt(void);

// 在每次加密操作后调用（Reload之后）
void mitigation_hook_post_encrypt(void);

// 在每个S-box条目测试前调用
void mitigation_hook_pre_sbox_entry(int sbox, int entry);

// 在每个S-box条目测试后调用
void mitigation_hook_post_sbox_entry(int sbox, int entry);

// 在每轮攻击开始前调用
void mitigation_hook_round_start(int round_num);

// 在每轮攻击结束后调用
void mitigation_hook_round_end(int round_num);

// 设置当前激活的缓解措施（用于钩子）
void mitigation_set_active(MitigationType type);

// 获取当前激活的缓解措施
MitigationType mitigation_get_active(void);

// ==================== 测试框架接口 ====================

// 运行单一缓解措施测试
MitigationTestResult mitigation_test_single(
    MitigationType type,
    int iterations,
    uint64_t test_key
);

// 运行对比测试（开启vs关闭缓解措施）
void mitigation_test_comparison(
    MitigationType type,
    int iterations,
    MitigationTestResult* baseline,
    MitigationTestResult* with_mitigation
);

// 运行所有缓解措施测试
void mitigation_test_all(
    int iterations,
    MitigationTestResult results[MITIGATION_COUNT]
);

// 跨核可迁移性测试
void mitigation_test_cross_core(
    CoreIsolationConfig* configs,
    int num_configs,
    MitigationTestResult* results
);

// 跨进程可迁移性测试
void mitigation_test_cross_process(
    ProcessIsolationConfig* configs,
    int num_configs,
    MitigationTestResult* results
);

// ==================== 统计分析与报告 ====================

// 计算缓解措施效果
void mitigation_calculate_effectiveness(
    const MitigationTestResult* baseline,
    const MitigationTestResult* with_mitigation,
    double* effectiveness_percent,
    double* overhead_percent
);

// 生成测试报告
void mitigation_generate_report(
    const MitigationTestResult results[MITIGATION_COUNT],
    const char* filename
);

// 打印测试结果摘要
void mitigation_print_summary(
    const MitigationTestResult results[MITIGATION_COUNT]
);

// ==================== 辅助功能 ====================

// 获取缓解措施名称
const char* mitigation_get_name(MitigationType type);

// 获取缓解措施描述
const char* mitigation_get_description(MitigationType type);

// 检查系统支持的缓解措施
bool mitigation_check_support(MitigationType type);

// 设置系统缓解参数（如内核参数）
bool mitigation_set_system_param(const char* param, int value);

// 获取当前CPU拓扑信息
void mitigation_get_cpu_topology(int* cores, int* sockets, int* ht_enabled);

#endif /* MITIGATION_H */
