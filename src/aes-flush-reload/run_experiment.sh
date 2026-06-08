#!/bin/bash

# AES Flush+Reload 综合实验脚本
# 支持成功率测试、量化指标测量、多策略对比、自动绘图
#
# 使用方法：
#   # 完整测试（所有AES类型 + 所有缓解措施）
#   # AES-128: 100轮, AES-192: 100轮, AES-256: 100轮
#   ./run_experiment.sh --full-test
#
#   # 基准测试（不使用缓解策略）
#   # 参数: $1=AES类型, $2=轮数, $3=样本量(可选，自动设置)
#   ./run_experiment.sh 128 100          # AES-128, 20000样本(自动)
#   ./run_experiment.sh 192 100          # AES-192, 20000样本(自动)
#   ./run_experiment.sh 256 100          # AES-256, 20000样本(自动)
#
#   # 单一策略测试（基准 + 指定缓解措施）
#   ./run_experiment.sh 128 100 --noise-low
#   ./run_experiment.sh 128 100 --noise-medium
#   ./run_experiment.sh 128 100 --noise-high
#   ./run_experiment.sh 128 100 --cache-flush
#
#   # 测试所有缓解措施 + 基准（--compare模式）
#   ./run_experiment.sh 128 100 --compare
#   ./run_experiment.sh 192 100 --compare
#   ./run_experiment.sh 256 100 --compare
#
# 参数说明：
#   $1 - AES类型 128/192/256 (默认: 128)
#   $2 - 测试轮数 (默认: 100)
#   $3 - 样本量 (可选，默认根据AES类型自动设置)
#        AES-128: 20000, AES-192: 20000, AES-256: 20000
#
#   样本量设置示例：
#   # 使用默认样本量
#   ./run_experiment.sh 128 100（推荐）
#   ./run_experiment.sh 128 100              # AES-128, 自动使用20000样本
#   ./run_experiment.sh 192 100              # AES-192, 自动使用20000样本
#
#   # 手动指定样本量（第三个参数）
#   ./run_experiment.sh 128 100 10000        # AES-128, 手动设置10000样本
#   ./run_experiment.sh 192 100 50000        # AES-192, 手动设置50000样本
#   ./run_experiment.sh 256 100 100000        # AES-256, 手动设置100000样本
#
# 缓解措施选项：
#   --noise-low       加密后以30%概率读取T表缓存行
#   --noise-medium    加密后以40%概率读取T表缓存行
#   --noise-high      加密后以50%概率读取T表缓存行
#   --cache-flush     victim加密后刷新T表缓存（最有效的缓解措施）
#   --compare         测试所有缓解措施 + 基准
#
# 输出指标说明：
#   - sample_count: 总样本数（加密次数）
#   - measurement_count: 总测量次数（= sample_count * 4，每次测量4个T表）
#   - hit_count/miss_count: 缓存命中/未命中次数
#   - hit_rate/miss_rate: 命中/未命中率 (0-1)
#   - avg_snr: 平均信噪比
#   - leakage_bw_bps: 泄露带宽 (bits per second)
#
# 输出文件：
#   - results/data/experiment_*.txt  实验数据
#   - results/figures/*.png          可视化图表
#   - results/data/summary_report.md 统计摘要报告

AES_TYPE=${1:-128}
ROUNDS=${2:-100}

case $AES_TYPE in
    128) DEFAULT_SAMPLES=8000 ;;
    192) DEFAULT_SAMPLES=13000 ;;
    256) DEFAULT_SAMPLES=18000 ;;
    *) DEFAULT_SAMPLES=8000 ;;
esac

SAMPLES=$DEFAULT_SAMPLES

COMPARE_MODE=0
MITIGATION_OPTIONS=""

for arg in "$@"; do
    case $arg in
        --compare) COMPARE_MODE=1 ;;
        --noise-low|--noise-medium|--noise-high|--cache-flush)
            MITIGATION_OPTIONS="$MITIGATION_OPTIONS $arg" ;;
        [0-9]*)
            if [ "$arg" != "$AES_TYPE" ] && [ "$arg" != "$ROUNDS" ]; then
                SAMPLES=$arg
            fi
            ;;
    esac
done

if [ $COMPARE_MODE -eq 1 ] && [ -z "$MITIGATION_OPTIONS" ]; then
    MITIGATION_OPTIONS="--noise-low --noise-medium --noise-high --cache-flush"
fi

option_count=$(echo $MITIGATION_OPTIONS | wc -w)
if [ $option_count -gt 1 ]; then
    COMPARE_MODE=1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
DATA_DIR="$RESULTS_DIR/data"
FIGURES_DIR="$RESULTS_DIR/figures"

mkdir -p "$DATA_DIR" "$FIGURES_DIR"

parse_metrics() {
    local output="$1"
    if echo "$output" | grep -q "METRICS_OUTPUT_START"; then
        echo "$output" | sed -n '/METRICS_OUTPUT_START/,/METRICS_OUTPUT_END/p' | \
            grep -E "^(sample_count|measurement_count|hit_count|miss_count|hit_|miss_|mean_diff|snr|welch|overlap|binary_mi|leakage|dist|avg_cycles|cpu_freq)"
    fi
}

parse_performance() {
    local output="$1"
    if echo "$output" | grep -q "PERFORMANCE_OUTPUT_START"; then
        echo "$output" | sed -n '/PERFORMANCE_OUTPUT_START/,/PERFORMANCE_OUTPUT_END/p' | \
            grep -E "^(total_encrypt_cycles|encrypt_count|avg_encrypt_cycles|encrypt_throughput|baseline_cycles|overhead_percent)"
    fi
}

aggregate_metrics() {
    local metrics_dir="$1"
    local output_file="$2"
    
    local total_samples=0 total_measurements=0
    local total_hit=0 total_miss=0
    local hit_sum=0 miss_sum=0 snr_sum=0 bw_sum=0
    local binary_mi_sum=0
    local perf_sum=0 perf_count=0
    local count=0
    
    for f in "$metrics_dir"/*.txt; do
        [ -f "$f" ] || continue
        while IFS=: read -r key val; do
            case "$key" in
                sample_count) total_samples=$((total_samples + val)) ;;
                measurement_count) total_measurements=$((total_measurements + val)) ;;
                hit_count) total_hit=$((total_hit + val)) ;;
                miss_count) total_miss=$((total_miss + val)) ;;
                hit_mean) hit_sum=$(echo "$hit_sum + $val" | bc); count=$((count + 1)) ;;
                miss_mean) miss_sum=$(echo "$miss_sum + $val" | bc) ;;
                snr) snr_sum=$(echo "$snr_sum + $val" | bc) ;;
                binary_mi) binary_mi_sum=$(echo "$binary_mi_sum + $val" | bc) ;;
                leakage_bw_bps) bw_sum=$(echo "$bw_sum + $val" | bc) ;;
                avg_encrypt_cycles) perf_sum=$(echo "$perf_sum + $val" | bc); perf_count=$((perf_count + 1)) ;;
            esac
        done < "$f"
    done
    
    [ $count -eq 0 ] && return
    
    {
        echo "sample_count_total:$total_samples"
        echo "measurement_count_total:$total_measurements"
        echo "hit_count_total:$total_hit"
        echo "miss_count_total:$total_miss"
        echo "hit_rate:$(echo "scale=4; $total_hit / $total_measurements" | bc)"
        echo "miss_rate:$(echo "scale=4; $total_miss / $total_measurements" | bc)"
        echo "rounds_tested:$count"
        echo "avg_hit_mean:$(echo "scale=2; $hit_sum / $count" | bc)"
        echo "avg_miss_mean:$(echo "scale=2; $miss_sum / $count" | bc)"
        echo "avg_snr:$(echo "scale=4; $snr_sum / $count" | bc)"
        echo "avg_binary_mi:$(echo "scale=6; $binary_mi_sum / $count" | bc)"
        echo "leakage_bw_bps:$(echo "scale=2; $bw_sum / $count" | bc)"
        if [ $perf_count -gt 0 ]; then
            echo "avg_encrypt_cycles:$(echo "scale=2; $perf_sum / $perf_count" | bc)"
        fi
    } > "$output_file"
}

run_single_test() {
    local options="$1"
    local success=0 fail=0
    local metrics_dir=$(mktemp -d)
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    RESULT_FILE="$DATA_DIR/experiment_${AES_TYPE}_${timestamp}.txt"
    
    echo "========================================"
    echo "AES-$AES_TYPE 综合统计测试"
    echo "========================================"
    echo "AES类型: $AES_TYPE | 样本量: $SAMPLES | 轮数: $ROUNDS"
    [ -n "$options" ] && echo "缓解措施:$options"
    echo "核心绑定: $(echo "$options" | grep -q '\-\-no-pin' && echo '禁用' || echo '启用')"
    echo "========================================"
    
    {
        echo "# Experiment: AES-$AES_TYPE"
        echo "# Config: samples=$SAMPLES, rounds=$ROUNDS"
        [ -n "$options" ] && echo "# Options:$options"
        echo "# Timestamp: $(date)"
        echo ""
        echo "# Success Rate Summary"
        echo "实验配置 | 成功次数 | 失败次数 | 成功率"
        echo "---------|----------|----------|--------"
    } > "$RESULT_FILE"
    
    for ((i=1; i<=ROUNDS; i++)); do
        OUTPUT=$(./build/bin/attack_aes $AES_TYPE $SAMPLES $options --metrics 2>&1)
        if echo "$OUTPUT" | grep -q "ATTACK SUCCESSFUL"; then
            ((success++)); echo "[$i/$ROUNDS] 成功 ✓"
        else
            ((fail++)); echo "[$i/$ROUNDS] 失败 ✗"
        fi
        parse_metrics "$OUTPUT" > "$metrics_dir/round_$i.txt"
    done
    
    echo ""
    echo "========================================"
    echo "测试结果: 成功=$success, 失败=$fail, 成功率=$((success*100/ROUNDS))%"
    echo "========================================"
    
    local agg_file=$(mktemp)
    aggregate_metrics "$metrics_dir" "$agg_file"
    cat "$agg_file"
    echo "========================================"
    
    echo "单独测试 | $success | $fail | $((success*100/ROUNDS))%" >> "$RESULT_FILE"
    {
        echo ""
        echo "# Metrics: 单独测试"
        cat "$agg_file"
    } >> "$RESULT_FILE"
    
    rm -rf "$metrics_dir" "$agg_file"
    
    echo ""
    echo "结果已保存到: $RESULT_FILE"
    
    echo ""
    echo "生成可视化图表..."
    python3 "$SCRIPT_DIR/scripts/plot_results.py" "$AES_TYPE" 2>/dev/null || \
        echo "Note: Python visualization skipped"
}

run_compare_test() {
    local desc="$1"
    local options="$2"
    local summary_file="$3"
    local success=0 fail=0
    local metrics_dir=$(mktemp -d)
    
    echo "=== $desc ==="
    for ((i=1; i<=ROUNDS; i++)); do
        result=$(./build/bin/attack_aes $AES_TYPE $SAMPLES $options --metrics 2>&1)
        if echo "$result" | grep -q "ATTACK SUCCESSFUL"; then
            ((success++))
        else
            ((fail++))
        fi
        parse_metrics "$result" > "$metrics_dir/round_$i.txt"
        printf "\r  Progress: %d/%d, Success: %d, Fail: %d" $i $ROUNDS $success $fail
    done
    echo ""
    echo "  Result: Success=$success, Fail=$fail, Rate=$((success*100/ROUNDS))%"
    
    local agg_file=$(mktemp)
    aggregate_metrics "$metrics_dir" "$agg_file"
    echo "  Metrics:"
    cat "$agg_file" | sed 's/^/    /'
    echo ""
    
    echo "$desc | $success | $fail | $((success*100/ROUNDS))%" >> "$summary_file"
    
    {
        echo ""
        echo "# Metrics: $desc"
        cat "$agg_file"
    } >> "$RESULT_FILE"
    
    rm -rf "$metrics_dir" "$agg_file"
}

run_compare_mode() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    RESULT_FILE="$DATA_DIR/experiment_${AES_TYPE}_${timestamp}.txt"
    local summary_temp=$(mktemp)
    
    if [ $COMPARE_MODE -eq 1 ]; then
        echo "========================================"
        echo "AES-$AES_TYPE 所有缓解措施对比测试"
        echo "========================================"
    else
        echo "========================================"
        echo "AES-$AES_TYPE 多策略组合测试"
        echo "========================================"
    fi
    echo "AES类型: $AES_TYPE | 样本量: $SAMPLES | 轮数: $ROUNDS"
    echo "========================================"
    
    {
        echo "# Experiment: AES-$AES_TYPE"
        echo "# Config: samples=$SAMPLES, rounds=$ROUNDS"
        echo "# Timestamp: $(date)"
        echo ""
        echo "# Success Rate Summary"
        echo "实验配置 | 成功次数 | 失败次数 | 成功率"
        echo "---------|----------|----------|--------"
    } > "$RESULT_FILE"
    
    echo "使用自动阈值校准（每次运行独立校准）..."
    THRESHOLD_OPT=""
    echo ""
    
    run_compare_test "1. 基准（默认）" "$THRESHOLD_OPT" "$summary_temp"
    
    local idx=2
    for opt in $MITIGATION_OPTIONS; do
        run_compare_test "$idx. $opt" "$THRESHOLD_OPT $opt" "$summary_temp"
        idx=$((idx + 1))
    done
    
    run_compare_test "$idx. 全部组合$MITIGATION_OPTIONS" "$THRESHOLD_OPT $MITIGATION_OPTIONS" "$summary_temp"
    
    cat "$summary_temp" >> "$RESULT_FILE"
    
    echo ""
    if [ $COMPARE_MODE -eq 1 ]; then
        echo "========================================"
        echo "所有缓解措施对比测试结果汇总"
        echo "========================================"
    else
        echo "========================================"
        echo "多策略组合测试结果汇总"
        echo "========================================"
    fi
    cat "$summary_temp"
    echo ""
    echo "结果已保存到: $RESULT_FILE"
    
    rm -f "$summary_temp"
    
    echo ""
    echo "生成可视化图表..."
    python3 "$SCRIPT_DIR/scripts/plot_results.py" "$AES_TYPE" 2>/dev/null || \
        echo "Note: Python visualization skipped"
}

run_full_test() {
    echo "========================================"
    echo "完整测试：所有AES类型 + 所有缓解措施"
    echo "测试轮数：每种配置100轮"
    echo "========================================"
    echo ""
    local all_results=""
    
    echo "=== AES-128 (8000样本, 100轮) ==="
    for mode in "" "--noise-low" "--noise-medium" "--noise-high" "--cache-flush"; do
        local mode_name=$(echo "$mode" | tr -d ' ' | sed 's/^$/基准/g')
        echo -n "  模式 '$mode_name': "
        local success=0
        for i in {1..100}; do
            result=$(./build/bin/attack_aes 128 8000 $mode 2>&1 | grep "Original Key")
            if [[ "$result" == *"SUCCESS"* ]]; then ((success++)); fi
            if (( i % 25 == 0 )); then echo -n "."; fi
        done
        echo " $success/100"
        all_results="$all_results\nAES-128|$mode_name|$success/100"
    done
    
    echo ""
    echo "=== AES-192 (13000样本, 100轮) ==="
    for mode in "" "--noise-low" "--noise-medium" "--noise-high" "--cache-flush"; do
        local mode_name=$(echo "$mode" | tr -d ' ' | sed 's/^$/基准/g')
        echo -n "  模式 '$mode_name': "
        local success=0
        for i in {1..100}; do
            result=$(./build/bin/attack_aes 192 13000 $mode 2>&1 | grep "Original Key")
            if [[ "$result" == *"SUCCESS"* ]]; then ((success++)); fi
            if (( i % 25 == 0 )); then echo -n "."; fi
        done
        echo " $success/100"
        all_results="$all_results\nAES-192|$mode_name|$success/100"
    done
    
    echo ""
    echo "=== AES-256 (18000样本, 100轮) ==="
    for mode in "" "--noise-low" "--noise-medium" "--noise-high" "--cache-flush"; do
        local mode_name=$(echo "$mode" | tr -d ' ' | sed 's/^$/基准/g')
        echo -n "  模式 '$mode_name': "
        local success=0
        for i in {1..100}; do
            result=$(./build/bin/attack_aes 256 18000 $mode 2>&1 | grep "Original Key")
            if [[ "$result" == *"SUCCESS"* ]]; then ((success++)); fi
            if (( i % 25 == 0 )); then echo -n "."; fi
        done
        echo " $success/100"
        all_results="$all_results\nAES-256|$mode_name|$success/100"
    done
    
    echo ""
    echo "========================================"
    echo "完整测试结果汇总"
    echo "========================================"
    echo "AES类型 | 缓解措施 | 成功率"
    echo "--------|----------|--------"
    echo -e "$all_results"
    echo "========================================"
}

if [ "$1" = "--full-test" ]; then
    run_full_test
    exit 0
fi

if [ $COMPARE_MODE -eq 1 ]; then
    run_compare_mode
else
    run_single_test "$MITIGATION_OPTIONS"
fi
