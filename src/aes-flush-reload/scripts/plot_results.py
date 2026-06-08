#!/usr/bin/env python3
"""
AES Flush+Reload 实验结果可视化脚本

功能：
1. 解析实验结果数据文件
2. 生成统计表格
3. 输出统计摘要

使用方法：
    python3 plot_results.py
"""

import os
import sys
import glob
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    import matplotlib
    matplotlib.use('Agg')
    import numpy as np
    
    plt.rcParams['font.sans-serif'] = ['Noto Sans CJK SC', 'Noto Sans CJK JP', 'AR PL UKai HK', 'DejaVu Sans', 'sans-serif']
    plt.rcParams['axes.unicode_minus'] = False
    plt.rcParams['figure.dpi'] = 150
    
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("Warning: matplotlib not installed, skipping plots")

SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS_DIR = os.path.join(SCRIPT_DIR, "results")
DATA_DIR = os.path.join(RESULTS_DIR, "data")
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")
SINGLE_DIR = os.path.join(FIGURES_DIR, "single_test")
COMPARE_DIR = os.path.join(FIGURES_DIR, "comparison")


def parse_experiment_file(filepath):
    """解析实验数据文件"""
    data = {'config': {}, 'results': []}
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    lines = content.split('\n')
    metrics_dict = {}
    success_rates = []
    current_metrics = {}
    current_name = ""
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        if line.startswith('# Experiment:'):
            data['config']['name'] = line.split(':', 1)[1].strip()
        elif line.startswith('# Config:'):
            parts = line.split(':', 1)
            if len(parts) > 1:
                data['config']['config'] = parts[1].strip()
        elif line.startswith('# Metrics:'):
            if current_metrics and current_name:
                metrics_dict[current_name] = current_metrics
            current_name = line.split(':', 1)[1].strip()
            current_metrics = {}
        elif '|' in line and not line.startswith('-') and '实验配置' not in line:
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 4:
                try:
                    success = int(parts[1])
                    fail = int(parts[2])
                    rate = int(parts[3].replace('%', ''))
                    success_rates.append({'name': parts[0], 'success': success, 'fail': fail, 'rate': rate})
                except (ValueError, IndexError):
                    pass
        elif ':' in line and not line.startswith('#'):
            key, val = line.split(':', 1)
            try:
                current_metrics[key.strip()] = float(val)
            except ValueError:
                current_metrics[key.strip()] = val.strip()
    
    if current_metrics and current_name:
        metrics_dict[current_name] = current_metrics
    
    for sr in success_rates:
        name = sr['name']
        metrics = {}
        for mname, mdata in metrics_dict.items():
            if mname == name or mname.endswith(name) or name.endswith(mname.split('.')[-1].strip()):
                metrics = mdata
                break
        sr['metrics'] = metrics
        data['results'].append(sr)
    
    return data


def is_compare_mode(data):
    """判断是否为对比测试模式"""
    return len(data['results']) > 1


def generate_single_test_table(data, output_dir, aes_type):
    """单独测试：生成完整详细的表格"""
    if not data['results']:
        return
    
    result = data['results'][0]
    m = result.get('metrics', {})
    success = result.get('success', 0)
    fail = result.get('fail', 0)
    rate = result.get('rate', 0)
    
    if not HAS_MATPLOTLIB:
        print("Warning: matplotlib not available, skipping table generation")
        return
    
    fig = plt.figure(figsize=(16, 12))
    ax = fig.add_subplot(111)
    ax.axis('off')
    
    headers = ['Category', 'Metric', 'Value', 'Description']
    
    cell_data = [
        ['Basic', 'AES Type', f'AES-{aes_type}', 'AES key length'],
        ['Basic', 'Test Rounds', str(result.get('rounds_tested', 0)), 'Number of test rounds'],
        ['Basic', 'Success Count', str(success), 'Successful attack count'],
        ['Basic', 'Fail Count', str(fail), 'Failed attack count'],
        ['Basic', 'Success Rate', f'{rate}%', 'Attack success rate'],
        ['Sample', 'Sample Count', f"{int(m.get('sample_count_total', 0))}", 'Total AES encryptions'],
        ['Sample', 'Measurement Count', f"{int(m.get('measurement_count_total', 0))}", 'Total T-table measurements'],
        ['Sample', 'Hit Count', f"{int(m.get('hit_count_total', 0))}", 'Cache hit count'],
        ['Sample', 'Miss Count', f"{int(m.get('miss_count_total', 0))}", 'Cache miss count'],
        ['Rate', 'Hit Rate', f"{m.get('hit_rate', 0):.4f}", 'Cache hit ratio'],
        ['Rate', 'Miss Rate', f"{m.get('miss_rate', 0):.4f}", 'Cache miss ratio'],
        ['Timing', 'Hit Mean (cycles)', f"{m.get('avg_hit_mean', 0):.2f}", 'Average cache hit time'],
        ['Timing', 'Miss Mean (cycles)', f"{m.get('avg_miss_mean', 0):.2f}", 'Average cache miss time'],
        ['Timing', 'Time Difference', f"{m.get('avg_miss_mean', 0) - m.get('avg_hit_mean', 0):.2f}", 'Miss - Hit time gap'],
        ['Security', 'SNR', f"{m.get('avg_snr', 0):.4f}", 'Signal-to-Noise Ratio'],
        ['Security', 'Leakage BW (bps)', f"{m.get('leakage_bw_bps', 0):.2f}", 'Information leakage rate'],
    ]
    
    table = ax.table(cellText=cell_data, colLabels=headers, loc='center',
                     cellLoc='center', colWidths=[0.15, 0.25, 0.2, 0.4])
    
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1.2, 1.8)
    
    for i in range(4):
        table[(0, i)].set_text_props(fontweight='bold', color='white')
        table[(0, i)].set_facecolor('#2c3e50')
    
    category_colors = {
        'Basic': '#ebf5fb',
        'Sample': '#e8f8f8',
        'Rate': '#fef9e7',
        'Timing': '#f5eef8',
        'Security': '#fdf2e9'
    }
    
    for i in range(1, len(cell_data) + 1):
        category = cell_data[i-1][0]
        color = category_colors.get(category, 'white')
        for j in range(4):
            table[(i, j)].set_facecolor(color)
    
    ax.set_title(f'AES-{aes_type} Single Test Results - Complete Metrics Table', 
                 fontsize=16, fontweight='bold', pad=20, y=0.98)
    
    plt.tight_layout()
    output_path = os.path.join(output_dir, f'single_test_table_{aes_type}.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()


def generate_compare_table(data, output_dir, aes_type):
    """对比测试：生成完整详细的对比表格"""
    if not data['results']:
        return
    
    if not HAS_MATPLOTLIB:
        print("Warning: matplotlib not available, skipping table generation")
        return
    
    config_names = {
        '1': 'Baseline',
        '2': 'Noise-Low',
        '3': 'Noise-Med',
        '4': 'Noise-High',
        '5': 'Cache-Flush'
    }

    config_desc = {
        'Baseline': 'Default config (CPU pinned)',
        'Noise-Low': 'Low noise (30% access probability)',
        'Noise-Med': 'Medium noise (40% access probability)',
        'Noise-High': 'High noise (50% access probability)',
        'Cache-Flush': 'Cache flushed after encryption'
    }

    config_full_names = {
        '1': '1-Baseline',
        '2': '2-Noise-Low',
        '3': '3-Noise-Med',
        '4': '4-Noise-High',
        '5': '5-Cache-Flush'
    }
    
    fig = plt.figure(figsize=(24, 12))
    ax = fig.add_subplot(111)
    ax.axis('off')
    
    headers = ['No.', 'Configuration', 'Success/Fail', 'Rate', 'Samples', 'Hit Rate', 'Miss Rate',
               'Hit Mean', 'Miss Mean', 'SNR', 'BW(bps)', 'Perf(cycles)', 'Overhead']
    
    baseline_cycles = None
    for r in data['results']:
        m = r.get('metrics', {})
        name_raw = r['name'].split('.')[0].strip()
        config_key = name_raw.split()[0] if name_raw.split()[0].isdigit() else '1'
        if config_key == '1':
            baseline_cycles = m.get('avg_encrypt_cycles', 0)
            break

    cell_data = []
    for r in data['results']:
        m = r.get('metrics', {})
        name_raw = r['name'].split('.')[0].strip()

        config_key = name_raw.split()[0] if name_raw.split()[0].isdigit() else '1'
        config_name = config_full_names.get(config_key, config_names.get(config_key, name_raw[:15]))
        
        avg_cycles = m.get('avg_encrypt_cycles', 0)
        overhead = ""
        if baseline_cycles and baseline_cycles > 0 and avg_cycles > 0:
            overhead_pct = ((avg_cycles - baseline_cycles) / baseline_cycles) * 100
            overhead = f"{overhead_pct:.1f}%"
        
        row = [
            config_key,
            config_name,
            f"{r.get('success', 0)}/{r.get('fail', 0)}",
            f"{r.get('rate', 0)}%",
            f"{int(m.get('sample_count_total', 0))//1000}K",
            f"{m.get('hit_rate', 0):.3f}",
            f"{m.get('miss_rate', 0):.3f}",
            f"{m.get('avg_hit_mean', 0):.1f}",
            f"{m.get('avg_miss_mean', 0):.1f}",
            f"{m.get('avg_snr', 0):.4f}",
            f"{m.get('leakage_bw_bps', 0):.0f}",
            f"{avg_cycles:.0f}" if avg_cycles > 0 else "-",
            overhead if overhead else "-"
        ]
        cell_data.append(row)
    
    col_widths = [0.03, 0.10, 0.05, 0.04, 0.04, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05, 0.05]
    
    table = ax.table(cellText=cell_data, colLabels=headers, loc='center',
                     cellLoc='center', colWidths=col_widths)
    
    table.auto_set_font_size(False)
    table.set_fontsize(8)
    table.scale(1.1, 1.8)
    
    for i in range(len(headers)):
        table[(0, i)].set_text_props(fontweight='bold', color='white')
        table[(0, i)].set_facecolor('#2c3e50')
    
    for i in range(1, len(cell_data) + 1):
        rate_val = int(cell_data[i-1][3].replace('%', ''))
        if rate_val >= 50:
            table[(i, 3)].set_facecolor('#d5f5e3')
        else:
            table[(i, 3)].set_facecolor('#fadbd8')
        
        bw_val = float(cell_data[i-1][10]) if cell_data[i-1][10] != '-' else 0
        if bw_val > 100000:
            table[(i, 10)].set_facecolor('#fadbd8')
        elif bw_val > 10000:
            table[(i, 10)].set_facecolor('#fef9e7')
        else:
            table[(i, 10)].set_facecolor('#d5f5e3')
        
        overhead_str = cell_data[i-1][12]
        if overhead_str != '-' and overhead_str != '':
            try:
                overhead_val = float(overhead_str.replace('%', ''))
                if overhead_val > 20:
                    table[(i, 12)].set_facecolor('#fadbd8')
                elif overhead_val > 5:
                    table[(i, 12)].set_facecolor('#fef9e7')
                else:
                    table[(i, 12)].set_facecolor('#d5f5e3')
            except:
                pass
    
    ax.set_title(f'AES-{aes_type} Comparison Test Results - Complete Metrics Table (with Performance Overhead)', 
                 fontsize=16, fontweight='bold', pad=20, y=0.98)
    
    footnote = ('Configuration Legend:\n'
                '• 1-Baseline: Default config (CPU core pinning enabled)\n'
                '• 2-Noise-Low: 30%% probability read T-table cache line 0 after encryption\n'
                '• 3-Noise-Med: 40%% probability read T-table cache line 0 after encryption\n'
                '• 4-Noise-High: 50%% probability read T-table cache line 0 after encryption\n'
                '• 5-Cache-Flush: T-table cache flushed after encryption\n\n'
                'Performance Overhead: Percentage increase in encryption cycles vs Baseline\n'
                'Color Code: Green=Secure/Low overhead, Yellow=Medium, Red=Vulnerable/High overhead')
    
    ax.text(0.5, -0.08, footnote, transform=ax.transAxes, fontsize=8, 
            ha='center', va='top', style='italic',
            bbox=dict(boxstyle='round', facecolor='#f8f9fa', alpha=0.9))
    
    plt.tight_layout()
    plt.subplots_adjust(bottom=0.18)
    output_path = os.path.join(output_dir, f'comparison_table_{aes_type}.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()


def generate_summary_report(all_data, output_path):
    """生成统计摘要报告"""
    report = []
    report.append("# AES Flush+Reload 实验结果摘要\n\n")
    report.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    
    for aes_type, data in sorted(all_data.items()):
        report.append(f"## AES-{aes_type}\n\n")
        
        if not data['results']:
            report.append("无数据\n\n")
            continue
        
        if is_compare_mode(data):
            report.append("### 对比测试结果\n\n")
        else:
            report.append("### 单独测试结果\n\n")
        
        report.append("| 配置 | 成功 | 失败 | 成功率 |\n")
        report.append("|------|------|------|--------|\n")
        for r in data['results']:
            report.append(f"| {r['name']} | {r.get('success', 'N/A')} | {r.get('fail', 'N/A')} | {r.get('rate', 'N/A')}% |\n")
        report.append("\n")
        
        report.append("### 关键指标\n\n")
        report.append("| 配置 | hit_rate | miss_rate | SNR | 泄露带宽(bps) |\n")
        report.append("|------|----------|-----------|-----|---------------|\n")
        for r in data['results']:
            m = r.get('metrics', {})
            hit_rate = m.get('hit_rate', 'N/A')
            miss_rate = m.get('miss_rate', 'N/A')
            snr = m.get('avg_snr', 'N/A')
            bw = m.get('leakage_bw_bps', 'N/A')
            
            hit_rate_str = f"{hit_rate:.4f}" if isinstance(hit_rate, (int, float)) else str(hit_rate)
            miss_rate_str = f"{miss_rate:.4f}" if isinstance(miss_rate, (int, float)) else str(miss_rate)
            snr_str = f"{snr:.4f}" if isinstance(snr, (int, float)) else str(snr)
            bw_str = f"{bw:.2f}" if isinstance(bw, (int, float)) else str(bw)
            
            report.append(f"| {r['name']} | {hit_rate_str} | {miss_rate_str} | {snr_str} | {bw_str} |\n")
        report.append("\n")
        
        baseline_rate = data['results'][0].get('rate', 0) if data['results'] else 0
        
        if is_compare_mode(data):
            cache_flush_rate = 0
            for r in data['results']:
                if '缓存刷新' in r['name'] or 'cache-flush' in r['name'].lower():
                    cache_flush_rate = r.get('rate', 0)
                    break
            
            report.append("### 结论\n\n")
            if cache_flush_rate == 0:
                report.append("- **缓存刷新**完全阻止了攻击\n")
            if baseline_rate > 80:
                report.append(f"- 基准攻击成功率为{baseline_rate}%，攻击有效\n")
            elif baseline_rate > 50:
                report.append(f"- 基准攻击成功率为{baseline_rate}%，攻击部分有效\n")
            else:
                report.append(f"- 基准攻击成功率为{baseline_rate}%，攻击效果有限\n")
        else:
            report.append("### 结论\n\n")
            if baseline_rate >= 50:
                report.append(f"- 攻击成功率为{baseline_rate}%，攻击有效\n")
            else:
                report.append(f"- 攻击成功率为{baseline_rate}%，攻击效果有限\n")
        
        report.append("\n")
    
    with open(output_path, 'w') as f:
        f.writelines(report)


def generate_success_rate_bar(data, output_dir, aes_type):
    """生成成功率柱状图"""
    if not data['results'] or not HAS_MATPLOTLIB:
        return
    
    config_labels = []
    rates = []
    for r in data['results']:
        name_raw = r['name'].split('.')[0].strip()
        config_key = name_raw.split()[0] if name_raw.split()[0].isdigit() else '1'
        
        label_map = {
            '1': 'Baseline',
            '2': 'Noise-Low',
            '3': 'Noise-Med',
            '4': 'Noise-High',
            '5': 'Cache-Flush'
        }
        if config_key == '6':
            continue
        config_labels.append(label_map.get(config_key, name_raw[:12]))
        rates.append(r.get('rate', 0))
    
    fig, ax = plt.subplots(figsize=(10, 6))
    colors = ['#2ecc71' if r >= 50 else '#e74c3c' if r == 0 else '#f39c12' for r in rates]
    bars = ax.bar(range(len(config_labels)), rates, color=colors, edgecolor='black', linewidth=0.5)
    
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
                f'{rate}%', ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    ax.set_xticks(range(len(config_labels)))
    ax.set_xticklabels(config_labels, rotation=30, ha='right', fontsize=10)
    ax.set_ylabel('Success Rate (%)', fontsize=12)
    ax.set_title(f'AES-{aes_type} Attack Success Rate by Mitigation', fontsize=14, fontweight='bold')
    ax.set_ylim(0, 115)
    ax.axhline(y=50, color='gray', linestyle='--', alpha=0.5, label='50% threshold')
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3)
    
    plt.tight_layout()
    output_path = os.path.join(output_dir, f'success_rate_bar_{aes_type}.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()


def generate_all_types_comparison(all_data, output_dir):
    """生成所有AES类型的综合对比图"""
    if not all_data or not HAS_MATPLOTLIB:
        return
    
    fig, axes = plt.subplots(1, 3, figsize=(18, 6), sharey=True)
    
    mitigation_labels = ['Baseline', 'Noise-Low', 'Noise-Med', 'Noise-High', 'Cache-Flush']
    
    for idx, aes_type in enumerate(['128', '192', '256']):
        ax = axes[idx]
        if aes_type not in all_data:
            ax.set_title(f'AES-{aes_type}\nNo Data', fontsize=12)
            continue
        
        data = all_data[aes_type]
        config_labels = []
        rates = []
        
        for r in data['results']:
            name_raw = r['name'].split('.')[0].strip()
            config_key = name_raw.split()[0] if name_raw.split()[0].isdigit() else '1'
            if config_key == '6':
                continue
            label_map = {
                '1': 'Baseline', '2': 'Noise-Low', '3': 'Noise-Med',
                '4': 'Noise-High', '5': 'Cache-Flush'
            }
            config_labels.append(label_map.get(config_key, name_raw[:10]))
            rates.append(r.get('rate', 0))
        
        colors = ['#2ecc71' if r >= 50 else '#e74c3c' if r == 0 else '#f39c12' for r in rates]
        bars = ax.bar(range(len(config_labels)), rates, color=colors, edgecolor='black', linewidth=0.5)
        
        for bar, rate in zip(bars, rates):
            ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1,
                    f'{rate}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
        
        ax.set_xticks(range(len(config_labels)))
        ax.set_xticklabels(config_labels, rotation=45, ha='right', fontsize=8)
        ax.set_title(f'AES-{aes_type}', fontsize=13, fontweight='bold')
        ax.set_ylim(0, 115)
        ax.grid(axis='y', alpha=0.3)
        if idx == 0:
            ax.set_ylabel('Success Rate (%)', fontsize=12)
    
    fig.suptitle('AES Flush+Reload Attack: Success Rate Comparison', 
                 fontsize=15, fontweight='bold', y=1.02)
    plt.tight_layout()
    output_path = os.path.join(output_dir, 'all_types_success_rate.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()


def generate_metrics_comparison(data, output_dir, aes_type):
    if not data['results'] or not HAS_MATPLOTLIB:
        return
    
    config_labels = []
    hit_rates = []
    miss_rates = []
    snrs = []
    
    for r in data['results']:
        m = r.get('metrics', {})
        name_raw = r['name'].split('.')[0].strip()
        config_key = name_raw.split()[0] if name_raw.split()[0].isdigit() else '1'
        label_map = {
            '1': 'Baseline', '2': 'Noise-Low', '3': 'Noise-Med',
            '4': 'Noise-High', '5': 'Cache-Flush', '6': 'All Combined'
        }
        config_labels.append(label_map.get(config_key, name_raw[:10]))
        hit_rates.append(m.get('hit_rate', 0))
        miss_rates.append(m.get('miss_rate', 0))
        snrs.append(m.get('avg_snr', 0))
    
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    
    x = range(len(config_labels))
    
    axes[0].bar(x, hit_rates, color='#3498db', alpha=0.8, label='Hit Rate')
    axes[0].bar(x, miss_rates, bottom=hit_rates, color='#e74c3c', alpha=0.8, label='Miss Rate')
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(config_labels, rotation=30, ha='right', fontsize=9)
    axes[0].set_title('Cache Hit/Miss Rate', fontsize=12, fontweight='bold')
    axes[0].legend(fontsize=9)
    axes[0].grid(axis='y', alpha=0.3)
    
    axes[1].bar(x, snrs, color='#9b59b6', alpha=0.8)
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(config_labels, rotation=30, ha='right', fontsize=9)
    axes[1].set_title('Signal-to-Noise Ratio (SNR)', fontsize=12, fontweight='bold')
    axes[1].grid(axis='y', alpha=0.3)
    
    rates = [r.get('rate', 0) for r in data['results']]
    axes[2].bar(x, rates, color='#2ecc71' if rates[0] >= 50 else '#e74c3c', alpha=0.8)
    for i, rate in enumerate(rates):
        axes[2].text(i, rate + 1, f'{rate}%', ha='center', fontsize=9, fontweight='bold')
    axes[2].set_xticks(x)
    axes[2].set_xticklabels(config_labels, rotation=30, ha='right', fontsize=9)
    axes[2].set_title('Attack Success Rate (%)', fontsize=12, fontweight='bold')
    axes[2].grid(axis='y', alpha=0.3)
    
    fig.suptitle(f'AES-{aes_type} Metrics Comparison', fontsize=14, fontweight='bold', y=1.01)
    plt.tight_layout()
    output_path = os.path.join(output_dir, f'metrics_comparison_{aes_type}.png')
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    plt.close()


def generate_thesis_figures(all_data, output_dir):
    if not all_data or not HAS_MATPLOTLIB:
        return
    
    plt.rcParams['figure.dpi'] = 200
    plt.rcParams['font.size'] = 10
    
    mitigation_labels = ['Baseline', 'Noise-Low', 'Noise-Med', 'Noise-High', 'Cache-Flush']
    mitigation_labels_cn = ['基准', '低噪声', '中噪声', '高噪声', '缓存刷新']
    colors_aes = {'128': '#e74c3c', '192': '#3498db', '256': '#2ecc71'}
    markers_aes = {'128': 'o', '192': 's', '256': '^'}
    
    def get_config_data(data, key, skip_combined=True):
        vals = {}
        for r in data['results']:
            name_raw = r['name'].split('.')[0].strip()
            config_key = name_raw.split()[0] if name_raw.split()[0].isdigit() else '1'
            if skip_combined and config_key == '6':
                continue
            m = r.get('metrics', {})
            if key == 'rate':
                vals[config_key] = r.get('rate', 0)
            else:
                vals[config_key] = m.get(key, 0)
        return vals
    
    # === Figure 1: 综合成功率对比 ===
    fig, ax = plt.subplots(figsize=(7, 4.2))
    x = np.arange(len(mitigation_labels))
    width = 0.25
    for i, aes_type in enumerate(['128', '192', '256']):
        if aes_type not in all_data:
            continue
        data = all_data[aes_type]
        vals = get_config_data(data, 'rate')
        rates = [vals.get(str(j+1), 0) for j in range(5)]
        bars = ax.bar(x + (i-1)*width, rates, width, label=f'AES-{aes_type}',
                      color=colors_aes[aes_type], alpha=0.85, edgecolor='black', linewidth=0.5)
        for bar, rate in zip(bars, rates):
            if rate > 0:
                ax.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 1.5,
                        f'{rate}%', ha='center', va='bottom', fontsize=7, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(mitigation_labels_cn, fontsize=9)
    ax.set_ylabel('攻击成功率 (%)', fontsize=10)
    ax.set_ylim(0, 115)
    ax.legend(fontsize=9, loc='upper right')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout(pad=0.5)
    fig.savefig(os.path.join(output_dir, 'thesis_success_rate.png'), dpi=200, bbox_inches='tight')
    plt.close()
    
    # === Figure 2: SNR对比 ===
    fig, ax = plt.subplots(figsize=(7, 3.8))
    for aes_type in ['128', '192', '256']:
        if aes_type not in all_data:
            continue
        data = all_data[aes_type]
        snr_vals = get_config_data(data, 'avg_snr')
        snr_list = [snr_vals.get(str(j+1), 0) for j in range(5)]
        ax.plot(mitigation_labels_cn, snr_list, marker=markers_aes[aes_type],
               color=colors_aes[aes_type], label=f'AES-{aes_type}', linewidth=1.5, markersize=6)
        for j, val in enumerate(snr_list):
            if val > 0:
                offset_y = 8 if aes_type != '128' or j > 0 else 8
                ax.annotate(f'{val:.1f}', (mitigation_labels_cn[j], val),
                           textcoords="offset points", xytext=(0, offset_y),
                           ha='center', fontsize=6, color=colors_aes[aes_type])
    ax.set_ylabel('信噪比 (SNR)', fontsize=10)
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3, linestyle='--')
    ax.tick_params(axis='x', labelsize=8)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout(pad=0.5)
    fig.savefig(os.path.join(output_dir, 'thesis_snr.png'), dpi=200, bbox_inches='tight')
    plt.close()
    
    # === Figure 3: 命中率对比 ===
    fig, ax = plt.subplots(figsize=(7, 3.8))
    for aes_type in ['128', '192', '256']:
        if aes_type not in all_data:
            continue
        data = all_data[aes_type]
        hit_vals = get_config_data(data, 'hit_rate')
        hit_list = [hit_vals.get(str(j+1), 0) for j in range(5)]
        ax.plot(mitigation_labels_cn, hit_list, marker=markers_aes[aes_type],
                color=colors_aes[aes_type], label=f'AES-{aes_type}', linewidth=1.5, markersize=6)
    ax.set_ylabel('缓存命中率', fontsize=10)
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3, linestyle='--')
    ax.tick_params(axis='x', labelsize=8)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout(pad=0.5)
    fig.savefig(os.path.join(output_dir, 'thesis_hit_rate.png'), dpi=200, bbox_inches='tight')
    plt.close()
    
    # === Figure 4: 泄露带宽对比 ===
    fig, ax = plt.subplots(figsize=(7, 3.8))
    for aes_type in ['128', '192', '256']:
        if aes_type not in all_data:
            continue
        data = all_data[aes_type]
        bw_vals = get_config_data(data, 'leakage_bw_bps')
        bw_list = [bw_vals.get(str(j+1), 0) for j in range(5)]
        ax.plot(mitigation_labels_cn, bw_list, marker=markers_aes[aes_type],
               color=colors_aes[aes_type], label=f'AES-{aes_type}', linewidth=1.5, markersize=6)
    ax.set_ylabel('泄露带宽 (bps)', fontsize=10)
    ax.legend(fontsize=9)
    ax.grid(alpha=0.3, linestyle='--')
    ax.tick_params(axis='x', labelsize=8)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    plt.tight_layout(pad=0.5)
    fig.savefig(os.path.join(output_dir, 'thesis_leakage_bw.png'), dpi=200, bbox_inches='tight')
    plt.close()
    
    plt.rcParams['figure.dpi'] = 150
    plt.rcParams['font.size'] = 10
    print("论文专用图表已生成")


def main():
    import sys
    
    target_aes_type = sys.argv[1] if len(sys.argv) > 1 else None
    
    os.makedirs(SINGLE_DIR, exist_ok=True)
    os.makedirs(COMPARE_DIR, exist_ok=True)
    
    all_data = {}
    
    txt_files = glob.glob(os.path.join(DATA_DIR, "experiment_*.txt"))
    
    files_by_type = {}
    for filepath in txt_files:
        filename = os.path.basename(filepath)
        parts = filename.replace('.txt', '').split('_')
        if len(parts) >= 2:
            aes_type = parts[1]
            if aes_type not in files_by_type:
                files_by_type[aes_type] = []
            files_by_type[aes_type].append(filepath)
    
    if target_aes_type:
        if target_aes_type in files_by_type:
            files = files_by_type[target_aes_type]
            files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            latest_file = files[0]
            data = parse_experiment_file(latest_file)
            all_data[target_aes_type] = data
    else:
        for aes_type, files in files_by_type.items():
            files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
            latest_file = files[0]
            data = parse_experiment_file(latest_file)
            all_data[aes_type] = data
    
    if not all_data:
        print("No data files found")
        return
    
    print("="*60)
    print("AES Flush+Reload 实验结果图表生成")
    print("="*60)
    
    has_single = False
    has_compare = False
    
    for aes_type, data in all_data.items():
        print(f"\n处理 AES-{aes_type} 数据...")
        
        if is_compare_mode(data):
            print(f"检测到对比测试模式 ({len(data['results'])} 个配置)")
            output_dir = COMPARE_DIR
            generate_compare_table(data, output_dir, aes_type)
            generate_success_rate_bar(data, output_dir, aes_type)
            generate_metrics_comparison(data, output_dir, aes_type)
            has_compare = True
        else:
            print(f"检测到单独测试模式")
            output_dir = SINGLE_DIR
            generate_single_test_table(data, output_dir, aes_type)
            has_single = True
    
    if len(all_data) > 1:
        generate_all_types_comparison(all_data, COMPARE_DIR)
        generate_thesis_figures(all_data, COMPARE_DIR)
    
    generate_summary_report(all_data, os.path.join(DATA_DIR, "summary_report.md"))
    
    print("\n" + "="*60)
    print("图表生成完成!")
    if has_single:
        print(f"单独测试图表: {SINGLE_DIR}")
    if has_compare:
        print(f"对比实验图表: {COMPARE_DIR}")
    print(f"摘要报告: {os.path.join(DATA_DIR, 'summary_report.md')}")
    print("="*60)


if __name__ == '__main__':
    main()
