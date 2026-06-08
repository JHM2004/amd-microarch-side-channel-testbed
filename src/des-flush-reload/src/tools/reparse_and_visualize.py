#!/usr/bin/env python3
"""
reparse_and_visualize.py
重新解析已有的日志文件并生成可视化
"""

import json
import os
import re
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

RESULTS_DIR = "results"
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")

def parse_results_from_log(log_file):
    """从日志文件中解析结果 - 使用正则表达式"""
    results = {
        'hit_mean': 0,
        'hit_stddev': 0,
        'miss_mean': 0,
        'miss_stddev': 0,
        'threshold': 0,
        'cohens_d': 0,
        'accuracy': 0,
        'detected_fragments': 0,
        'attack_success': 0
    }
    
    try:
        with open(log_file, 'r') as f:
            content = f.read()
        
        # 解析Cache Hit - 格式: "Cache Hit  - Mean: 89.42, StdDev: 318.48, ..."
        hit_match = re.search(r'Cache Hit\s+- Mean:\s+([\d.]+),\s+StdDev:\s+([\d.]+)', content)
        if hit_match:
            results['hit_mean'] = float(hit_match.group(1))
            results['hit_stddev'] = float(hit_match.group(2))
        
        # 解析Cache Miss - 格式: "Cache Miss - Mean: 1031.26, StdDev: 57698.38, ..."
        miss_match = re.search(r'Cache Miss\s+- Mean:\s+([\d.]+),\s+StdDev:\s+([\d.]+)', content)
        if miss_match:
            results['miss_mean'] = float(miss_match.group(1))
            results['miss_stddev'] = float(miss_match.group(2))
        
        # 解析Cohen's d
        cohen_match = re.search(r"Cohen's d:\s+([\d.]+)", content)
        if cohen_match:
            results['cohens_d'] = float(cohen_match.group(1))
        
        # 解析Threshold
        threshold_match = re.search(r'Threshold:\s+(\d+)\s+cycles', content)
        if threshold_match:
            results['threshold'] = float(threshold_match.group(1))
        
        # 解析Classification Accuracy
        accuracy_match = re.search(r'Classification Accuracy:\s+([\d.]+)%', content)
        if accuracy_match:
            results['accuracy'] = float(accuracy_match.group(1))
        
        # 解析检测到的S-box数量
        detected_match = re.search(r'S-boxes detected:\s*(\d+)/8', content)
        if detected_match:
            results['detected_fragments'] = int(detected_match.group(1))
            results['attack_success'] = 1 if results['detected_fragments'] >= 6 else 0
                    
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
    
    return results

def main():
    print("="*70)
    print("Re-parsing Log Files and Generating Visualization")
    print("="*70)
    
    # 日志文件路径
    log_files = [
        ("Default (No CPU Binding)", "results/env_logs/env_0_Default_(No_CPU_Binding).log"),
        ("CPU Pinned (Core 0)", "results/env_logs/env_1_CPU_Pinned_(Core_0).log")
    ]
    
    # 解析所有日志
    all_results = []
    for name, log_file in log_files:
        print(f"\nParsing: {name}")
        print(f"File: {log_file}")
        
        if not os.path.exists(log_file):
            print(f"  ERROR: File not found!")
            continue
        
        results = parse_results_from_log(log_file)
        
        print(f"  Hit Mean: {results['hit_mean']:.2f}")
        print(f"  Hit StdDev: {results['hit_stddev']:.2f}")
        print(f"  Miss Mean: {results['miss_mean']:.2f}")
        print(f"  Miss StdDev: {results['miss_stddev']:.2f}")
        print(f"  Cohen's d: {results['cohens_d']:.4f}")
        print(f"  Accuracy: {results['accuracy']:.2f}%")
        print(f"  Detected: {results['detected_fragments']}/8")
        
        all_results.append((name, results))
    
    if len(all_results) != 2:
        print("\nERROR: Need exactly 2 results!")
        return 1
    
    # 保存JSON
    data = {
        'timestamp': datetime.now().isoformat(),
        'environments': []
    }
    
    for name, results in all_results:
        env_data = {
            'name': name,
            'hit_mean': results['hit_mean'],
            'hit_stddev': results['hit_stddev'],
            'miss_mean': results['miss_mean'],
            'miss_stddev': results['miss_stddev'],
            'threshold': results['threshold'],
            'cohens_d': results['cohens_d'],
            'accuracy': results['accuracy'],
            'detected_fragments': results['detected_fragments'],
            'attack_success': results['attack_success'],
            'attack_duration': 0  # 从日志中无法获取
        }
        data['environments'].append(env_data)
    
    json_file = os.path.join(RESULTS_DIR, 'environment_comparison.json')
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"\nSaved: {json_file}")
    
    # 生成可视化
    print("\nGenerating visualization...")
    os.makedirs(FIGURES_DIR, exist_ok=True)
    
    default = all_results[0][1]
    pinned = all_results[1][1]
    
    fig = plt.figure(figsize=(12, 10))
    fig.suptitle('CPU Binding Impact on Flush+Reload Attack', 
                 fontsize=16, fontweight='bold')
    
    from matplotlib.gridspec import GridSpec
    gs = GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)
    
    # 1. 时序对比
    ax1 = fig.add_subplot(gs[0, 0])
    categories = ['Hit Mean', 'Miss Mean']
    default_vals = [default['hit_mean'], default['miss_mean']]
    pinned_vals = [pinned['hit_mean'], pinned['miss_mean']]
    
    x = np.arange(len(categories))
    width = 0.35
    
    ax1.bar(x - width/2, default_vals, width, label='Default', color='lightcoral', alpha=0.8)
    ax1.bar(x + width/2, pinned_vals, width, label='CPU Pinned', color='lightgreen', alpha=0.8)
    ax1.set_ylabel('Cycles')
    ax1.set_title('Cache Timing Comparison')
    ax1.set_xticks(x)
    ax1.set_xticklabels(categories)
    ax1.legend()
    ax1.grid(axis='y', alpha=0.3)
    
    for i, (d, p) in enumerate(zip(default_vals, pinned_vals)):
        ax1.text(i - width/2, d, f'{d:.0f}', ha='center', va='bottom', fontsize=9)
        ax1.text(i + width/2, p, f'{p:.0f}', ha='center', va='bottom', fontsize=9)
    
    # 2. 标准差对比
    ax2 = fig.add_subplot(gs[0, 1])
    categories2 = ['Hit StdDev', 'Miss StdDev']
    default_std = [default['hit_stddev'], default['miss_stddev']]
    pinned_std = [pinned['hit_stddev'], pinned['miss_stddev']]
    
    x2 = np.arange(len(categories2))
    ax2.bar(x2 - width/2, default_std, width, label='Default', color='lightcoral', alpha=0.8)
    ax2.bar(x2 + width/2, pinned_std, width, label='CPU Pinned', color='lightgreen', alpha=0.8)
    ax2.set_ylabel('StdDev (cycles)')
    ax2.set_title('Timing Variability (Lower is Better)')
    ax2.set_xticks(x2)
    ax2.set_xticklabels(categories2)
    ax2.legend()
    ax2.grid(axis='y', alpha=0.3)
    
    # 3. 关键指标表格
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.axis('off')
    
    hit_improve = ((default['hit_mean'] - pinned['hit_mean']) / default['hit_mean']) * 100
    std_improve = ((default['hit_stddev'] - pinned['hit_stddev']) / (default['hit_stddev'] + 1)) * 100
    
    table_data = [
        ['Metric', 'Default', 'CPU Pinned', 'Change'],
        ['Hit Mean', f"{default['hit_mean']:.1f}", f"{pinned['hit_mean']:.1f}", f"{hit_improve:+.1f}%"],
        ['Hit StdDev', f"{default['hit_stddev']:.1f}", f"{pinned['hit_stddev']:.1f}", f"{std_improve:+.1f}%"],
        ['Cohen d', f"{default['cohens_d']:.4f}", f"{pinned['cohens_d']:.4f}", 
         f"{((pinned['cohens_d']-default['cohens_d'])/default['cohens_d']*100 if default['cohens_d'] != 0 else 0):+.1f}%"],
        ['Accuracy', f"{default['accuracy']:.1f}%", f"{pinned['accuracy']:.1f}%", 
         f"{pinned['accuracy']-default['accuracy']:+.1f}%"],
    ]
    
    table = ax3.table(cellText=table_data[1:], colLabels=table_data[0],
                     cellLoc='center', loc='center',
                     colWidths=[0.3, 0.25, 0.25, 0.2])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2)
    
    for i in range(len(table_data[0])):
        table[(0, i)].set_facecolor('#4CAF50')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    ax3.set_title('Performance Comparison', fontweight='bold', pad=20)
    
    # 4. 结论
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.axis('off')
    
    conclusion_text = "CONCLUSION\n" + "="*40 + "\n\n"
    
    if pinned['hit_stddev'] < default['hit_stddev']:
        improvement = (default['hit_stddev'] - pinned['hit_stddev']) / default['hit_stddev'] * 100
        conclusion_text += f"✓ CPU binding reduces\n  timing variability by {improvement:.1f}%\n\n"
    
    if pinned['cohens_d'] > default['cohens_d']:
        improvement = (pinned['cohens_d'] - default['cohens_d']) / default['cohens_d'] * 100
        conclusion_text += f"✓ Improves effect size by {improvement:.1f}%\n\n"
    
    if pinned['accuracy'] > default['accuracy']:
        conclusion_text += f"✓ Increases accuracy by {pinned['accuracy']-default['accuracy']:.1f}%\n\n"
    
    conclusion_text += "\nRECOMMENDATION\n" + "="*40 + "\n\n"
    conclusion_text += "Use CPU affinity:\n"
    conclusion_text += "  taskset -c 0 ./spy\n"
    conclusion_text += "    ./libdes.so"
    
    ax4.text(0.1, 0.5, conclusion_text, fontsize=11, family='monospace',
             verticalalignment='center',
             bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.3))
    
    dashboard_path = os.path.join(FIGURES_DIR, "environment_comparison_dashboard.png")
    plt.savefig(dashboard_path, dpi=150, bbox_inches='tight')
    print(f"Saved: {dashboard_path}")
    
    # 生成文本报告
    report_path = os.path.join(RESULTS_DIR, "environment_comparison_report.txt")
    with open(report_path, 'w') as f:
        f.write("="*70 + "\n")
        f.write("CPU Binding Impact Analysis Report\n")
        f.write("="*70 + "\n\n")
        
        f.write("[RESULTS]\n\n")
        f.write(f"{'Metric':<25} {'Default':>12} {'CPU Pinned':>12} {'Change':>12}\n")
        f.write("-"*70 + "\n")
        f.write(f"{'Hit Mean (cycles)':<25} {default['hit_mean']:>12.2f} {pinned['hit_mean']:>12.2f} {hit_improve:>+11.1f}%\n")
        f.write(f"{'Hit StdDev (cycles)':<25} {default['hit_stddev']:>12.2f} {pinned['hit_stddev']:>12.2f} {std_improve:>+11.1f}%\n")
        f.write(f"{'Cohen d':<25} {default['cohens_d']:>12.4f} {pinned['cohens_d']:>12.4f} "
                f"{((pinned['cohens_d']-default['cohens_d'])/default['cohens_d']*100 if default['cohens_d'] != 0 else 0):>+11.1f}%\n")
        f.write(f"{'Accuracy (%)':<25} {default['accuracy']:>12.2f} {pinned['accuracy']:>12.2f} {pinned['accuracy']-default['accuracy']:>+11.1f}%\n")
        f.write(f"{'Detected Fragments':<25} {default['detected_fragments']:>12} {pinned['detected_fragments']:>12} "
                f"{pinned['detected_fragments']-default['detected_fragments']:>+11}\n")
        
        f.write("\n" + "="*70 + "\n")
    
    print(f"Saved: {report_path}")
    
    print("\n" + "="*70)
    print("Complete!")
    print("="*70)
    
    return 0

if __name__ == "__main__":
    exit(main())
