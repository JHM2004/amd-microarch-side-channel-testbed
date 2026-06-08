#!/usr/bin/env python3
"""
visualize_environment_comparison.py
环境控制对比实验可视化 - 简化版（仅对比默认 vs CPU绑定）
"""

import json
import os
import sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

RESULTS_DIR = "results"
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")

def load_results(filepath):
    """加载实验结果"""
    with open(filepath, 'r') as f:
        return json.load(f)

def create_comparison_dashboard(data, output_path):
    """创建环境控制对比仪表板 - 简化版（2x2布局）"""
    envs = data['environments']
    
    if len(envs) != 2:
        print(f"Warning: Expected 2 environments, got {len(envs)}")
    
    default = envs[0]
    pinned = envs[1]
    
    fig = plt.figure(figsize=(12, 10))
    fig.suptitle('CPU Binding Impact on Flush+Reload Attack', 
                 fontsize=16, fontweight='bold')
    
    # 使用2x2布局
    from matplotlib.gridspec import GridSpec
    gs = GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)
    
    # 1. 时序对比 - Hit/Miss Mean
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
    
    # 添加数值标签
    for i, (d, p) in enumerate(zip(default_vals, pinned_vals)):
        ax1.text(i - width/2, d, f'{d:.0f}', ha='center', va='bottom', fontsize=9)
        ax1.text(i + width/2, p, f'{p:.0f}', ha='center', va='bottom', fontsize=9)
    
    # 2. 标准差对比（噪声水平）
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
    
    # 3. 关键指标对比表格
    ax3 = fig.add_subplot(gs[1, 0])
    ax3.axis('off')
    
    # 计算改进百分比
    hit_improve = ((default['hit_mean'] - pinned['hit_mean']) / default['hit_mean']) * 100
    std_improve = ((default['hit_stddev'] - pinned['hit_stddev']) / (default['hit_stddev'] + 1)) * 100
    duration_improve = ((default['attack_duration'] - pinned['attack_duration']) / default['attack_duration']) * 100
    
    table_data = [
        ['Metric', 'Default', 'CPU Pinned'],
        ['Hit Mean (cycles)', f"{default['hit_mean']:.1f}", f"{pinned['hit_mean']:.1f}"],
        ['Hit StdDev (cycles)', f"{default['hit_stddev']:.1f}", f"{pinned['hit_stddev']:.1f}"],
        ['Cohen\'s d', f"{default['cohens_d']:.4f}", f"{pinned['cohens_d']:.4f}"],
        ['Recovery Rate', f"{default.get('recovery_rate', 0):.1f}%", f"{pinned.get('recovery_rate', 0):.1f}%"],
        ['SNR (dB)', f"{default.get('snr', 0):.1f}", f"{pinned.get('snr', 0):.1f}"],
    ]
    
    table = ax3.table(cellText=table_data[1:], colLabels=table_data[0],
                     cellLoc='center', loc='center',
                     colWidths=[0.4, 0.3, 0.3])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2)
    
    # 高亮表头
    for i in range(len(table_data[0])):
        table[(0, i)].set_facecolor('#4CAF50')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    ax3.set_title('Performance Comparison', fontweight='bold', pad=20)
    
    # 4. 结论和建议
    ax4 = fig.add_subplot(gs[1, 1])
    ax4.axis('off')
    
    conclusion_text = "CONCLUSION\n" + "="*40 + "\n\n"
    
    if duration_improve > 0:
        conclusion_text += f"✓ CPU binding reduces\n  attack time by {duration_improve:.1f}%\n\n"
    
    if std_improve > 0:
        conclusion_text += f"✓ Reduces timing variability\n  (noise reduction)\n\n"
    
    if hit_improve > 0:
        conclusion_text += f"✓ Improves timing stability\n  ({hit_improve:.1f}% lower hit time)\n\n"
    
    conclusion_text += "RECOMMENDATION\n" + "="*40 + "\n\n"
    conclusion_text += "For consistent results:\n"
    conclusion_text += "  taskset -c 0 ./spy\n"
    conclusion_text += "    ./libdes.so"
    
    ax4.text(0.1, 0.5, conclusion_text, fontsize=11, family='monospace',
             verticalalignment='center',
             bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.3))
    
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Saved environment comparison dashboard: {output_path}")
    plt.close()

def create_summary_report(data, output_path):
    """生成文本摘要报告"""
    envs = data['environments']
    
    if len(envs) != 2:
        print(f"Warning: Expected 2 environments, got {len(envs)}")
        return
    
    default = envs[0]
    pinned = envs[1]
    
    # 计算改进
    hit_improve = ((default['hit_mean'] - pinned['hit_mean']) / default['hit_mean']) * 100
    std_improve = ((default['hit_stddev'] - pinned['hit_stddev']) / (default['hit_stddev'] + 1)) * 100
    duration_improve = ((default['attack_duration'] - pinned['attack_duration']) / default['attack_duration']) * 100
    
    with open(output_path, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("CPU Binding Impact Analysis Report\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("[SUMMARY]\n")
        f.write("Comparison of Flush+Reload attack performance with and without\n")
        f.write("CPU affinity binding.\n\n")
        
        f.write("[RESULTS]\n\n")
        f.write(f"{'Metric':<25} {'Default':>15} {'CPU Pinned':>15}\n")
        f.write("-" * 60 + "\n")
        f.write(f"{'Hit Mean (cycles)':<25} {default['hit_mean']:>15.2f} {pinned['hit_mean']:>15.2f}\n")
        f.write(f"{'Hit StdDev (cycles)':<25} {default['hit_stddev']:>15.2f} {pinned['hit_stddev']:>15.2f}\n")
        f.write(f"{'Cohen d':<25} {default['cohens_d']:>15.4f} {pinned['cohens_d']:>15.4f}\n")
        f.write(f"{'Recovery Rate':<25} {default.get('recovery_rate', 0):>14.1f}% {pinned.get('recovery_rate', 0):>14.1f}%\n")
        f.write(f"{'SNR (dB)':<25} {default.get('snr', 0):>15.1f} {pinned.get('snr', 0):>15.1f}\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("[CONCLUSION]\n\n")
        
        if duration_improve > 0:
            f.write(f"✓ CPU binding reduces attack time by {duration_improve:.1f}%\n")
        if std_improve > 0:
            f.write(f"✓ CPU binding reduces timing variability\n")
        if hit_improve > 0:
            f.write(f"✓ CPU binding improves timing stability\n")
        
        f.write("\n" + "=" * 70 + "\n")
        f.write("[RECOMMENDATION]\n\n")
        f.write("For production testing, use CPU affinity binding:\n\n")
        f.write("  taskset -c 0 ./build/spy ./build/libdes.so\n\n")
        f.write("This ensures:\n")
        f.write("  - Consistent CPU cache behavior\n")
        f.write("  - Reduced scheduling noise\n")
        f.write("  - More reproducible results\n\n")
        
        f.write("=" * 70 + "\n")
    
    print(f"Saved summary report: {output_path}")

def main():
    print("=" * 70)
    print("Environment Control Comparison Visualization")
    print("=" * 70)
    
    # 确保输出目录存在
    os.makedirs(FIGURES_DIR, exist_ok=True)
    
    # 加载数据
    data_file = os.path.join(RESULTS_DIR, "environment_comparison.json")
    if not os.path.exists(data_file):
        print(f"\nError: Data file not found: {data_file}")
        print("Please run the environment control test first.")
        return 1
    
    print(f"\nLoading data from: {data_file}")
    data = load_results(data_file)
    
    print("\nGenerating visualizations...")
    
    # 生成仪表板
    dashboard_path = os.path.join(FIGURES_DIR, "environment_comparison_dashboard.png")
    create_comparison_dashboard(data, dashboard_path)
    
    # 生成摘要报告
    report_path = os.path.join(RESULTS_DIR, "environment_comparison_report.txt")
    create_summary_report(data, report_path)
    
    print("\n" + "=" * 70)
    print("Visualization Complete!")
    print("=" * 70)
    print(f"\nOutput files:")
    print(f"  Dashboard: {dashboard_path}")
    print(f"  Report:    {report_path}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
