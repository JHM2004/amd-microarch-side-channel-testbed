#!/usr/bin/env python3
"""
quantify_analysis.py
DES Flush+Reload Attack - 量化指标分析与可视化

功能：
- 读取攻击指标JSON数据
- 生成泄露带宽、信噪比图表
- 输出统计摘要
"""

import json
import os
import sys
import glob
import subprocess

# 检查依赖
def check_dependencies():
    required = [
        ('numpy', 'numpy>=1.19.0'),
        ('matplotlib', 'matplotlib>=3.3.0'),
    ]
    missing = []
    for mod, pkg in required:
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if missing:
        print("=" * 60)
        print("错误：缺少必要的Python库")
        print("=" * 60)
        print("\n缺失的库：")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\n请运行：pip3 install -r requirements.txt")
        print("=" * 60)
        sys.exit(1)

check_dependencies()

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

# 配置
RESULTS_DIR = "results"
METRICS_DIR = os.path.join(RESULTS_DIR, "metrics")
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")

def ensure_directories():
    """确保输出目录存在"""
    for d in [METRICS_DIR, FIGURES_DIR]:
        os.makedirs(d, exist_ok=True)

def load_metrics(filepath):
    """加载指标JSON文件"""
    with open(filepath, 'r') as f:
        return json.load(f)

def create_metrics_dashboard(metrics, output_path):
    """创建量化指标仪表板"""
    fig = plt.figure(figsize=(12, 8))
    fig.suptitle('DES Flush+Reload Attack Quantitative Metrics', fontsize=16, fontweight='bold')
    
    # 使用2x2布局
    from matplotlib.gridspec import GridSpec
    gs = GridSpec(2, 2, figure=fig, hspace=0.3, wspace=0.3)
    
    # 1. 泄露带宽 (左上) - 只显示 bandwidth 和 bits_per_attack
    ax1 = fig.add_subplot(gs[0, 0])
    bandwidth = metrics.get('leakage_bandwidth', 0)
    bits_per_attack = metrics.get('bits_per_attack', 0)
    
    categories = ['Bandwidth\n(bits/s)', 'Bits per\nAttack']
    values = [bandwidth, bits_per_attack]
    colors = ['#2ecc71', '#3498db']
    
    bars = ax1.bar(categories, values, color=colors, alpha=0.7, edgecolor='black')
    ax1.set_title('Leakage Bandwidth Analysis', fontweight='bold')
    ax1.set_ylabel('Value')
    
    # 在柱子上添加数值标签
    for bar, val in zip(bars, values):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{val:.2f}', ha='center', va='bottom', fontsize=10)
    
    # 2. 信噪比 (右上)
    ax2 = fig.add_subplot(gs[0, 1])
    snr_db = metrics.get('snr_db', 0)
    signal_mean = metrics.get('signal_mean', 0)
    noise_mean = metrics.get('noise_mean', 0)
    
    # SNR仪表盘
    theta = np.linspace(0, np.pi, 100)
    r = 1.0
    ax2.plot(r * np.cos(theta), r * np.sin(theta), 'k-', linewidth=2)
    
    # 指针
    snr_normalized = min(max(snr_db / 30, 0), 1)  # 假设30dB为最大值
    needle_angle = np.pi * (1 - snr_normalized)
    ax2.plot([0, 0.8 * np.cos(needle_angle)], [0, 0.8 * np.sin(needle_angle)], 
             'r-', linewidth=3)
    ax2.plot(0, 0, 'ko', markersize=10)
    
    ax2.set_xlim(-1.2, 1.2)
    ax2.set_ylim(-0.2, 1.2)
    ax2.set_aspect('equal')
    ax2.axis('off')
    ax2.set_title(f'SNR: {snr_db:.2f} dB', fontweight='bold')
    
    # 添加刻度标签
    ax2.text(-0.9, -0.1, '0dB', fontsize=8)
    ax2.text(0, -0.15, '15dB', fontsize=8, ha='center')
    ax2.text(0.9, -0.1, '30dB', fontsize=8, ha='right')
    
    # 3. Signal vs Noise 对比 (左下) - 分组柱状图
    ax3 = fig.add_subplot(gs[1, 0])
    
    categories = ['Mean\n(cycles)', 'Std\n(cycles)']
    signal_values = [signal_mean, metrics.get('signal_std', 0)]
    noise_values = [noise_mean, metrics.get('noise_std', 0)]
    
    x = np.arange(len(categories))
    width = 0.35
    
    bars1 = ax3.bar(x - width/2, signal_values, width, label='Signal (Hit)', 
                    color='#2ecc71', alpha=0.8, edgecolor='black')
    bars2 = ax3.bar(x + width/2, noise_values, width, label='Noise (Miss)', 
                    color='#e74c3c', alpha=0.8, edgecolor='black')
    
    ax3.set_ylabel('Cycles')
    ax3.set_title('Signal vs Noise Characteristics', fontweight='bold')
    ax3.set_xticks(x)
    ax3.set_xticklabels(categories)
    ax3.legend()
    ax3.grid(axis='y', alpha=0.3)
    
    # 添加数值标签
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax3.text(bar.get_x() + bar.get_width()/2., height,
                    f'{height:.0f}', ha='center', va='bottom', fontsize=9)
    
    # 4. Recovery Rate 环形图 (右下)
    ax4 = fig.add_subplot(gs[1, 1])
    
    recovery_rate = metrics.get('recovery_rate', 0)
    recovered = metrics.get('recovered_fragments', 0)
    total = metrics.get('total_fragments', 8)
    
    # 创建环形图
    sizes = [recovery_rate, 1 - recovery_rate]
    colors_ring = ['#3498db', '#ecf0f1']
    explode = (0.05, 0)  # 突出显示成功部分
    
    wedges, texts, autotexts = ax4.pie(sizes, colors=colors_ring, 
                                        autopct='%1.1f%%',
                                        startangle=90,
                                        explode=explode,
                                        wedgeprops=dict(width=0.5, edgecolor='black'))
    
    # 设置字体大小
    for autotext in autotexts:
        autotext.set_fontsize(14)
        autotext.set_fontweight('bold')
    
    # 添加中心文字
    ax4.text(0, 0, f'{recovered}/{total}', ha='center', va='center', 
             fontsize=16, fontweight='bold')
    
    ax4.set_title(f'Key Recovery Rate\n({recovered} of {total} fragments)', 
                  fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"Saved metrics dashboard: {output_path}")
    plt.close()

def generate_summary_report(metrics, output_path):
    """生成文本摘要报告"""
    with open(output_path, 'w') as f:
        f.write("=" * 70 + "\n")
        f.write("DES Flush+Reload Attack Quantitative Analysis Report\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("[LEAKAGE BANDWIDTH]\n")
        f.write(f"  Bandwidth:        {metrics.get('leakage_bandwidth', 0):.2f} bits/second\n")
        f.write(f"  Bits per attack:  {metrics.get('bits_per_attack', 0):.1f} bits\n\n")
        
        f.write("[SIGNAL-TO-NOISE RATIO]\n")
        f.write(f"  SNR:              {metrics.get('snr_db', 0):.2f} dB\n")
        f.write(f"  Signal mean:      {metrics.get('signal_mean', 0):.2f} cycles\n")
        f.write(f"  Noise mean:       {metrics.get('noise_mean', 0):.2f} cycles\n")
        f.write(f"  Signal std:       {metrics.get('signal_std', 0):.2f} cycles\n")
        f.write(f"  Noise std:        {metrics.get('noise_std', 0):.2f} cycles\n\n")
        
        f.write("[TIMING STATISTICS]\n")
        f.write(f"  Hit time range:   {metrics.get('min_hit_time', 0)} - {metrics.get('max_hit_time', 0)} cycles\n")
        f.write(f"  Miss time range:  {metrics.get('min_miss_time', 0)} - {metrics.get('max_miss_time', 0)} cycles\n")
        f.write(f"  Threshold:        {metrics.get('threshold', 0)} cycles\n\n")
        
        f.write("[RECOVERY STATUS]\n")
        recovered = metrics.get('recovered_fragments', 0)
        total = metrics.get('total_fragments', 8)
        rate = metrics.get('recovery_rate', 0) * 100
        f.write(f"  Fragments:        {recovered}/{total}\n")
        f.write(f"  Recovery rate:    {rate:.2f}%\n\n")
        
        f.write("=" * 70 + "\n")
    
    print(f"Saved summary report: {output_path}")

def main():
    print("=" * 70)
    print("DES Flush+Reload Attack Quantitative Analysis")
    print("=" * 70)
    
    ensure_directories()
    
    # 查找指标文件
    metrics_file = os.path.join(METRICS_DIR, "attack_metrics.json")
    
    if not os.path.exists(metrics_file):
        print(f"\nError: Metrics file not found: {metrics_file}")
        print("Please run the attack first to generate metrics.")
        return 1
    
    print(f"\nLoading metrics from: {metrics_file}")
    metrics = load_metrics(metrics_file)
    
    print("\nGenerating visualizations...")
    
    # 生成仪表板
    dashboard_path = os.path.join(FIGURES_DIR, "quantitative_metrics.png")
    create_metrics_dashboard(metrics, dashboard_path)
    
    # 生成摘要报告
    report_path = os.path.join(RESULTS_DIR, "quantitative_report.txt")
    generate_summary_report(metrics, report_path)
    
    print("\n" + "=" * 70)
    print("Analysis Complete!")
    print("=" * 70)
    print(f"\nOutput files:")
    print(f"  Dashboard: {dashboard_path}")
    print(f"  Report:    {report_path}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
