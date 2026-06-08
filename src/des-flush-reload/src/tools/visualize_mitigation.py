#!/usr/bin/env python3
"""
visualize_mitigation.py
DES Flush+Reload Attack - 缓解措施对比可视化

功能：
- 读取mitigation_report.txt中的测试数据
- 为每个缓解措施生成与基准（无缓解）的对比图表
- 生成多种类型的可视化
"""

import json
import os
import sys
import re

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
MITIGATION_FIGURES_DIR = os.path.join(RESULTS_DIR, "figures", "mitigation")
REPORT_FILE = os.path.join(RESULTS_DIR, "mitigation_report.txt")

def ensure_directories():
    """确保输出目录存在"""
    os.makedirs(MITIGATION_FIGURES_DIR, exist_ok=True)

def parse_mitigation_report(filename):
    """
    解析缓解措施测试报告文件
    返回：[(name, baseline_dict, mitigation_dict), ...]
    """
    results = []
    
    with open(filename, 'r') as f:
        content = f.read()
    
    # 解析基准数据
    baseline_match = re.search(
        r'BASELINE \(No Mitigation\).*?Success Rate:\s*(\d+\.?\d*)%.*?Avg Duration:\s*(\d+\.?\d*)',
        content, re.DOTALL
    )
    
    if baseline_match:
        baseline_success = float(baseline_match.group(1))
        baseline_duration = float(baseline_match.group(2))
    else:
        print("[警告] 无法解析基准数据，使用默认值")
        baseline_success = 60.0
        baseline_duration = 5000.0
    
    baseline = {
        'success_rate': baseline_success,
        'duration': baseline_duration,
        'effectiveness': 0.0,
        'overhead': 0.0
    }
    
    # 添加基准到结果列表
    results.append(("Baseline (None)", baseline, baseline))
    
    # 解析各缓解措施数据
    mitigation_patterns = [
        ("CPU Pinning", r'CPU Pinning:.*?Success Rate:\s*(\d+\.?\d*)%.*?Effectiveness:\s*(-?\d+\.?\d*)%.*?Overhead:\s*(-?\d+\.?\d*)%.*?Avg Duration:\s*(\d+\.?\d*)', re.DOTALL),
        ("Cache Flush", r'Cache Flush:.*?Success Rate:\s*(\d+\.?\d*)%.*?Effectiveness:\s*(-?\d+\.?\d*)%.*?Overhead:\s*(-?\d+\.?\d*)%.*?Avg Duration:\s*(\d+\.?\d*)', re.DOTALL),
        ("Noise Injection", r'Noise Injection:.*?Success Rate:\s*(\d+\.?\d*)%.*?Effectiveness:\s*(-?\d+\.?\d*)%.*?Overhead:\s*(-?\d+\.?\d*)%.*?Avg Duration:\s*(\d+\.?\d*)', re.DOTALL),
        ("Access Obfuscation", r'Access Obfuscation:.*?Success Rate:\s*(\d+\.?\d*)%.*?Effectiveness:\s*(-?\d+\.?\d*)%.*?Overhead:\s*(-?\d+\.?\d*)%.*?Avg Duration:\s*(\d+\.?\d*)', re.DOTALL),
        ("Process Isolation", r'Process Isolation:.*?Success Rate:\s*(\d+\.?\d*)%.*?Effectiveness:\s*(-?\d+\.?\d*)%.*?Overhead:\s*(-?\d+\.?\d*)%.*?Avg Duration:\s*(\d+\.?\d*)', re.DOTALL),
        ("Core Isolation", r'Core Isolation:.*?Success Rate:\s*(\d+\.?\d*)%.*?Effectiveness:\s*(-?\d+\.?\d*)%.*?Overhead:\s*(-?\d+\.?\d*)%.*?Avg Duration:\s*(\d+\.?\d*)', re.DOTALL),
        ("Disable Hyperthreading", r'Disable Hyperthreading:.*?Success Rate:\s*(\d+\.?\d*)%.*?Effectiveness:\s*(-?\d+\.?\d*)%.*?Overhead:\s*(-?\d+\.?\d*)%.*?Avg Duration:\s*(\d+\.?\d*)', re.DOTALL),
    ]
    
    for name, pattern, flags in mitigation_patterns:
        match = re.search(pattern, content, flags)
        if match:
            mitigation = {
                'success_rate': float(match.group(1)),
                'effectiveness': float(match.group(2)),
                'overhead': float(match.group(3)),
                'duration': float(match.group(4))
            }
            results.append((name, baseline.copy(), mitigation))
        else:
            print(f"[警告] 无法解析 {name} 的数据")
    
    return results

def create_comparison_bar_chart(mitigation_name, baseline, mitigation, output_path):
    """
    创建攻击成功率和性能开销的对比柱状图
    """
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    fig.suptitle(f'Mitigation Effectiveness: {mitigation_name}', fontsize=16, fontweight='bold')
    
    # 数据准备
    categories = ['No Mitigation\n(Baseline)', f'With\n{mitigation_name}']
    success_rates = [baseline['success_rate'], mitigation['success_rate']]
    durations = [baseline['duration'], mitigation['duration']]
    
    # 颜色
    colors_success = ['#e74c3c', '#27ae60']
    colors_duration = ['#3498db', '#f39c12']
    
    # 图1: 攻击成功率对比
    bars1 = ax1.bar(categories, success_rates, color=colors_success, alpha=0.8, edgecolor='black', linewidth=2)
    ax1.set_ylabel('Attack Success Rate (%)', fontsize=12)
    ax1.set_title('Attack Success Rate Comparison', fontsize=14, fontweight='bold')
    ax1.set_ylim(0, 110)
    ax1.grid(axis='y', alpha=0.3)
    
    # 添加数值标签
    for bar, val in zip(bars1, success_rates):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 2,
                f'{val:.1f}%', ha='center', va='bottom', fontsize=14, fontweight='bold')
    
    # 添加效果评估
    effectiveness = mitigation['effectiveness']
    if effectiveness > 50:
        assessment = 'Effective'
        box_color = '#d5f4e6'
    elif effectiveness > 20:
        assessment = 'Partial'
        box_color = '#fef9e7'
    else:
        assessment = 'Ineffective'
        box_color = '#fadbd8'
    
    ax1.text(0.5, 50, f'Effectiveness:\n{effectiveness:.1f}%\n{assessment}',
             ha='center', va='center', fontsize=12, fontweight='bold',
             bbox=dict(boxstyle='round', facecolor=box_color, alpha=0.8))
    
    # 图2: 性能开销对比
    bars2 = ax2.bar(categories, durations, color=colors_duration, alpha=0.8, edgecolor='black', linewidth=2)
    ax2.set_ylabel('Attack Duration (ms)', fontsize=12)
    ax2.set_title('Performance Impact Comparison', fontsize=14, fontweight='bold')
    ax2.grid(axis='y', alpha=0.3)
    
    # 添加数值标签
    for bar, val in zip(bars2, durations):
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.02,
                f'{val:.1f}ms', ha='center', va='bottom', fontsize=12, fontweight='bold')
    
    # 添加开销百分比
    overhead = mitigation['overhead']
    overhead_text = f'Overhead: {overhead:+.1f}%'
    ax2.text(0.5, max(durations) * 0.5, overhead_text,
             ha='center', va='center', fontsize=12, fontweight='bold',
             bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"[保存] {output_path}")
    plt.close()

def create_radar_chart(all_results, output_path):
    """创建所有缓解措施的雷达图对比"""
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection='polar'))
    
    # 准备数据
    mitigation_names = []
    effectiveness_values = []
    
    for i, (name, baseline, mitigation) in enumerate(all_results):
        if i == 0:  # 跳过基准
            continue
        mitigation_names.append(name.replace(' ', '\n'))
        effectiveness_values.append(mitigation['effectiveness'])
    
    # 雷达图参数
    num_vars = len(mitigation_names)
    angles = np.linspace(0, 2 * np.pi, num_vars, endpoint=False).tolist()
    effectiveness_values += effectiveness_values[:1]
    angles += angles[:1]
    
    # 绘制雷达图
    ax.plot(angles, effectiveness_values, 'o-', linewidth=2, color='#e74c3c', label='Effectiveness')
    ax.fill(angles, effectiveness_values, alpha=0.25, color='#e74c3c')
    
    # 设置标签
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(mitigation_names, fontsize=10)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(['20%', '40%', '60%', '80%', '100%'], fontsize=8)
    ax.grid(True)
    
    plt.title('Mitigation Effectiveness Comparison\n(Higher is better)', 
              fontsize=16, fontweight='bold', pad=20)
    plt.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"[保存] {output_path}")
    plt.close()

def create_summary_dashboard(all_results, output_path):
    """创建综合对比仪表板"""
    fig = plt.figure(figsize=(16, 10))
    fig.suptitle('DES Flush+Reload Attack Mitigation Comparison Dashboard', 
                 fontsize=18, fontweight='bold')
    
    # 提取数据
    names = []
    success_rates = []
    durations = []
    effectiveness = []
    overheads = []
    
    for name, baseline, mitigation in all_results:
        names.append(name)
        success_rates.append(mitigation['success_rate'])
        durations.append(mitigation['duration'])
        effectiveness.append(mitigation['effectiveness'])
        overheads.append(mitigation['overhead'])
    
    # 使用GridSpec创建复杂布局
    from matplotlib.gridspec import GridSpec
    gs = GridSpec(2, 3, figure=fig, hspace=0.3, wspace=0.3)
    
    # 图1: 攻击成功率对比
    ax1 = fig.add_subplot(gs[0, 0])
    colors = ['#e74c3c' if i == 0 else '#3498db' for i in range(len(names))]
    bars1 = ax1.barh(names, success_rates, color=colors, alpha=0.8, edgecolor='black')
    ax1.set_xlabel('Success Rate (%)', fontsize=11)
    ax1.set_title('Attack Success Rate', fontsize=12, fontweight='bold')
    ax1.set_xlim(0, 110)
    for bar, val in zip(bars1, success_rates):
        width = bar.get_width()
        ax1.text(width + 2, bar.get_y() + bar.get_height()/2.,
                f'{val:.1f}%', ha='left', va='center', fontsize=9)
    
    # 图2: 缓解效果对比
    ax2 = fig.add_subplot(gs[0, 1])
    colors2 = ['gray' if e == 0 else '#27ae60' if e > 50 else '#f39c12' if e > 20 else '#e74c3c' 
               for e in effectiveness]
    bars2 = ax2.barh(names, effectiveness, color=colors2, alpha=0.8, edgecolor='black')
    ax2.set_xlabel('Effectiveness (%)', fontsize=11)
    ax2.set_title('Mitigation Effectiveness\n(Attack Reduction)', fontsize=12, fontweight='bold')
    ax2.set_xlim(0, 110)
    for bar, val in zip(bars2, effectiveness):
        width = bar.get_width()
        ax2.text(width + 2, bar.get_y() + bar.get_height()/2.,
                f'{val:.1f}%', ha='left', va='center', fontsize=9)
    
    # 图3: 性能开销对比
    ax3 = fig.add_subplot(gs[0, 2])
    colors3 = ['#3498db' if o < 0 else '#e74c3c' for o in overheads]
    bars3 = ax3.barh(names, overheads, color=colors3, alpha=0.8, edgecolor='black')
    ax3.set_xlabel('Overhead (%)', fontsize=11)
    ax3.set_title('Performance Overhead\n(Negative = Faster)', fontsize=12, fontweight='bold')
    ax3.axvline(x=0, color='black', linestyle='-', linewidth=0.5)
    for bar, val in zip(bars3, overheads):
        width = bar.get_width()
        ax3.text(width + (3 if width >= 0 else -3), bar.get_y() + bar.get_height()/2.,
                f'{val:+.1f}%', ha='left' if width >= 0 else 'right', va='center', fontsize=9)
    
    # 图4: 攻击耗时对比
    ax4 = fig.add_subplot(gs[1, 0])
    bars4 = ax4.bar(range(len(names)), durations, color='#9b59b6', alpha=0.8, edgecolor='black')
    ax4.set_xticks(range(len(names)))
    ax4.set_xticklabels([n.replace(' ', '\n') for n in names], fontsize=8, rotation=0)
    ax4.set_ylabel('Duration (ms)', fontsize=11)
    ax4.set_title('Attack Duration', fontsize=12, fontweight='bold')
    ax4.grid(axis='y', alpha=0.3)
    for bar, val in zip(bars4, durations):
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                f'{val:.0f}', ha='center', va='bottom', fontsize=8)
    
    # 图5: 效果评估矩阵
    ax5 = fig.add_subplot(gs[1, 1:])
    ax5.axis('off')
    
    # 创建评估表格
    table_data = []
    for i, (name, sr, eff, oh) in enumerate(zip(names, success_rates, effectiveness, overheads)):
        if eff > 50:
            assess = 'Effective'
        elif eff > 20:
            assess = 'Partial'
        elif eff == 0 and i > 0:
            assess = 'Ineffective'
        else:
            assess = '-'
        table_data.append([name, f'{sr:.1f}%', f'{eff:.1f}%', f'{oh:+.1f}%', assess])
    
    table = ax5.table(cellText=table_data,
                     colLabels=['Mitigation', 'Success Rate', 'Effectiveness', 'Overhead', 'Assessment'],
                     cellLoc='center',
                     loc='center',
                     colWidths=[0.25, 0.15, 0.15, 0.15, 0.2])
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 2)
    
    # 设置表头样式
    for i in range(5):
        table[(0, i)].set_facecolor('#34495e')
        table[(0, i)].set_text_props(weight='bold', color='white')
    
    # 设置行颜色
    for i in range(1, len(table_data) + 1):
        for j in range(5):
            if i == 1:
                table[(i, j)].set_facecolor('#ecf0f1')
            elif table_data[i-1][4] == 'Effective':
                table[(i, j)].set_facecolor('#d5f4e6')
            elif table_data[i-1][4] == 'Partial':
                table[(i, j)].set_facecolor('#fef9e7')
            elif table_data[i-1][4] == 'Ineffective':
                table[(i, j)].set_facecolor('#fadbd8')
    
    ax5.set_title('Mitigation Assessment Summary', fontsize=14, fontweight='bold', pad=20)
    
    plt.savefig(output_path, dpi=150, bbox_inches='tight')
    print(f"[保存] {output_path}")
    plt.close()

def main():
    print("=" * 70)
    print("DES Flush+Reload Attack Mitigation Visualization")
    print("=" * 70)
    
    ensure_directories()
    
    # 检查报告文件是否存在
    if not os.path.exists(REPORT_FILE):
        print(f"[错误] 报告文件不存在: {REPORT_FILE}")
        print("请先运行测试: sudo ./build/test_mitigation -a -i 5")
        return 1
    
    # 解析报告文件
    print(f"\n[读取] 解析报告文件: {REPORT_FILE}")
    all_results = parse_mitigation_report(REPORT_FILE)
    
    if len(all_results) < 2:
        print("[错误] 报告文件解析失败或数据不足")
        return 1
    
    print(f"[成功] 解析了 {len(all_results)} 个缓解措施的数据")
    
    # 生成单个对比图
    mitigation_names = [
        "Baseline (None)",
        "CPU Pinning",
        "Cache Flush", 
        "Noise Injection",
        "Access Obfuscation",
        "Process Isolation",
        "Core Isolation",
        "Disable Hyperthreading"
    ]
    
    for i, (name, baseline, mitigation) in enumerate(all_results):
        if i == 0:  # 跳过基准
            continue
        
        output_file = os.path.join(MITIGATION_FIGURES_DIR, 
                                   f"mitigation_{i:02d}_{name.lower().replace(' ', '_')}_comparison.png")
        create_comparison_bar_chart(name, baseline, mitigation, output_file)
    
    # 生成雷达图
    print("\n[生成] 缓解措施效果雷达图...")
    radar_file = os.path.join(MITIGATION_FIGURES_DIR, "mitigation_effectiveness_radar.png")
    create_radar_chart(all_results, radar_file)
    
    # 生成综合仪表板
    print("[生成] 综合对比仪表板...")
    dashboard_file = os.path.join(MITIGATION_FIGURES_DIR, "mitigation_comparison_dashboard.png")
    create_summary_dashboard(all_results, dashboard_file)
    
    print("\n" + "=" * 70)
    print("可视化完成！")
    print("=" * 70)
    print(f"\n生成的文件:")
    print(f"  单个对比图: {MITIGATION_FIGURES_DIR}/mitigation_XX_*_comparison.png")
    print(f"  雷达图: {radar_file}")
    print(f"  综合仪表板: {dashboard_file}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
