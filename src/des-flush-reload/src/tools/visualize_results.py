#!/usr/bin/env python3
"""
DES Flush+Reload Attack Results Visualization Script
用于可视化缓存侧信道攻击的时间测量统计结果

功能说明：
- 从JSON和CSV文件加载统计结果
- 生成时间分布可视化图表（直方图、箱线图、Q-Q图）
- 生成攻击结果可视化图表（检测率、热力图、趋势图）
- 输出文本摘要报告

依赖库：
- numpy: 数值计算
- matplotlib: 绘图
- pandas: 数据处理
- seaborn: 高级可视化

安装依赖：
    pip3 install -r requirements.txt
"""

import json
import os
import sys
import glob
import subprocess

# 检查并安装依赖
def check_and_install_dependencies():
    """检查必要的Python库，如果缺失则提示安装"""
    required_packages = [
        ('numpy', 'numpy>=1.19.0'),
        ('matplotlib', 'matplotlib>=3.3.0'),
        ('pandas', 'pandas>=1.1.0'),
        ('seaborn', 'seaborn>=0.11.0')
    ]
    
    missing_packages = []
    
    for module_name, package_name in required_packages:
        try:
            __import__(module_name)
        except ImportError:
            missing_packages.append(package_name)
    
    if missing_packages:
        print("=" * 60)
        print("错误：缺少必要的Python库")
        print("=" * 60)
        print("\n缺失的库：")
        for pkg in missing_packages:
            print(f"  - {pkg}")
        print("\n请运行以下命令安装依赖：")
        print("  pip3 install -r requirements.txt")
        print("\n或直接安装：")
        print(f"  pip3 install {' '.join(missing_packages)}")
        print("=" * 60)
        sys.exit(1)

# 运行依赖检查
check_and_install_dependencies()

# 设置无头模式（在没有显示器的环境下运行）
import matplotlib
matplotlib.use('Agg')  # 使用非交互式后端

import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import pandas as pd
from datetime import datetime

# 设置中文字体支持，防止中文显示为方块
plt.rcParams['font.sans-serif'] = ['DejaVu Sans', 'SimHei', 'Arial Unicode MS']
plt.rcParams['axes.unicode_minus'] = False

# 结果目录配置
RESULTS_DIR = "results"  # 主结果目录
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")  # 图表输出子目录

def ensure_directories():
    """
    确保输出目录存在
    功能：创建results和figures目录（如果不存在）
    使用exist_ok=True避免目录已存在时报错
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(FIGURES_DIR, exist_ok=True)

def load_calibration_stats():
    """
    加载校准统计数据
    从JSON文件读取缓存校准的统计结果
    
    Returns:
        dict: 包含校准统计信息的字典，文件不存在返回None
        包含字段：sample_info, cache_hit_stats, cache_miss_stats, threshold_info等
    """
    filepath = os.path.join(RESULTS_DIR, "calibration", "calibration_stats.json")
    if not os.path.exists(filepath):
        print(f"Error: {filepath} not found")
        return None
    
    with open(filepath, 'r') as f:
        return json.load(f)

def load_calibration_csv():
    """
    加载校准CSV数据
    从CSV文件读取原始时间测量数据
    
    Returns:
        pandas.DataFrame: 包含time_cycles和type列的数据框
        用于绘制详细的分布图
    """
    filepath = os.path.join(RESULTS_DIR, "calibration", "calibration_stats.csv")
    if not os.path.exists(filepath):
        print(f"Error: {filepath} not found")
        return None
    
    return pd.read_csv(filepath)

def load_attack_stats(round_num):
    """
    加载指定轮次的攻击统计数据
    
    Args:
        round_num: 攻击轮次编号（1, 2, 3...）
    
    Returns:
        dict: 该轮攻击的统计信息，包含sbox_results等
        文件不存在返回None
    """
    filepath = os.path.join(RESULTS_DIR, "attack", f"attack_round_{round_num}_stats.json")
    if not os.path.exists(filepath):
        return None
    
    with open(filepath, 'r') as f:
        return json.load(f)

def get_all_attack_rounds():
    """
    获取所有攻击轮次文件
    通过glob匹配results/attack目录下的attack_round_*_stats.json文件
    
    Returns:
        list: 所有攻击轮次编号的有序列表
        例如：[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    """
    pattern = os.path.join(RESULTS_DIR, "attack", "attack_round_*_stats.json")
    files = glob.glob(pattern)
    rounds = []
    for f in files:
        try:
            # 从文件名提取轮次编号
            # 文件名格式：attack_round_{num}_stats.json
            round_num = int(os.path.basename(f).split('_')[2])
            rounds.append(round_num)
        except:
            pass
    return sorted(rounds)

def plot_timing_distribution(stats, save_path=None):
    """
    绘制时间分布分析图
    包含四个子图：直方图、箱线图、Q-Q图、统计表格
    
    Args:
        stats: 校准统计数据字典（从JSON加载）
        save_path: 图表保存路径，None则只显示不保存
    
    Returns:
        matplotlib.figure.Figure: 生成的图表对象
    
    图表说明：
    - 子图1: 重叠直方图，显示命中和未命中的分布对比
    - 子图2: 箱线图，显示中位数、四分位数和异常值
    - 子图3: Q-Q图，比较两组数据的分位数
    - 子图4: 统计指标表格
    """
    # 加载CSV原始数据用于绘图
    csv_data = load_calibration_csv()
    if csv_data is None:
        return
    
    # 分离命中和未命中数据
    # type列值为'hit'或'miss'，time_cycles为时间值
    hit_data = csv_data[csv_data['type'] == 'hit']['time_cycles'].values
    miss_data = csv_data[csv_data['type'] == 'miss']['time_cycles'].values
    
    # 创建2x2的子图布局，figsize设置画布大小（宽14英寸，高10英寸）
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Cache Timing Distribution Analysis', fontsize=16, fontweight='bold')
    
    # ========== 子图1: 重叠直方图（分开的bins） ==========
    ax1 = axes[0, 0]
    
    # 为Hit和Miss分别创建合适的bins范围
    hit_bins = np.linspace(hit_data.min(), hit_data.max(), 50)
    miss_bins = np.linspace(miss_data.min(), miss_data.max(), 50)
    
    # 计算直方图（密度模式）
    hit_counts, hit_bin_edges = np.histogram(hit_data, bins=hit_bins, density=True)
    miss_counts, miss_bin_edges = np.histogram(miss_data, bins=miss_bins, density=True)
    
    # 计算bin中心
    hit_centers = (hit_bin_edges[:-1] + hit_bin_edges[1:]) / 2
    miss_centers = (miss_bin_edges[:-1] + miss_bin_edges[1:]) / 2
    
    # 归一化到0-1范围以便在同一图表显示
    hit_y = hit_counts / hit_counts.max() if hit_counts.max() > 0 else hit_counts
    miss_y = miss_counts / miss_counts.max() if miss_counts.max() > 0 else miss_counts
    
    # 绘制平滑的曲线
    ax1.plot(hit_centers, hit_y, label='Signal (Hit)', color='green', linewidth=2)
    ax1.fill_between(hit_centers, hit_y, alpha=0.3, color='green')
    ax1.plot(miss_centers, miss_y, label='Noise (Miss)', color='red', linewidth=2)
    ax1.fill_between(miss_centers, miss_y, alpha=0.3, color='red')
    
    # 添加阈值线，用于可视化判断标准
    threshold = stats['threshold_info']['threshold']
    ax1.axvline(threshold, color='black', linestyle='--', linewidth=2, label=f'Threshold={threshold}')
    ax1.set_xlabel('Cycles')
    ax1.set_ylabel('Normalized Density')
    ax1.set_title('Timing Distribution')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # ========== 子图2: 箱线图对比 ==========
    ax2 = axes[0, 1]
    # patch_artist=True允许填充箱体颜色
    bp = ax2.boxplot([hit_data, miss_data], labels=['Cache Hit', 'Cache Miss'], 
                     patch_artist=True, showfliers=True)
    bp['boxes'][0].set_facecolor('lightgreen')  # 命中为浅绿色
    bp['boxes'][1].set_facecolor('lightcoral')  # 未命中为浅红色
    ax2.axhline(threshold, color='blue', linestyle='--', linewidth=2)
    ax2.set_ylabel('Time (cycles)')
    ax2.set_title('Box Plot Comparison')
    ax2.grid(True, alpha=0.3)
    
    # ========== 子图3: 分位数-分位数图 (Q-Q Plot) ==========
    ax3 = axes[1, 0]
    # 对数据进行排序
    hit_sorted = np.sort(hit_data)
    miss_sorted = np.sort(miss_data)
    # 取两组数据的最小长度，确保一一对应
    min_len = min(len(hit_sorted), len(miss_sorted))
    
    # 计算分位数：在0到1之间均匀取min_len个点
    quantiles = np.linspace(0, 1, min_len)
    hit_quantiles = np.quantile(hit_sorted[:min_len], quantiles)
    miss_quantiles = np.quantile(miss_sorted[:min_len], quantiles)
    
    # 散点图：x轴为命中分位数，y轴为未命中分位数
    ax3.scatter(hit_quantiles, miss_quantiles, alpha=0.5, s=10)
    # 绘制y=x参考线，如果数据点在这条线上，说明两组分布相同
    max_val = max(hit_quantiles.max(), miss_quantiles.max())
    ax3.plot([0, max_val], [0, max_val], 'r--', label='y=x')
    ax3.set_xlabel('Cache Hit Quantiles')
    ax3.set_ylabel('Cache Miss Quantiles')
    ax3.set_title('Q-Q Plot')
    ax3.legend()
    ax3.grid(True, alpha=0.3)
    
    # ========== 子图4: 统计指标表格 ==========
    ax4 = axes[1, 1]
    ax4.axis('off')  # 关闭坐标轴，只显示表格
    
    # 从stats字典提取统计数据
    hit_stats = stats['cache_hit_stats']
    miss_stats = stats['cache_miss_stats']
    threshold_info = stats['threshold_info']
    
    # 构建表格数据，每行是一个指标
    table_data = [
        ['Metric', 'Cache Hit', 'Cache Miss', 'Difference'],
        ['Mean (cycles)', f"{hit_stats['mean']:.2f}", f"{miss_stats['mean']:.2f}",
         f"{miss_stats['mean'] - hit_stats['mean']:.2f}"],
        ['Std Dev', f"{hit_stats['stddev']:.2f}", f"{miss_stats['stddev']:.2f}",
         f"{abs(miss_stats['stddev'] - hit_stats['stddev']):.2f}"],
        ['Median', f"{hit_stats['median']:.2f}", f"{miss_stats['median']:.2f}",
         f"{miss_stats['median'] - hit_stats['median']:.2f}"],
        ['IQR', f"{hit_stats['iqr']:.2f}", f"{miss_stats['iqr']:.2f}",
         f"{abs(miss_stats['iqr'] - hit_stats['iqr']):.2f}"],
        ['Min/Max', f"{hit_stats['min']}/{hit_stats['max']}",
         f"{miss_stats['min']}/{miss_stats['max']}",
         f"{miss_stats['min'] - hit_stats['min']:.0f}/{miss_stats['max'] - hit_stats['max']:.0f}"],
        ['Cohen\'s d', f"{threshold_info['cohens_d']:.4f}",
         f"{threshold_info['cohens_d']:.4f}",
         f"{threshold_info['cohens_d']:.4f}"],
        ['Separation', f"{threshold_info['separation_ratio']:.4f}",
         f"{threshold_info['separation_ratio']:.4f}",
         f"{threshold_info['separation_ratio']:.4f}"],
        ['Accuracy (%)', f"{threshold_info['classification_accuracy']['hit_accuracy_percent']:.2f}",
         f"{threshold_info['classification_accuracy']['miss_accuracy_percent']:.2f}",
         f"{threshold_info['classification_accuracy']['overall_accuracy_percent']:.2f}"],
    ]
    
    # 创建表格，cellLoc='center'表示单元格内容居中
    table = ax4.table(cellText=table_data[1:], colLabels=table_data[0],
                      cellLoc='center', loc='center',
                      colWidths=[0.3, 0.25, 0.25, 0.2])
    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 2)  # 缩放表格，1为宽度倍数，2为高度倍数
    
    # 高亮表头：设置背景色和文字样式
    for i in range(4):
        table[(0, i)].set_facecolor('#4CAF50')  # 绿色背景
        table[(0, i)].set_text_props(weight='bold', color='white')  # 白色粗体
    
    ax4.set_title('Statistical Summary', fontsize=12, fontweight='bold', pad=20)
    
    # 自动调整子图间距，避免重叠
    plt.tight_layout()
    
    # 保存图表到文件
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Saved: {save_path}")
    
    return fig

def plot_attack_results(rounds, save_path=None):
    """
    绘制攻击结果汇总图
    展示多轮攻击的统计结果
    
    Args:
        rounds: 攻击轮次编号列表
        save_path: 图表保存路径
    
    Returns:
        matplotlib.figure.Figure: 生成的图表对象
    
    图表说明：
    - 子图1: 每轮检测到的S-box数量柱状图
    - 子图2: 命中分布热力图（第一轮数据）
    - 子图3: 命中率趋势折线图
    - 子图4: 攻击摘要文本
    """
    if not rounds:
        print("No attack round data found")
        return None
    
    # 创建2x2子图布局
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('DES Attack Results Analysis', fontsize=16, fontweight='bold')
    
    # 收集所有轮次的数据
    all_data = []
    for round_num in rounds:
        stats = load_attack_stats(round_num)
        if stats:
            all_data.append((round_num, stats))
    
    if not all_data:
        print("No valid attack data")
        return None
    
    # ========== 子图1: 每轮检测到的S-box数量 ==========
    ax1 = axes[0, 0]
    rounds_list = [d[0] for d in all_data]
    detected_counts = []
    for _, stats in all_data:
        # 统计该轮成功检测的S-box数量（detected_entry >= 0表示成功）
        count = sum(1 for sbox in stats['sbox_results'] if sbox['detected_entry'] >= 0)
        detected_counts.append(count)
    
    # 绘制柱状图
    bars = ax1.bar(rounds_list, detected_counts, color='steelblue', edgecolor='black')
    # 添加目标线（8个S-box）
    ax1.axhline(y=8, color='red', linestyle='--', label='Target (8 S-boxes)')
    ax1.set_xlabel('Attack Round')
    ax1.set_ylabel('Detected S-boxes')
    ax1.set_title('S-box Detection per Round')
    ax1.set_ylim(0, 9)
    ax1.legend()
    ax1.grid(True, alpha=0.3, axis='y')
    
    # 在柱状图上添加数值标签
    for bar, count in zip(bars, detected_counts):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
                f'{count}', ha='center', va='bottom')
    
    # ========== 子图2: 最佳命中的分布热力图 ==========
    ax2 = axes[0, 1]
    
    # 选择第一轮的数据来展示S-box命中分布
    if all_data:
        first_round_stats = all_data[0][1]
        sbox_data = []
        for sbox in first_round_stats['sbox_results']:
            # hit_distribution是64个entry的命中次数数组
            sbox_data.append(sbox['hit_distribution'])
        
        if sbox_data:
            # 使用YlOrRd颜色映射（黄-橙-红），值越大颜色越深
            im = ax2.imshow(sbox_data, cmap='YlOrRd', aspect='auto')
            ax2.set_xlabel('Entry Index')
            ax2.set_ylabel('S-box')
            ax2.set_title('Hit Distribution Heatmap (Round 1)')
            ax2.set_yticks(range(8))
            ax2.set_yticklabels([f'S{i}' for i in range(8)])
            plt.colorbar(im, ax=ax2, label='Hit Count')
    
    # ========== 子图3: 命中率分析 ==========
    ax3 = axes[1, 0]
    hit_ratios = []
    for _, stats in all_data:
        # 计算每轮的平均命中率
        ratios = [sbox['hit_ratio'] for sbox in stats['sbox_results'] if sbox['detected_entry'] >= 0]
        if ratios:
            hit_ratios.append(np.mean(ratios))
        else:
            hit_ratios.append(0)
    
    # 绘制折线图
    ax3.plot(rounds_list, hit_ratios, 'o-', linewidth=2, markersize=8, color='green')
    ax3.set_xlabel('Attack Round')
    ax3.set_ylabel('Average Hit Ratio')
    ax3.set_title('Hit Ratio Trend Across Rounds')
    ax3.grid(True, alpha=0.3)
    ax3.set_ylim(0, 1)  # 命中率范围0-1
    
    # ========== 子图4: 攻击统计摘要（可视化） ==========
    ax4 = axes[1, 1]
    
    # 计算统计数据
    total_iterations = all_data[0][1]['iterations_per_entry'] * 64 if all_data else 0
    success_rate = np.mean(detected_counts) / 8
    best_round_idx = np.argmax(detected_counts)
    best_round = rounds_list[best_round_idx]
    max_detections = max(detected_counts)
    avg_detections = np.mean(detected_counts)
    avg_hit_ratio = np.mean(hit_ratios)
    
    # 使用GridSpec创建2x2小图表
    from matplotlib.gridspec import GridSpec
    gs_sub = GridSpec(2, 2, figure=fig, left=0.55, right=0.95, 
                      bottom=0.08, top=0.45, wspace=0.3, hspace=0.4)
    
    # 清除ax4，使用子GridSpec
    ax4.axis('off')
    
    # 小图1: 成功率环形图
    ax4_1 = fig.add_subplot(gs_sub[0, 0])
    sizes = [success_rate, 1 - success_rate]
    colors_ring = ['#2ecc71', '#ecf0f1']
    explode = (0.05, 0)
    wedges, texts, autotexts = ax4_1.pie(sizes, colors=colors_ring,
                                          autopct='%1.1f%%',
                                          startangle=90, explode=explode,
                                          wedgeprops=dict(width=0.5, edgecolor='black'))
    for autotext in autotexts:
        autotext.set_fontsize(10)
        autotext.set_fontweight('bold')
    ax4_1.set_title(f'Success Rate\n({success_rate*100:.1f}%)', fontsize=10, fontweight='bold')
    
    # 小图2: Best vs Average 对比
    ax4_2 = fig.add_subplot(gs_sub[0, 1])
    categories = ['Best', 'Average']
    values = [max_detections, avg_detections]
    colors_bar = ['#e74c3c', '#3498db']
    bars = ax4_2.barh(categories, values, color=colors_bar, alpha=0.8, edgecolor='black')
    ax4_2.set_xlim(0, 9)
    ax4_2.set_xlabel('Detections')
    ax4_2.set_title('Detections Comparison', fontsize=10, fontweight='bold')
    for bar, val in zip(bars, values):
        width = bar.get_width()
        ax4_2.text(width + 0.1, bar.get_y() + bar.get_height()/2.,
                  f'{val:.1f}', ha='left', va='center', fontsize=9)
    
    # 小图3: 关键指标（使用文本+背景）
    ax4_3 = fig.add_subplot(gs_sub[1, 0])
    ax4_3.axis('off')
    metrics_text = f"""Key Metrics:
    
Rounds: {len(all_data)}
Samples: {total_iterations}
Best Round: #{best_round}
Hit Ratio: {avg_hit_ratio*100:.1f}%"""
    ax4_3.text(0.1, 0.5, metrics_text, fontsize=9, family='monospace',
               verticalalignment='center',
               bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.3))
    
    # 小图4: 检测进度条
    ax4_4 = fig.add_subplot(gs_sub[1, 1])
    ax4_4.barh(['Progress'], [avg_detections], color='#9b59b6', alpha=0.8, height=0.3)
    ax4_4.barh(['Progress'], [8], color='gray', alpha=0.2, height=0.3)
    ax4_4.set_xlim(0, 9)
    ax4_4.set_xlabel('S-boxes (0-8)')
    ax4_4.set_title(f'Progress: {avg_detections:.1f}/8', fontsize=10, fontweight='bold')
    ax4_4.text(avg_detections + 0.2, 0, f'{avg_detections:.1f}', 
               va='center', fontsize=9, fontweight='bold')
    
    plt.tight_layout()
    
    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches='tight')
        print(f"Saved: {save_path}")
    
    return fig

def generate_summary_report(stats_list, attack_rounds):
    """
    生成文本摘要报告
    将统计结果输出为易读的文本格式
    
    Args:
        stats_list: 校准统计数据列表
        attack_rounds: 攻击轮次编号列表
    
    Returns:
        str: 生成的报告文件路径
    """
    report_path = os.path.join(RESULTS_DIR, "summary_report.txt")
    
    with open(report_path, 'w') as f:
        # 写入报告头部
        f.write("=" * 60 + "\n")
        f.write("DES Flush+Reload Attack - Statistical Report\n")
        f.write("=" * 60 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # 写入校准统计部分
        if stats_list:
            stats = stats_list[0]
            f.write("CALIBRATION STATISTICS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Sample Size: {stats['sample_info']['total_samples']}\n")
            f.write(f"Measurement Repeats: {stats['sample_info']['measurement_repeats']}\n\n")
            
            hit = stats['cache_hit_stats']
            miss = stats['cache_miss_stats']
            thresh = stats['threshold_info']
            
            # 缓存命中统计
            f.write("Cache Hit Statistics:\n")
            f.write(f"  Mean: {hit['mean']:.2f} cycles\n")
            f.write(f"  StdDev: {hit['stddev']:.2f} cycles\n")
            f.write(f"  Median: {hit['median']:.2f} cycles\n")
            f.write(f"  Range: {hit['min']} - {hit['max']} cycles\n")
            f.write(f"  IQR: {hit['iqr']:.2f} cycles\n\n")
            
            # 缓存未命中统计
            f.write("Cache Miss Statistics:\n")
            f.write(f"  Mean: {miss['mean']:.2f} cycles\n")
            f.write(f"  StdDev: {miss['stddev']:.2f} cycles\n")
            f.write(f"  Median: {miss['median']:.2f} cycles\n")
            f.write(f"  Range: {miss['min']} - {miss['max']} cycles\n")
            f.write(f"  IQR: {miss['iqr']:.2f} cycles\n\n")
            
            # 可区分性分析
            f.write("Discriminability Analysis:\n")
            f.write(f"  Cohen's d: {thresh['cohens_d']:.4f} ({thresh['discriminability']})\n")
            f.write(f"  Separation Ratio: {thresh['separation_ratio']:.4f}\n")
            f.write(f"  Classification Accuracy: {thresh['classification_accuracy']['overall_accuracy_percent']:.2f}%\n")
            f.write(f"  Threshold: {thresh['threshold']} cycles\n\n")
        
        # 写入攻击结果部分
        if attack_rounds:
            f.write("ATTACK RESULTS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Attack Rounds: {len(attack_rounds)}\n\n")
            
            for round_num in attack_rounds:
                stats = load_attack_stats(round_num)
                if stats:
                    detected = sum(1 for s in stats['sbox_results'] if s['detected_entry'] >= 0)
                    f.write(f"Round {round_num}: {detected}/8 S-boxes detected\n")
        
        # 写入报告尾部
        f.write("\n" + "=" * 60 + "\n")
        f.write("Files Generated:\n")
        f.write(f"  - {RESULTS_DIR}/calibration_stats.json\n")
        f.write(f"  - {RESULTS_DIR}/calibration_stats.csv\n")
        f.write(f"  - {FIGURES_DIR}/timing_distribution.png\n")
        f.write(f"  - {FIGURES_DIR}/attack_results.png\n")
        f.write(f"  - {RESULTS_DIR}/summary_report.txt\n")
        f.write("=" * 60 + "\n")
    
    print(f"Generated: {report_path}")
    return report_path

def main():
    """
    主函数
    程序入口点，协调各个功能模块的执行
    
    执行流程：
    1. 确保输出目录存在
    2. 加载校准统计数据
    3. 生成时间分布可视化图
    4. 加载攻击轮次数据
    5. 生成攻击结果可视化图
    6. 生成文本摘要报告
    """
    # 打印程序标题
    print("=" * 60)
    print("DES Flush+Reload Attack Visualization")
    print("=" * 60)
    
    # 步骤1: 确保目录存在
    ensure_directories()
    
    # 步骤2: 加载校准统计数据
    calibration_stats = load_calibration_stats()
    if calibration_stats is None:
        print("\nError: No calibration data found. Please run the attack first.")
        sys.exit(1)
    
    print("\n1. Loading calibration statistics...")
    print(f"   Samples: {calibration_stats['sample_info']['total_samples']}")
    print(f"   Cohen's d: {calibration_stats['threshold_info']['cohens_d']:.4f}")
    
    # 步骤3: 绘制时间分布图
    print("\n2. Generating timing distribution plots...")
    timing_fig = plot_timing_distribution(
        calibration_stats,
        save_path=os.path.join(FIGURES_DIR, "timing_distribution.png")
    )
    
    # 步骤4: 加载攻击轮次数据
    attack_rounds = get_all_attack_rounds()
    print(f"\n3. Found {len(attack_rounds)} attack round(s)")
    
    # 步骤5: 绘制攻击结果图
    if attack_rounds:
        print("\n4. Generating attack results plots...")
        attack_fig = plot_attack_results(
            attack_rounds,
            save_path=os.path.join(FIGURES_DIR, "attack_results.png")
        )
    
    # 步骤6: 生成摘要报告
    print("\n5. Generating summary report...")
    generate_summary_report([calibration_stats], attack_rounds)
    
    # 打印完成信息
    print("\n" + "=" * 60)
    print("Visualization Complete!")
    print("=" * 60)
    print(f"\nOutput files:")
    print(f"  Figures: {FIGURES_DIR}/")
    print(f"  Report:  {RESULTS_DIR}/summary_report.txt")
    print(f"\nTo view results:")
    print(f"  - Open PNG files in {FIGURES_DIR}/")
    print(f"  - Read {RESULTS_DIR}/summary_report.txt")
    
    # 尝试显示图表（如果在图形环境中）
    try:
        plt.show()
    except:
        pass

if __name__ == "__main__":
    main()
