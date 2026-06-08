#!/usr/bin/env python3
"""
run_env_comparison.py
环境控制对比实验 - 简化版（仅对比默认 vs CPU绑定）
"""

import subprocess
import json
import os
import sys
import time
import signal
from datetime import datetime

# 配置 - 只保留2种对比
RESULTS_DIR = "results"
BUILD_DIR = "build"
ENV_CONFIGS = [
    {
        "name": "Default (No CPU Binding)",
        "cpu": None,
        "description": "默认配置，不绑定CPU"
    },
    {
        "name": "CPU Pinned (Core 0)",
        "cpu": 0,
        "description": "绑定到CPU核心0"
    }
]

def run_attack_with_env(config, output_file):
    """在特定环境配置下运行攻击"""
    print(f"\n{'='*60}")
    print(f"Testing: {config['name']}")
    print(f"{'='*60}")
    
    # 构建命令
    cmd = []
    
    # CPU绑定
    if config['cpu'] is not None:
        cmd.extend(['taskset', '-c', str(config['cpu'])])
    
    # 主程序
    cmd.extend([f'./{BUILD_DIR}/spy', f'./{BUILD_DIR}/libdes.so'])
    
    print(f"Command: {' '.join(cmd)}")
    
    # 运行程序
    start_time = time.time()
    try:
        with open(output_file, 'w') as f:
            process = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # 等待完成（设置超时）
            try:
                process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                print("Timeout! Killing process...")
                process.send_signal(signal.SIGTERM)
                process.wait()
                
    except Exception as e:
        print(f"Error running attack: {e}")
        return None
    
    duration = time.time() - start_time
    print(f"Completed in {duration:.2f} seconds")
    
    return duration

def parse_results(output_file):
    """从输出文件中解析结果 - 修复版"""
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
        with open(output_file, 'r') as f:
            content = f.read()
        
        import re
        
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
        
        # 解析Cohen's d - 格式: "Cohen's d:  0.0231 (Good)"
        cohen_match = re.search(r"Cohen's d:\s+([\d.]+)", content)
        if cohen_match:
            results['cohens_d'] = float(cohen_match.group(1))
        
        # 解析Threshold - 格式: "Threshold:  135 cycles"
        threshold_match = re.search(r'Threshold:\s+(\d+)\s+cycles', content)
        if threshold_match:
            results['threshold'] = float(threshold_match.group(1))
        
        # 解析Classification Accuracy - 格式: "Classification Accuracy: 99.33%"
        accuracy_match = re.search(r'Classification Accuracy:\s+([\d.]+)%', content)
        if accuracy_match:
            results['accuracy'] = float(accuracy_match.group(1))
        
        # 解析检测到的S-box数量 - 格式: "S-boxes detected: 8/8"
        detected_match = re.search(r'S-boxes detected:\s*(\d+)/8', content)
        if detected_match:
            results['detected_fragments'] = int(detected_match.group(1))
            results['attack_success'] = 1 if results['detected_fragments'] >= 6 else 0
                    
    except Exception as e:
        print(f"Error parsing results: {e}")
    
    return results

def save_comparison_json(all_results, output_file):
    """保存对比结果到JSON"""
    data = {
        'timestamp': datetime.now().isoformat(),
        'environments': []
    }
    
    for i, (config, results) in enumerate(all_results):
        env_data = {
            'name': config['name'],
            'description': config['description'],
            'hit_mean': results.get('hit_mean', 0),
            'hit_stddev': results.get('hit_stddev', 0),
            'miss_mean': results.get('miss_mean', 0),
            'miss_stddev': results.get('miss_stddev', 0),
            'threshold': results.get('threshold', 0),
            'cohens_d': results.get('cohens_d', 0),
            'accuracy': results.get('accuracy', 0),
            'detected_fragments': results.get('detected_fragments', 0),
            'attack_success': results.get('attack_success', 0),
            'attack_duration': results.get('duration', 0)
        }
        data['environments'].append(env_data)
    
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\nResults saved to: {output_file}")

def main():
    print("="*70)
    print("Environment Control Comparison: Default vs CPU Pinned")
    print("="*70)
    print(f"\nStart time: {datetime.now()}")
    
    # 确保目录存在
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(os.path.join(RESULTS_DIR, 'env_logs'), exist_ok=True)
    
    # 检查程序是否存在
    if not os.path.exists(f'./{BUILD_DIR}/spy'):
        print(f"\nError: ./{BUILD_DIR}/spy not found!")
        print("Please run 'make' first.")
        return 1
    
    # 运行所有配置
    all_results = []
    
    for i, config in enumerate(ENV_CONFIGS):
        print(f"\n\n[{i+1}/{len(ENV_CONFIGS)}] Testing: {config['name']}")
        
        # 输出文件
        log_file = os.path.join(RESULTS_DIR, 'env_logs', f'env_{i}_{config["name"].replace(" ", "_")}.log')
        
        # 运行攻击
        duration = run_attack_with_env(config, log_file)
        
        if duration is None:
            print(f"Failed to run configuration: {config['name']}")
            continue
        
        # 解析结果
        results = parse_results(log_file)
        results['duration'] = duration
        
        print(f"\nResults:")
        print(f"  Hit Mean: {results['hit_mean']:.2f} cycles")
        print(f"  Hit StdDev: {results['hit_stddev']:.2f} cycles")
        print(f"  Cohen's d: {results['cohens_d']:.4f}")
        print(f"  Duration: {duration:.2f}s")
        
        all_results.append((config, results))
        
        # 实验间隔
        if i < len(ENV_CONFIGS) - 1:
            print("\nWaiting 3 seconds before next test...")
            time.sleep(3)
    
    # 保存结果
    json_file = os.path.join(RESULTS_DIR, 'environment_comparison.json')
    save_comparison_json(all_results, json_file)
    
    # 打印对比总结
    print("\n" + "="*70)
    print("COMPARISON SUMMARY")
    print("="*70)
    
    if len(all_results) == 2:
        default = all_results[0][1]
        pinned = all_results[1][1]
        
        print(f"\n{'Metric':<30} {'Default':>12} {'CPU Pinned':>12} {'Change':>12}")
        print("-"*70)
        print(f"{'Hit Mean (cycles)':<30} {default['hit_mean']:>12.2f} {pinned['hit_mean']:>12.2f} {((pinned['hit_mean']-default['hit_mean'])/default['hit_mean']*100):>+11.1f}%")
        print(f"{'Hit StdDev (cycles)':<30} {default['hit_stddev']:>12.2f} {pinned['hit_stddev']:>12.2f} {((pinned['hit_stddev']-default['hit_stddev'])/(default['hit_stddev']+1)*100):>+11.1f}%")
        cohen_change = ((pinned['cohens_d']-default['cohens_d'])/default['cohens_d']*100) if default['cohens_d'] != 0 else 0
        print(f"{'Cohen d':<30} {default['cohens_d']:>12.4f} {pinned['cohens_d']:>12.4f} {cohen_change:>+11.1f}%")
        print(f"{'Duration (seconds)':<30} {default['duration']:>12.2f} {pinned['duration']:>12.2f} {((pinned['duration']-default['duration'])/default['duration']*100):>+11.1f}%")
        
        # 结论
        print("\n" + "="*70)
        print("CONCLUSION")
        print("="*70)
        
        if pinned['duration'] < default['duration']:
            improvement = (default['duration'] - pinned['duration']) / default['duration'] * 100
            print(f"\n✓ CPU binding reduces attack time by {improvement:.1f}%")
        
        if pinned['hit_stddev'] < default['hit_stddev']:
            print(f"✓ CPU binding reduces timing variability (noise)")
        
        if pinned['cohens_d'] > default['cohens_d']:
            print(f"✓ CPU binding improves effect size (better signal)")
    
    print("\n" + "="*70)
    print(f"End time: {datetime.now()}")
    print("="*70)
    
    print("\nNext step:")
    print("python3 ./src/tools/visualize_environment_comparison.py")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
