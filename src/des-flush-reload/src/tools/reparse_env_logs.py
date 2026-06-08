#!/usr/bin/env python3
"""
reparse_env_logs.py
重新解析环境对比实验的日志文件，提取完整的攻击结果
"""

import json
import os
import re
from datetime import datetime

RESULTS_DIR = "results"

def parse_full_results(log_file):
    """从日志文件中解析完整结果"""
    results = {
        'hit_mean': 0,
        'hit_stddev': 0,
        'miss_mean': 0,
        'miss_stddev': 0,
        'threshold': 0,
        'cohens_d': 0,
        'accuracy': 0,
        'detected_fragments': 0,
        'attack_success': 0,
        'snr': 0,
        'recovery_rate': 0
    }
    
    try:
        with open(log_file, 'r') as f:
            content = f.read()
        
        # 解析Cache Hit
        hit_match = re.search(r'Cache Hit\s+- Mean:\s+([\d.]+),\s+StdDev:\s+([\d.]+)', content)
        if hit_match:
            results['hit_mean'] = float(hit_match.group(1))
            results['hit_stddev'] = float(hit_match.group(2))
        
        # 解析Cache Miss
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
        
        # 解析SNR
        snr_match = re.search(r'SNR:\s+([\d.]+)\s+dB', content)
        if snr_match:
            results['snr'] = float(snr_match.group(1))
        
        # 解析Recovery Rate和Detected Fragments
        recovery_match = re.search(r'Recovered:\s+(\d+)/8', content)
        if recovery_match:
            results['detected_fragments'] = int(recovery_match.group(1))
            results['recovery_rate'] = (results['detected_fragments'] / 8.0) * 100
            results['attack_success'] = 1 if results['detected_fragments'] >= 6 else 0
        
        # 解析Duration
        duration_match = re.search(r'Duration:\s+([\d.]+)\s+ms', content)
        if duration_match:
            results['attack_duration'] = float(duration_match.group(1)) / 1000.0  # 转换为秒
                    
    except Exception as e:
        print(f"Error parsing {log_file}: {e}")
    
    return results

def main():
    print("="*70)
    print("Re-parsing Environment Comparison Logs")
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
        
        results = parse_full_results(log_file)
        
        print(f"  Hit Mean: {results['hit_mean']:.2f}")
        print(f"  Hit StdDev: {results['hit_stddev']:.2f}")
        print(f"  Cohen's d: {results['cohens_d']:.4f}")
        print(f"  Accuracy: {results['accuracy']:.2f}%")
        print(f"  Detected: {results['detected_fragments']}/8")
        print(f"  Recovery Rate: {results['recovery_rate']:.2f}%")
        print(f"  SNR: {results['snr']:.2f} dB")
        print(f"  Duration: {results['attack_duration']:.2f}s")
        
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
            'recovery_rate': results['recovery_rate'],
            'attack_success': results['attack_success'],
            'snr': results['snr'],
            'attack_duration': results['attack_duration']
        }
        data['environments'].append(env_data)
    
    json_file = os.path.join(RESULTS_DIR, 'environment_comparison.json')
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"\nSaved: {json_file}")
    
    print("\n" + "="*70)
    print("Complete! Now run visualize_environment_comparison.py")
    print("="*70)
    
    return 0

if __name__ == "__main__":
    exit(main())
