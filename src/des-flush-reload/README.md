# 基于Flush+Reload的DES算法Cache计时攻击

本项目实现了针对DES加密算法的Flush+Reload缓存侧信道攻击，并评估了多种缓解措施的效果。

## 项目概述

### 攻击原理

Flush+Reload是一种缓存侧信道攻击技术，利用CPU缓存的时间差异来推断敏感信息：

1. **Flush**: 攻击者将目标内存行从缓存中驱逐
2. **Trigger**: 触发受害者执行加密操作
3. **Reload**: 测量重新加载目标内存行的时间

通过分析时序差异，攻击者可以恢复DES密钥。

### 实验环境

```
硬件: Intel i5-1135G7 (Tiger Lake), 2 vCPUs
虚拟化: VMware + Ubuntu 20.04 LTS
内核: Linux 5.15.0-139-generic
编译器: GCC 9.4.0
```

***

## 快速开始

### 1. 环境准备

```bash
# 安装Python依赖
pip3 install -r requirements.txt

# 编译项目
make clean && make

# 验证编译结果
ls -lh build/
# 应包含: spy, test_mitigation, libdes.so
```

### 2. 运行基础攻击

```bash
# 运行单次攻击测试
./build/spy ./build/libdes.so

# 生成可视化图表
python3 ./src/tools/visualize_results.py
python3 ./src/tools/quantify_analysis.py

# 查看结果
ls results/figures/
```

***

## 完整实验流程

### 流程一：基础攻击测试

```bash
# Step 1: 编译
make clean && make

# Step 2: 运行攻击
./build/spy ./build/libdes.so

# Step 3: 生成可视化
python3 ./src/tools/visualize_results.py
python3 ./src/tools/quantify_analysis.py

# Step 4: 查看结果
cat results/summary_report.txt
cat results/quantitative_report.txt
ls results/figures/
```

**预期输出**:

- `results/figures/timing_distribution.png` - 时序分布分析
- `results/figures/attack_results.png` - 攻击结果
- `results/figures/quantitative_metrics.png` - 量化指标
- `results/summary_report.txt` - 攻击摘要

### 流程二：CPU绑定对比实验（环境控制）

```bash
# Step 1: 确保已编译
make clean && make

# Step 2: 运行环境对比实验
python3 ./src/tools/run_env_comparison.py

# Step 3: 生成可视化
python3 ./src/tools/visualize_environment_comparison.py

# Step 4: 查看结果
cat results/environment_comparison_report.txt
ls results/figures/environment_comparison_dashboard.png
```

**实验内容**:

- 对比"默认配置" vs "CPU绑定"的攻击效果
- 评估环境控制对时序稳定性的影响

**关键发现**:

- CPU绑定降低Hit StdDev 90%（318.48 → 31.26）
- Cohen's d提升211%（0.0231 → 0.0719）
- 显著提高攻击稳定性

### 流程三：缓解措施测试（完整评估）

```bash
# Step 1: 编译
make clean && make

# Step 2: 运行完整缓解措施测试（约1小时）
./build/test_mitigation -a

# Step 3: 生成可视化
python3 ./src/tools/visualize_mitigation.py

# Step 4: 查看结果
cat results/mitigation_report.txt
ls results/figures/mitigation/
```

**测试的缓解措施**:

1. CPU Pinning
2. Cache Flush
3. Noise Injection
4. Access Obfuscation
5. Process Isolation
6. Core Isolation
7. Disable Hyperthreading

### 流程四：特定缓解措施测试（单独验证）

```bash
# 编译
make clean && make

# 测试特定措施（25轮迭代）
./build/test_mitigation -c 1 -i 25  # CPU Pinning
./build/test_mitigation -c 2 -i 25  # Cache Flush
./build/test_mitigation -c 3 -i 25  # Noise Injection
./build/test_mitigation -c 4 -i 25  # Access Obfuscation
./build/test_mitigation -c 5 -i 25  # Process Isolation
./build/test_mitigation -c 6 -i 25  # Core Isolation
./build/test_mitigation -c 7 -i 25  # Disable HT

# 查看结果
cat results/mitigation_report.txt
```

## 项目结构

```
.
├── build/                      # 编译输出
│   ├── spy                     # 主攻击程序
│   ├── test_mitigation         # 缓解措施测试
│   └── libdes.so              # DES库
├── src/
│   ├── spy.c                  # 攻击实现
│   ├── test_mitigation.c      # 缓解措施测试
│   ├── mitigation.c           # 缓解措施实现
│   ├── metrics.c              # 指标计算
│   ├── output.c               # 输出处理
│   ├── statistics.c           # 统计分析
│   └── tools/                 # 可视化工具
│       ├── visualize_results.py
│       ├── quantify_analysis.py
│       ├── visualize_mitigation.py
│       ├── run_env_comparison.py      # CPU绑定对比
│       ├── visualize_environment_comparison.py
│       ├── reparse_env_logs.py
│       └── reparse_and_visualize.py
├── include/                   # 头文件
├── doc/                       # 文档
│   └── 图表指标详解.md        # 详细解释所有图表指标
├── results/                   # 实验结果
│   ├── figures/              # 可视化图表
│   ├── attack/               # 攻击数据
│   └── metrics/              # 指标数据
├── Makefile
├── requirements.txt
└── README.md
```
