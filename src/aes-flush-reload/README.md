# AES Flush+Reload Cache Side-Channel Attack

## 项目概述

本项目实现了针对AES-128、AES-192和AES-256的**真实Flush+Reload缓存侧信道攻击**。攻击使用POSIX共享内存实现跨进程T表共享，通过fork()创建victim和attacker进程，利用缓存访问模式推断密钥。

本项目为天津大学2026届本科毕业论文《处理器微架构侧信道漏洞安全测试技术研究》的配套实验代码。

## 攻击成功率

| 攻击模式    | 密钥长度 | 恢复目标 | 原始密钥恢复   | 推荐样本数 | 成功率     |
| ------- | ---- | ---- | -------- | ----- | ------- |
| AES-128 | 128位 | K10  | **完全恢复** | 5000  | **100%** |
| AES-192 | 192位 | K12+K11 | **完全恢复** | 9000 | **100%** |
| AES-256 | 256位 | K14+K13 | **完全恢复** | 15000 | **100%** |

### 原始密钥恢复说明

- **AES-128**：可以从K10完全逆向恢复原始密钥K0（16字节）
- **AES-192**：需要恢复K12和K11两个轮密钥才能恢复原始密钥（24字节）
- **AES-256**：需要恢复K14和K13两个轮密钥才能恢复原始密钥（32字节）

### 两阶段密钥恢复策略

AES-128仅需恢复最后一轮子密钥K10，通过密钥扩展逆过程即可推导原始密钥K0。

AES-192和AES-256需要两阶段攻击：

1. **阶段一**：通过排除法恢复最后一轮子密钥（AES-192恢复K12，AES-256恢复K14）
2. **阶段二**：复用同一批Flush+Reload监控数据，结合等效解密中间值IV₁，对等效解密轮密钥Kd₁的每个字节直接执行排除法，恢复Kd₁后经MixColumns变换得到加密倒数第二轮子密钥

两个阶段共享同一批监控数据，无需重复采样。两阶段攻击的整体成功率是两个阶段成功率的乘积，噪声对每个阶段的削弱效应会级联放大——阶段一恢复的轮密钥一旦有任意字节出错，阶段二的等效解密计算就会全部错误。

## 项目结构

```
aes-flush-reload/
├── include/              # 头文件目录
│   ├── config.h          # 全局配置文件
│   ├── aes.h             # AES算法接口定义
│   ├── shared_mem.h      # 共享内存管理
│   ├── utils.h           # 缓存攻击工具函数
│   └── attack_common.h   # 攻击共同代码
├── src/                  # 源文件目录
│   ├── attack_aes.c      # 统一攻击程序（支持AES-128/192/256）
│   ├── attack_common.c   # 攻击共同实现
│   └── aes.c             # AES算法实现（T表版本）
├── scripts/              # 脚本目录
│   └── plot_results.py   # 实验结果可视化脚本
├── thesis/               # 毕业论文LaTeX源码
│   ├── contents/         # 论文章节
│   └── figures/          # 论文图表
├── results/              # 实验结果目录
│   ├── data/             # 实验数据
│   └── figures/          # 可视化图表
├── run_experiment.sh     # 综合实验脚本
├── Makefile              # 编译脚本
└── README.md             # 项目说明
```

## 编译

### 依赖

- GCC编译器
- Linux操作系统（需要clflush指令支持）
- POSIX共享内存支持
- Python 3 + matplotlib（可视化，可选）

### 编译命令

```bash
make clean && make
```

## 使用方法

### 基本攻击

```bash
# AES-128攻击
./build/bin/attack_aes 128 5000

# AES-192攻击
./build/bin/attack_aes 192 9000

# AES-256攻击
./build/bin/attack_aes 256 15000
```

### 命令行参数

```
Usage: ./attack_aes <aes_type> [samples] [options]

Arguments:
  aes_type    AES类型: 128, 192, 或 256
  samples     样本数量（可选，使用默认值）

Mitigation Options (for comparison experiments):
  --no-pin          Disable CPU core pinning
  --noise-low       30% probability read T-table cache line 0
  --noise-medium    40% probability read T-table cache line 0
  --noise-high      50% probability read T-table cache line 0
  --cache-flush     Victim flushes T-tables after encryption
  --metrics         Output detailed timing metrics

Examples:
  ./build/bin/attack_aes 128                    # AES-128，默认样本数
  ./build/bin/attack_aes 128 5000               # AES-128，5000样本
  ./build/bin/attack_aes 192 9000 --no-pin     # AES-192，不绑定核心
  ./build/bin/attack_aes 256 15000 --metrics    # AES-256，输出详细指标
```

## 综合统计测试

`run_experiment.sh` 是统一的测试脚本，同时测量成功率和量化指标。

### 单一策略测试模式

测试指定配置下的攻击成功率和量化指标：

```bash
# 测试 AES-128，5000样本，100轮
./run_experiment.sh 128 5000 100

# 测试 AES-192，9000样本，50轮
./run_experiment.sh 192 9000 50

# 测试 AES-256，15000样本，30轮
./run_experiment.sh 256 15000 30

# 单一策略 + 指定缓解措施
./run_experiment.sh 128 5000 100 --no-pin
./run_experiment.sh 128 5000 100 --noise-low
./run_experiment.sh 128 5000 100 --noise-medium
./run_experiment.sh 128 5000 100 --noise-high
./run_experiment.sh 128 5000 100 --cache-flush

# 默认参数：AES-128，5000样本，100轮
./run_experiment.sh
```

### 对比测试模式

对比多种缓解措施的效果：

```bash
# AES-128 对比实验（默认5种配置）
./run_experiment.sh 128 20 --compare

# AES-192 对比实验
./run_experiment.sh 192 20 --compare

# AES-256 对比实验
./run_experiment.sh 256 20 --compare
```

默认对比测试会运行以下5种配置：

1. 基准（默认）
2. Noise-Low（30%概率读取T表监控缓存行）
3. Noise-Medium（40%概率读取T表监控缓存行）
4. Noise-High（50%概率读取T表监控缓存行）
5. 缓存刷新

### 自定义对比（自由组合缓解措施）

```bash
# 只对比基准 vs 不绑定核心
./run_experiment.sh 128 20 --compare --no-pin

# 对比基准 vs 噪声缓解
./run_experiment.sh 128 20 --compare --noise-low --noise-medium --noise-high

# 对比基准 vs 缓存刷新
./run_experiment.sh 128 20 --compare --cache-flush
```

### 输出指标

脚本在所有轮次结束后输出聚合的量化指标：

#### 基础统计

| 指标                     | 说明                          |
| ---------------------- | --------------------------- |
| sample\_count          | 总样本数（加密次数）                  |
| measurement\_count     | 总测量次数（= sample\_count \* 4） |
| hit\_count/miss\_count | 缓存命中/未命中次数                  |

#### 比率指标

| 指标           | 说明           |
| ------------ | ------------ |
| hit\_rate    | 缓存命中率 (0-1)  |
| miss\_rate   | 缓存未命中率 (0-1) |

#### 时间统计

| 指标         | 说明                     |
| ---------- | ---------------------- |
| hit\_mean  | 平均缓存命中时间 (CPU cycles)  |
| miss\_mean | 平均缓存未命中时间 (CPU cycles) |
| mean\_diff | 时间差异 (miss - hit)      |

#### 安全指标

| 指标               | 说明                          |
| ---------------- | --------------------------- |
| snr              | 信噪比 (基于错误率的简化模型) |
| leakage\_bw\_bps | 泄露带宽 (bits per second，基于二值信道互信息) |

### 输出文件

- `results/data/experiment_*.txt` - 实验原始数据
- `results/figures/comparison/` - 对比实验图表
- `results/figures/single_test/` - 单独测试图表
- `results/data/summary_report.md` - 统计摘要报告

## 攻击算法

### 排除法：恢复最后一轮密钥

**核心思想**：利用缓存未命中信息排除不可能的密钥候选。

对于每个样本，如果检测到T表缓存行0未被访问：

```
说明最后一轮输入x ∉ [0, 15]
因此 S[x] ∉ {S[0], S[1], ..., S[15]}
由于 K_last = ciphertext ⊕ S[x]
所以 K_last ≠ ciphertext ⊕ S[i]，对于 i ∈ [0, 15]
```

这些候选值被"排除"，增加它们的计数。最终选择被排除次数最少的候选作为正确密钥。

### 有效未命中率分析

排除法仅在未命中样本上执行排除。每张T表在加密中被多次访问，单次访问不落在第0缓存行的概率为15/16。整次加密中第0缓存行从未被访问的概率：

| AES变体 | 每表访问次数 | p_miss | 理论最低样本量 |
|---------|-----------|--------|------------|
| AES-128 | 40次 | 0.076 | ~1171 |
| AES-192 | 48次 | 0.045 | ~1978 |
| AES-256 | 56次 | 0.027 | ~3296 |

AES-256的p_miss比AES-192低约40%，有效排除样本更少，单字节恢复的可靠性更低。两阶段攻击需要同时恢复32个字节的轮密钥，级联放大效应将微小的单字节可靠性差异急剧放大。

### 原始密钥恢复

**AES-128**：通过逆向密钥扩展从K10恢复K0

```
正向扩展：W[i] = W[i-4] ^ SubWord(RotWord(W[i-1])) ^ Rcon[i/4]
逆向推导：W[i-4] = W[i] ^ SubWord(RotWord(W[i-1])) ^ Rcon[i/4]
```

**AES-192/256**：需要恢复多个轮密钥才能推导原始密钥

- AES-192的Nk=6，一轮子密钥仅4个字，不足以逆推6字一组的密钥扩展，必须恢复K12和K11获得8个连续字
- AES-256的Nk=8，同理必须恢复K14和K13获得8个连续字

## 配置参数

在`include/config.h`中可以修改以下参数：

| 常量名              | 默认值    | 说明           |
| ---------------- | ------ | ------------ |
| `AES128_SAMPLES` | 5000   | AES-128默认样本数 |
| `AES192_SAMPLES` | 9000  | AES-192默认样本数 |
| `AES256_SAMPLES` | 15000  | AES-256默认样本数 |
| `MAX_SAMPLES`    | 1000000 | 最大样本数        |

## 注意事项

1. **CPU核心绑定**：攻击者和受害者必须绑定到同一CPU核心，否则缓存不共享
2. **样本数量**：AES-256需要更多样本才能成功恢复密钥
3. **阈值校准**：程序会自动校准缓存命中/未命中阈值
4. **缓解措施测试**：使用`--compare`模式可以对比不同缓解措施的效果

## 实验结果

### 实验环境

- **处理器**: Intel Core i5-1135G7 @ 2.40GHz, 4核8线程 (Tiger Lake微架构)
- **缓存**: L1d 48KB/core (12路), L2 1.25MB/core (20路), L3 8MB shared (12路)
- **操作系统**: Ubuntu 20.04 LTS, Linux 5.15.0
- **编译器**: GCC 9.4.0, -O0 -march=native
- **其他配置**: 关闭ASLR, CPU频率设为performance模式, 超线程保留, 进程绑定CPU 0

### 缓存时间分布与阈值校准

| 统计量 | 命中时间（周期） | 未命中时间（周期） |
|------|-----------|-----------|
| 中位数 | 118.0 | 347.0 |
| Q1 | 116.0 | 344.0 |
| Q3 | 120.0 | 362.0 |
| P5 | 108.0 | 333.0 |
| P95 | 132.0 | 508.0 |

命中时间中位数（118周期）与未命中时间中位数（347周期）相差约229周期，P5-P95范围内无重叠。分类阈值 T = (118 + 347) / 2 = 233周期。

### 攻击成功率

| 攻击模式    | 密钥长度 | 恢复目标 | 原始密钥恢复   | 推荐样本数 | 成功率     |
| ------- | ---- | ---- | -------- | ----- | ------- |
| AES-128 | 128位 | K10  | **完全恢复** | 5000  | **100%** |
| AES-192 | 192位 | K12+K11 | **完全恢复** | 9000 | **100%** |
| AES-256 | 256位 | K14+K13 | **完全恢复** | 15000 | **100%** |

### 缓解措施对比测试结果

每种配置测试30轮，结果如下：

#### AES-128 (5000样本)

| 配置 | 成功率 | 泄露带宽(bps) |
|------|--------|------------|
| Baseline | **100%** | 60759 |
| Noise-Low (30%) | 100% | 26079 |
| Noise-Med (40%) | 90% | 21873 |
| Noise-High (50%) | 46% | 12467 |
| Cache-Flush | 0% | 0 |

#### AES-192 (9000样本)

| 配置 | 成功率 | 泄露带宽(bps) |
|------|--------|------------|
| Baseline | **100%** | 34678 |
| Noise-Low (30%) | 93% | 18080 |
| Noise-Med (40%) | 66% | 12433 |
| Noise-High (50%) | 36% | 9174 |
| Cache-Flush | 0% | 0 |

#### AES-256 (15000样本)

| 配置 | 成功率 | 泄露带宽(bps) |
|------|--------|------------|
| Baseline | **100%** | 23584 |
| Noise-Low (30%) | 66% | 10758 |
| Noise-Med (40%) | 40% | 8329 |
| Noise-High (50%) | 20% | 6032 |
| Cache-Flush | 0% | 0 |

### 噪声对多阶段攻击的级联放大效应

AES-128采用单阶段攻击，对噪声相对鲁棒；AES-192和AES-256采用两阶段攻击，对噪声更敏感。两阶段攻击的整体成功率近似为两个阶段成功率的乘积：

```
P_total = P_1 × P_{2|1} ≈ p_byte^32
```

若单字节成功率p_byte = 0.99，则整体约0.72；若p_byte = 0.97，则整体约0.38。单字节可靠性仅差2个百分点，经过32次乘积后成功率几乎减半。

AES-256比AES-192更难攻破的根本原因：
1. 14轮加密使p_miss更低（0.027 vs 0.045），每阶段有效信息量少约40%
2. 两阶段攻击需要同时恢复32个字节的轮密钥，级联放大效应将微小差异急剧放大
3. 噪声注入进一步压缩本已稀缺的有效信息，使级联失败更加严重

### 泄露带宽分析

泄露带宽定义为 BW = 4 × MI_binary × f_sample，其中MI_binary为单次缓存行观测的互信息，f_sample为采样频率。

泄露带宽随噪声增强的下降幅度：

| AES变体 | Noise-Low降幅 | Noise-Med降幅 | Noise-High降幅 |
|---------|-------------|-------------|--------------|
| AES-128 | 57% (60759→26079) | 64% (→21873) | 79% (→12467) |
| AES-192 | 48% (34678→18080) | 64% (→12433) | 73% (→9174) |
| AES-256 | 54% (23584→10758) | 65% (→8329) | 74% (→6032) |

泄露带宽的下降幅度在三种AES变体间总体接近，但成功率的下降差异显著。例如Noise-High下三种变体的泄露带宽降幅都在73%-79%之间，但AES-128成功率为46%，AES-192为36%，AES-256仅为20%。这说明成功率下降的主因是级联放大效应，而非单纯的泄露量减少。

### 指标说明

- **SNR**：信噪比，基于错误率的简化度量模型。定义为(1 - ε_total) / ε_total，其中ε_total = ε_timing + ε_noise为总错误率，ε_timing为定时测量固有误差（取0.01），ε_noise = (1 - p_access) × f为噪声引入的误差（p_access为缓存命中率，f为噪声假阳性概率）。Cache-Flush下SNR为0。
- **泄露带宽(BW)**：基于二值信道互信息与采样频率计算，反映单位时间内通过侧信道泄露的信息量。Cache-Flush下泄露带宽为0，表明该缓解措施完全消除了信息泄露。

### 缓解措施有效性总结

| 缓解措施 | AES-128 | AES-192 | AES-256 | 评价 |
|----------|---------|---------|---------|------|
| Cache-Flush | 0% | 0% | 0% | **最有效**，完全阻止攻击，泄露带宽为0 |
| Noise-High (50%) | 46% | 36% | 20% | 对三种AES均有显著效果，密钥越长越有效 |
| Noise-Med (40%) | 90% | 66% | 40% | 对AES-192/256效果显著 |
| Noise-Low (30%) | 100% | 93% | 66% | 对AES-256有一定效果 |
| Baseline | 100% | 100% | 100% | 无防护下三种AES均可完全恢复密钥 |

### 可视化图表

实验生成的图表位于 `results/figures/comparison/` 目录：

- `thesis_success_rate.png` - 三种AES类型攻击成功率对比
- `thesis_snr.png` - 信噪比对比
- `thesis_hit_rate.png` - 缓存命中率对比
- `thesis_leakage_bw.png` - 泄露带宽对比
- `metrics_comparison_*.png` - 各AES类型关键指标对比图
- `comparison_table_*.png` - 完整指标对比表格
