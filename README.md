## Language

- [English](#english)
- [中文](#中文)

---

### English

# amd-microarch-side-channel-testbed

**Processor Microarchitectural Side-Channel Vulnerability Testbed on AMD Platform (TJU 2026 Graduation Thesis)**

---

## 1. Project Introduction

**Project Focus：**

This project focuses on the security testing of processor microarchitecture side channels, specifically on reproducing and validating publicly disclosed vulnerabilities, using AMD processors as the experimental platform. The research includes:

1. **Summarizing typical side-channel cases** related to the AMD platform, and outlining threat models and attack prerequisites.
2. **Reproducing at least two types of vulnerability prototypes** based on published papers and open-source examples, combining high-precision timing and performance counters to collect side-channel evidence.
3. **Designing simplified evaluation metrics and scripts** to quantify leakage bandwidth, hit rate, signal-to-noise ratio (SNR), and cross-core/cross-process portability.
4. **Verifying the effectiveness of common mitigation measures** (such as isolation strategies, cache flushing, compiler or kernel parameters, microcode and firmware updates) and comparing the differences before and after their application.
5. **Developing reusable experimental documentation** and one-click demonstration scripts to support rapid reproduction on AMD platforms.

**Project Requirements:**

- Possess foundational knowledge of computer systems and architecture.
- Be familiar with operating systems and multi-threaded programming.
- Capable of conducting tests in a Linux environment using high-precision timing, performance counters, and kernel interfaces.
- Prioritize using existing open-source code and data collection tools to configure and reproduce experiments on AMD CPU platforms.
- Implement reproducible demonstrations and basic countermeasure tests for at least two types of side-channel vulnerabilities.
- Deliver quantitative results and visualizations.

---

### 中文

# 处理器微架构侧信道漏洞安全测试技术研究

**基于 AMD 平台的处理器微架构侧信道漏洞测试平台（天津大学 2026 届毕业设计）**

---

## 1. 课题介绍

**课题定位：**

本课题聚焦处理器微架构测信道的安全测试，面向已有公开漏洞的复现与验证，平台为基于AMD处理器。研究内容包括：

1）整理AMD平台相关的典型测信道案例，梳理威胁模型与攻击前提；

2）基于公开论文与开源样例，复现至少两类漏洞原型，结合高精度计时与性能计数器收集侧证据；

3）设计简化评测指标与脚本，量化泄露带宽、命中率、信噪比与跨核/跨进程可迁移性；

4）验证常见缓解措施（隔离策略、缓存冲洗、编译器或内核参数、微码与固件更新）的效果，对比前后差异；

5）形成可复用的实验说明与一键化演示，支持在AMD平台上快速复现。

**项目要求：**

- 具备计算机系统与体系结构基础，熟悉操作系统与多线程编程；
- 能在Linux环境下使用高精度计时、性能计数器与内核接口开展测试；
- 优先使用现成开源代码与数据采集工具，完成在AMD CPU平台上的配置与复现；
- 实现至少两类测信道漏洞的可复现演示与基本对抗测试，输出量化结果与可视化图表。

---

