**Read this in other languages: [English](README.md), [中文](README_zh.md).**

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

