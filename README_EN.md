**Read this in other languages: [English](README_EN.md), [中文](README.md).**

# Microarch-Side-Channel-Vulnerability

**Processor Microarchitectural Side-Channel Vulnerability Research (TJU 2026 Graduation Thesis)**

## 1. Project Introduction

This project focuses on the security testing of processor microarchitecture side channels, specifically on reproducing and validating publicly disclosed vulnerabilities. The research includes:

1. Summarizing typical side-channel cases and outlining threat models and attack prerequisites.
2. Reproducing at least two types of vulnerability prototypes based on published papers and open-source examples, combining high-precision timing and performance counters to collect side-channel evidence.
3. Designing evaluation metrics and scripts to quantify leakage bandwidth, hit rate, signal-to-noise ratio (SNR), and cross-core/cross-process portability.
4. Verifying the effectiveness of common mitigation measures (such as isolation strategies, cache flushing, compiler or kernel parameters, microcode and firmware updates) and comparing the differences before and after their application.
5. Developing reusable experimental documentation and one-click demonstration scripts to support rapid reproduction.

## 2. Code Repository

**2.1 Cache Timing Attack on DES Using Flush+Reload** Code Repository: https://github.com/JHM2004/des-flush-reload

**2.2 Cache Timing Attack on AES Using Flush+Reload** Code Repository: https://github.com/JHM2004/aes-flush-reload