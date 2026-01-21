## 在vmscape-main/uARF/src/flush_reload.c中分析了flush and reload的部分代码细节

### 分为7个部分：

1. 初始化实现

```c
UarfFrConfig uarf_fr_init(uint16_t num_slots, uint8_t num_bins, size_t *bin_map) {}
```

2. Flush阶段实现 

```c
void uarf_fr_flush(UarfFrConfig *conf) {}
```

3. 分箱辅助函数

```c
static size_t uarf_get_bin(UarfFrConfig *conf, size_t iteration) {}
```

4. Reload阶段实现

```c
void uarf_fr_reload_binned(UarfFrConfig *conf, size_t iteration) {}
```

5. 结果统计实现

```c
uint64_t uarf_fr_num_hits(UarfFrConfig *conf) {}
```

6. 结果打印实现 

```c
void uarf_fr_print(UarfFrConfig *conf) {}
```

7. 资源释放实现

```c
void uarf_fr_deinit(UarfFrConfig *conf) {}
```





















在vmscape-main/uARF/src/flush_reload.c中分析了flush and reload的部分代码细节

