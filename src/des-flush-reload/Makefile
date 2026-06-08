CC = gcc
CFLAGS = -O0 -g -march=native -Wall -fPIC -Wno-unused-result -fno-stack-protector
LDFLAGS = -ldl -pthread -lm

# 构建目录
BUILD_DIR = build
SRC_DIR = src
INCLUDE_DIR = include

# 创建构建目录
$(shell mkdir -p $(BUILD_DIR))

# 源文件
DES_SRC = $(SRC_DIR)/des.c
MAIN_SRC = $(SRC_DIR)/main.c
SPY_SRC = $(SRC_DIR)/spy.c
METRICS_SRC = $(SRC_DIR)/metrics.c
MITIGATION_SRC = $(SRC_DIR)/mitigation.c
TEST_MITIGATION_SRC = $(SRC_DIR)/test_mitigation.c
LOADER_SRC = $(SRC_DIR)/utils/des_loader.c
OUTPUT_SRC = $(SRC_DIR)/output.c
STATS_SRC = $(SRC_DIR)/statistics.c

# 最终目标
TARGETS = $(BUILD_DIR)/libdes.so $(BUILD_DIR)/spy $(BUILD_DIR)/test_mitigation

all: $(TARGETS)

# 共享库：保持-O0避免编译器优化掉内存访问（对侧信道很重要）
$(BUILD_DIR)/libdes.so: $(DES_SRC)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -shared -o $@ $<

# Spy程序：包含main.c, spy.c, metrics.c, mitigation.c和其他模块
$(BUILD_DIR)/spy: $(MAIN_SRC) $(SPY_SRC) $(METRICS_SRC) $(MITIGATION_SRC) $(LOADER_SRC) $(OUTPUT_SRC) $(STATS_SRC)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -no-pie -o $@ $^ $(LDFLAGS)

# Mitigation测试程序
$(BUILD_DIR)/test_mitigation: $(TEST_MITIGATION_SRC) $(MITIGATION_SRC) $(SPY_SRC) $(METRICS_SRC) $(LOADER_SRC) $(OUTPUT_SRC) $(STATS_SRC)
	$(CC) $(CFLAGS) -I$(INCLUDE_DIR) -no-pie -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)/*.so $(BUILD_DIR)/spy $(BUILD_DIR)/*.o

.PHONY: all clean
