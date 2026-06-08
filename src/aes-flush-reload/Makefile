CC = gcc
CFLAGS = -O0 -g -march=native -Wall -fno-stack-protector -Iinclude
LDFLAGS = -lrt -pthread -lm

BUILD_DIR = build
BIN_DIR = $(BUILD_DIR)/bin

ATTACK_AES = $(BIN_DIR)/attack_aes

SRC_DIR = src
INCLUDE_DIR = include

AES_SRC = $(SRC_DIR)/aes.c
ATTACK_COMMON_SRC = $(SRC_DIR)/attack_common.c

.PHONY: all clean

all: attack

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

attack: $(BIN_DIR) $(ATTACK_AES)

$(ATTACK_AES): $(SRC_DIR)/attack_aes.c $(AES_SRC) $(ATTACK_COMMON_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
	mkdir -p $(BIN_DIR)
