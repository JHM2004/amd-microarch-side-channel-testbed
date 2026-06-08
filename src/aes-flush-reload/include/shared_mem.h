/**
 * shared_mem.h - 共享内存管理
 * 
 * 用于victim和attacker进程间共享T表和密文
 * Flush+Reload攻击的核心前提：两个进程必须访问同一物理内存
 */

#ifndef SHARED_MEM_H
#define SHARED_MEM_H

#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdatomic.h>

#include "aes.h"

#define SHM_NAME "/aes_ttables"
#define MAX_CIPHERTEXTS 65536

typedef struct {
    TTable Te0, Te1, Te2, Te3;
    TTable Td0, Td1, Td2, Td3;
    uint8_t Td4[256];
    int initialized;
    
    atomic_int attacker_ready;
    atomic_int encrypt_done;
    atomic_int sample_count;
    uint8_t current_ciphertext[16];
} SharedTTables;

#define SHM_SIZE sizeof(SharedTTables)

static inline SharedTTables* create_shared_memory(void) {
    shm_unlink(SHM_NAME);
    
    int fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        perror("shm_open create");
        return NULL;
    }
    
    if (ftruncate(fd, SHM_SIZE) == -1) {
        perror("ftruncate");
        close(fd);
        return NULL;
    }
    
    void *ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, 
                     MAP_SHARED, fd, 0);
    close(fd);
    
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    
    memset(ptr, 0, SHM_SIZE);
    
    return (SharedTTables*)ptr;
}

static inline SharedTTables* attach_shared_memory(void) {
    int fd = shm_open(SHM_NAME, O_RDWR, 0666);
    if (fd == -1) {
        perror("shm_open attach");
        return NULL;
    }
    
    void *ptr = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, 
                     MAP_SHARED, fd, 0);
    close(fd);
    
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
    
    return (SharedTTables*)ptr;
}

static inline void destroy_shared_memory(SharedTTables *shm) {
    if (shm) {
        munmap(shm, SHM_SIZE);
        shm_unlink(SHM_NAME);
    }
}

static inline void detach_shared_memory(SharedTTables *shm) {
    if (shm) {
        munmap(shm, SHM_SIZE);
    }
}

static inline void reset_sync_state(SharedTTables *shm) {
    atomic_store(&shm->attacker_ready, 0);
    atomic_store(&shm->encrypt_done, 0);
    atomic_store(&shm->sample_count, 0);
}

static inline void signal_attacker_ready(SharedTTables *shm) {
    atomic_store(&shm->attacker_ready, 1);
}

static inline void wait_for_attacker_ready(SharedTTables *shm) {
    while (atomic_load(&shm->attacker_ready) == 0) {
        asm volatile("pause" ::: "memory");
    }
}

static inline void signal_encrypt_done(SharedTTables *shm) {
    atomic_store(&shm->encrypt_done, 1);
}

static inline void wait_for_encrypt(SharedTTables *shm) {
    while (atomic_load(&shm->encrypt_done) == 0) {
        asm volatile("pause" ::: "memory");
    }
}

static inline void clear_encrypt_done(SharedTTables *shm) {
    atomic_store(&shm->encrypt_done, 0);
}

static inline void increment_sample_count(SharedTTables *shm) {
    atomic_fetch_add(&shm->sample_count, 1);
}

static inline int get_sample_count(SharedTTables *shm) {
    return atomic_load(&shm->sample_count);
}

static inline void wait_for_sample(SharedTTables *shm, int target) {
    while (atomic_load(&shm->sample_count) <= target) {
        asm volatile("pause" ::: "memory");
    }
}

static inline void store_current_ciphertext(SharedTTables *shm, const uint8_t *ciphertext) {
    memcpy(shm->current_ciphertext, ciphertext, 16);
}

static inline void get_current_ciphertext(SharedTTables *shm, uint8_t *ciphertext) {
    memcpy(ciphertext, shm->current_ciphertext, 16);
}

#endif
