#ifndef HW_MALLOC_H
#define HW_MALLOC_H

#include <stddef.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>

#define MMAP_THRESHOLD 32*1024

typedef struct chunk_header *chunk_ptr_t ;
typedef unsigned long long chunk_size_t ;

typedef struct {
    chunk_size_t chunk_size;
    chunk_size_t pre_chunk_size;
    unsigned int allocated_flag;
    unsigned int mmap_flag;
} chunk_info_t;

struct chunk_header {
    chunk_ptr_t prev;
    chunk_ptr_t next;
    chunk_info_t size_and_flag;
};

typedef struct {
    chunk_ptr_t prev;
    chunk_ptr_t next;
} bin_t;

typedef struct {
    chunk_ptr_t prev;
    chunk_ptr_t next;
} mmap_t;

bin_t bin[11];

mmap_t mmap_head;

chunk_ptr_t mmap_all[100];
void *heap_initial_addr;
void *mmap_regu;
#endif
