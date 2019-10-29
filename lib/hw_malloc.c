#include <stdlib.h>
#include <stdio.h>
#include "hw_malloc.h"

int first_alloc = 1;
int first_mmap=1;
int i=0;
int mmap_total=0;
size_t good_size(size_t bytes)
{
    int power = 1;
    while(power<bytes) {
        power*=2;
    }
    return power;
}

void bin_init(bin_t *bin_)
{
    bin_->prev = (chunk_ptr_t)bin_;
    bin_->next = (chunk_ptr_t)bin_;
}

void mmap_init(mmap_t *mmap_)
{
    mmap_->prev = (chunk_ptr_t)mmap_;
    mmap_->next = (chunk_ptr_t)mmap_;
}

void bin_add_chunk(unsigned int bin_num, chunk_ptr_t chunk_ptr)
{

    chunk_ptr_t bin_compare = bin[bin_num].next;
    while(bin_compare!=(chunk_ptr_t)&bin[bin_num]) {
        if((unsigned long long)bin_compare < (unsigned long long)chunk_ptr) break;
        else bin_compare = bin_compare->next;
    }

    bin_compare->prev->next = chunk_ptr;
    chunk_ptr->next = bin_compare;
    chunk_ptr->prev = bin_compare->prev;
    bin_compare->prev = chunk_ptr;
}

void mmap_add(chunk_ptr_t chunk_ptr)
{
    chunk_ptr_t compare=mmap_head.next;

    while(compare!=(chunk_ptr_t)&mmap_head) {
        //printf("size: %llu\n",(unsigned long long)compare->size_and_flag.chunk_size);
        if((unsigned int)compare->size_and_flag.chunk_size>(unsigned int)chunk_ptr->size_and_flag.chunk_size) break;
        else {
            compare=compare->next;
        }
    }
    // chunk_ptr_t front=compare->prev;
    // chunk_ptr_t back=compare->next;

    //front->next=chunk_ptr;
    compare->prev->next = chunk_ptr;
    chunk_ptr->next = compare;
    //chunk_ptr->prev = front;
    chunk_ptr->prev = compare->prev;
    compare->prev = chunk_ptr;

}

void bin_del_chunk(chunk_ptr_t chunk_ptr)
{
    chunk_ptr->prev->next = chunk_ptr->next;
    chunk_ptr->next->prev = chunk_ptr->prev;
}

void mmap_del(chunk_ptr_t chunk_ptr)
{
    chunk_ptr->prev->next = chunk_ptr->next;
    chunk_ptr->next->prev = chunk_ptr->prev;
}

void chunk_init(chunk_ptr_t chunk_ptr)
{
    chunk_ptr->size_and_flag.chunk_size = 0;
    chunk_ptr->size_and_flag.pre_chunk_size = 0;
    chunk_ptr->size_and_flag.allocated_flag = 0;
    chunk_ptr->size_and_flag.mmap_flag = 0;
}

void chunk_split(unsigned int bin_num, size_t bytes)
{
    chunk_ptr_t current = bin[bin_num].prev;

    unsigned long long new_size;
    while(current->size_and_flag.chunk_size > bytes) {
        new_size = current->size_and_flag.chunk_size / 2;

        bin_del_chunk(current);

        chunk_ptr_t new_chunk = (chunk_ptr_t)((void*)current + new_size);
        chunk_init(new_chunk);

        bin_num--;

        bin_add_chunk(bin_num, current);
        bin_add_chunk(bin_num, new_chunk);

        current->size_and_flag.chunk_size = new_size;
        new_chunk->size_and_flag.chunk_size = new_size;
        current->size_and_flag.pre_chunk_size = new_size;
        new_chunk->size_and_flag.pre_chunk_size = new_size;

        current = bin[bin_num].prev;
    }
}

void chunk_merge(unsigned int bin_num, chunk_ptr_t chunk1, chunk_ptr_t chunk2)
{
    unsigned long long size_bef_merge = chunk2->size_and_flag.chunk_size;

    //remove chunk high&low
    bin_del_chunk(chunk1);
    bin_del_chunk(chunk2);

    bin_add_chunk(bin_num+1, chunk2);

    chunk2->size_and_flag.chunk_size = size_bef_merge*2;
    chunk2->size_and_flag.pre_chunk_size = size_bef_merge*2;

}

chunk_ptr_t heap_alloc(size_t bytes)
{
    bytes = good_size(bytes);
    if(bytes<64)
        bytes=64;
    if(first_alloc) {
        heap_initial_addr = sbrk(64*1024);
        chunk_ptr_t new_free_chunk_ptr1 = (chunk_ptr_t)((void*)heap_initial_addr + (unsigned long long)24);
        new_free_chunk_ptr1->size_and_flag.chunk_size = 64*1024/2;
        new_free_chunk_ptr1->size_and_flag.pre_chunk_size = 0;
        new_free_chunk_ptr1->size_and_flag.allocated_flag = 0;
        new_free_chunk_ptr1->size_and_flag.mmap_flag = 0;

        chunk_ptr_t new_free_chunk_ptr2 = (chunk_ptr_t)((void*)heap_initial_addr + (unsigned long long)(64*1024/2 + 24));
        new_free_chunk_ptr2->size_and_flag.chunk_size = 64*1024/2;
        new_free_chunk_ptr2->size_and_flag.pre_chunk_size = 0;
        new_free_chunk_ptr2->size_and_flag.allocated_flag = 0;
        new_free_chunk_ptr2->size_and_flag.mmap_flag = 0;

        for(int i = 0; i<11; i++) {
            bin_init(&bin[i]);
        }
        bin_add_chunk(10, new_free_chunk_ptr2);
        bin_add_chunk(10, new_free_chunk_ptr1);

        first_alloc = 0;
    }

    chunk_ptr_t chunk_to_alloc;
    //find the suitable bin
    int n = bytes;
    int p = 0;
    while(n!=1) {
        n/=2;
        p++;
    }
    int bin_num = p-5;
    if (bin_num<0) {
        bin_num = 0;
        bytes = 32;
    }
    while(bin_num<11) {
        if (bin[bin_num].next != (chunk_ptr_t)&bin[bin_num]) break;
        else bin_num++;
    }

    if(bin_num>=11) return NULL;

    chunk_split(bin_num, bytes);

    bin_num = p-5;
    if(bin_num<0)bin_num = 0;

    chunk_to_alloc = bin[bin_num].prev;  //choose the lowest address
    bin_del_chunk(chunk_to_alloc);
    chunk_to_alloc->size_and_flag.allocated_flag = 1;

    return chunk_to_alloc;
}

chunk_ptr_t mmap_alloc(size_t bytes)
{
    if(first_mmap) {
        mmap_init(&mmap_head);
        first_mmap=0;
    }
    char * chunk_mmap_address;  //store the address of mmap
    chunk_mmap_address = mmap(
                             NULL,
                             bytes,
                             PROT_READ|PROT_WRITE|PROT_EXEC,
                             MAP_ANON|MAP_SHARED,0,0          // to a private block of hardware memory

                         );
    if(chunk_mmap_address==MAP_FAILED) {
        perror("Could not mmap");
        return NULL;
    }
    chunk_ptr_t chunk_mmap=(chunk_ptr_t)chunk_mmap_address;
    chunk_mmap->size_and_flag.chunk_size=bytes;
    chunk_mmap->size_and_flag.pre_chunk_size=0;
    chunk_mmap->size_and_flag.allocated_flag=1;
    chunk_mmap->size_and_flag.mmap_flag=1;
    mmap_add(chunk_mmap);
    mmap_all[mmap_total]=chunk_mmap;
    mmap_total++;
    //printf("inside mmap_alloc: x0%012lx\n",chunk_mmap);
    return chunk_mmap;
}

void *hw_malloc(size_t bytes)
{
    if(bytes<0)
        return NULL;
    bytes+=24;
    if(bytes<MMAP_THRESHOLD) {
        chunk_ptr_t allocated;
        allocated = heap_alloc(good_size(bytes));
        if(allocated==NULL) return NULL;
        else return (void*)allocated;
    } else {
        chunk_ptr_t allocated;
        allocated = mmap_alloc(bytes);
        if(allocated==NULL) return NULL;
        else {
            //printf("inside malloc: %014p\n",allocated);
            return (void*)allocated;
        }

    }

}

int hw_free(void *mem)
{
    chunk_ptr_t chunk_ptr = (chunk_ptr_t)mem;

    if(chunk_ptr->size_and_flag.mmap_flag==1) {
        mmap_del(chunk_ptr);
        mmap_total--;
        int unmap_result=munmap(chunk_ptr,chunk_ptr->size_and_flag.chunk_size);
        if(unmap_result!=0) {
            perror("Could not munmap");
            return 0;
        }
        return 1;
    }
    if(chunk_ptr->size_and_flag.allocated_flag==1) {

        unsigned long long size = chunk_ptr->size_and_flag.chunk_size;
        int p = 0;
        while(size!=1) {
            size/=2;
            p++;
        }
        int bin_num = p-5;
        bin_add_chunk(bin_num, chunk_ptr);
        chunk_ptr->size_and_flag.allocated_flag = 0;

        while((chunk_ptr_t)chunk_ptr->next->next!=chunk_ptr&&bin_num<10) {
            if(chunk_ptr->next != (chunk_ptr_t)&bin[bin_num] && chunk_ptr->next->size_and_flag.allocated_flag==0
                    && chunk_ptr == (chunk_ptr_t)((void*)chunk_ptr->next + chunk_ptr->next->size_and_flag.chunk_size)) {
                chunk_merge(bin_num, chunk_ptr, chunk_ptr->next);
                chunk_ptr = chunk_ptr->next;
            } else if (chunk_ptr->prev != (chunk_ptr_t)&bin[bin_num] && chunk_ptr->prev->size_and_flag.allocated_flag==0
                       && chunk_ptr->prev == (chunk_ptr_t)((void*)chunk_ptr + chunk_ptr->size_and_flag.chunk_size)) chunk_merge(bin_num, chunk_ptr->prev, chunk_ptr);
            else break;
            bin_num++;
        }

        return 1;
    } else return 0;
}

void *hw_get_start_brk(void)
{
    return heap_initial_addr;
}


void bin_show(bin_t *bin_)
{
    chunk_ptr_t current = bin_->prev;
    while(current != (chunk_ptr_t)bin_) {
        printf("0x%012lx", (unsigned long)current - (unsigned long)heap_initial_addr-(unsigned long)24);
        printf("--------%llu\n", (unsigned long long )current->size_and_flag.chunk_size);
        current = current->prev;
    }
}
void mmap_show()
{
    chunk_ptr_t current=mmap_head.next;
    for(i=0; i<mmap_total; i++) {
        printf("0x%012lx", (unsigned long)current);
        printf("--------%llu\n", current->size_and_flag.chunk_size);
        current = current->next;
    }
}

