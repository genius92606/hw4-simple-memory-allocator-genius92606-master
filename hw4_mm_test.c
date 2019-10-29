#include "hw4_mm_test.h"
int mmap_api=0;
int main(int argc, char *argv[])
{



    // printf("%014p\n",hw_malloc(6)-(unsigned long long)(hw_get_start_brk()));
    // printf("%014p\n",hw_malloc(100)-(unsigned long long)(hw_get_start_brk()));
    // printf("%014p\n",hw_malloc(1000)-(unsigned long long)(hw_get_start_brk()));
    // printf("%014p\n",hw_malloc(10000)-(unsigned long long)(hw_get_start_brk()));
    // printf("%014p\n",hw_get_start_brk());
    // test=hw_malloc(6);
    // printf("%014p\n",test-(unsigned long long)hw_get_start_brk());
    // test=hw_malloc(16);
    // printf("%014p\n",test-(unsigned long long)hw_get_start_brk());
    // test=hw_malloc(16);
    // printf("%014p\n",test-(unsigned long long)hw_get_start_brk());
    // printf("%014p\n",bin[1]);
    // printf("%014p\n",bin[1].prev);
    // printf("%014p\n",bin[1].prev->prev);
    // printf("%014p\n",bin[1].prev->prev->prev);
    // void* temp=hw_malloc(33768);

    // printf("0x%012lx\n",(unsigned long)mmap_all[mmap_api++]);
    // temp=hw_malloc(37864);
    // printf("0x%012lx\n",(unsigned long)mmap_all[mmap_api++]);
    // temp=hw_malloc(35816);
    // printf("0x%012lx\n",(unsigned long)mmap_all[mmap_api++]);

    // printf("why different???\n");
    // printf("%014p\n",mmap_head.next);
    // printf("%014p\n",mmap_head.next->next);
    // printf("%014p\n",mmap_head.next->next->next);
    // printf("%014p\n",mmap_head.next->next->next->next);
    // printf("%llu\n",mmap_head.next->size_and_flag.chunk_size);
    // printf("%llu\n",mmap_head.next->next->size_and_flag.chunk_size);
    // printf("%llu\n",mmap_head.next->next->next->size_and_flag.chunk_size);

    // mmap_show();

    void* temp; //for alloc address
    char str[32];
    char *cmd, *param;
    int i=0;
    int to_print_bin;
    int print_heap_or_mmap=0;    //1 for heap, 2 for mmap, 0 for none of them
    while(fgets(str, sizeof(str), stdin)!=NULL) {

        print_heap_or_mmap=0;


        if (strcmp(str, "\n") == 0)
            continue;
        cmd = strtok(str, "\n");
        cmd = strtok(str, " ");
        param = strtok(NULL, " ");
        if(param==NULL) {
            continue;
        }
        if (!strcmp(cmd, "alloc")) {
            unsigned long long to_alloc_size;
            sscanf(param, "%llu", &to_alloc_size);
            if(to_alloc_size+24<32*1024) {
                printf("0x%012llx\n", (unsigned long long)hw_malloc(to_alloc_size)-(unsigned long long)
                       (hw_get_start_brk()));
            } else {
                temp=(chunk_ptr_t)hw_malloc(to_alloc_size);
                printf("0x%012llx\n",(unsigned long long)mmap_all[mmap_api++]+(unsigned long long)24);
            }

        } else if (!strcmp(cmd, "free")) {
            void *to_free_addr;
            sscanf(param, "%p", &to_free_addr);
            //printf("going to free: %p\n",(void *)heap_initial_addr + (unsigned long long)
            //       to_free_addr);
            printf("%s\n", hw_free((void *)heap_initial_addr + (unsigned long long)
                                   to_free_addr) == 1 ? "success" : "fail");
        } else if(!strcmp(cmd,"print")) {
            if(!strcmp(param,"mmap_alloc_list")) {
                mmap_show();
                print_heap_or_mmap=2;
            } else {
                print_heap_or_mmap=1;
                char *bin, *num;
                bin=strtok(param, "[");
                if(!strcmp(bin, "bin")) {
                    num = strtok(NULL, "]");
                    if(num==NULL)
                        continue;
                    sscanf(num, "%d", &to_print_bin);
                }
            }




        }
        if(print_heap_or_mmap==1) {
            bin_show(&bin[to_print_bin]);
        }



    }

    // mmap_show();
    //bin_show(&bin[10]);
    brk(heap_initial_addr);
    return 0;
}
