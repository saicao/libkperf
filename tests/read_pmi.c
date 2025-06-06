#include "kperf/kperf.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
int main(int argc, const char * argv[]) {
    int ret;
    uint64_t period [12] ={0};
    
    ret=kpc_get_period(3, period);
    if(ret){
        printf("Failed to get period: %d.\n", ret);
        return 1;
    }
    for(int i = 0; i < 10; i++) {
        printf("period[%d]: %llu\n", i, (unsigned long long)period[i]);
    }
}