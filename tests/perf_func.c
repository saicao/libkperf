#include "kperf/kperf.h"
#include <stdlib.h>
#include <stdio.h>

#define EVENT_NAME_MAX 8
typedef struct {
    const char *alias; /// name for print
    const char *names[EVENT_NAME_MAX]; /// name from pmc db
} event_alias;
/// Event names from /usr/share/kpep/<name>.plist
static const event_alias profile_events[] = {
    {   "cycles", {
            "FIXED_CYCLES",                 // Apple A7-A15
            "CPU_CLK_UNHALTED.THREAD",      // Intel Core 1th-10th
            "CPU_CLK_UNHALTED.CORE",        // Intel Yonah, Merom
    }},
    {   "instructions", {
            "FIXED_INSTRUCTIONS",           // Apple A7-A15
            "INST_RETIRED.ANY"              // Intel Yonah, Merom, Core 1th-10th
    }},
    {   "branches", {
            "INST_BRANCH",                  // Apple A7-A15
            "BR_INST_RETIRED.ALL_BRANCHES", // Intel Core 1th-10th
            "INST_RETIRED.ANY",             // Intel Yonah, Merom
    }},
    {   "branch-misses", {
            "BRANCH_MISPRED_NONSPEC",       // Apple A7-A15, since iOS 15, macOS 12
            "BRANCH_MISPREDICT",            // Apple A7-A14
            "BR_MISP_RETIRED.ALL_BRANCHES", // Intel Core 2th-10th
            "BR_INST_RETIRED.MISPRED",      // Intel Yonah, Merom
    }},
};

static kpep_event *get_event(kpep_db *db, const event_alias *alias) {
    for (usize j = 0; j < EVENT_NAME_MAX; j++) {
        const char *name = alias->names[j];
        if (!name) break;
        kpep_event *ev = NULL;
        if (kpep_db_event(db, name, &ev) == 0) {
            return ev;
        }
    }
    return NULL;
}



// -----------------------------------------------------------------------------
// Demo 1: profile a function in current thread
// -----------------------------------------------------------------------------



static void profile_func(void) {
    for (u32 i = 0; i < 100000; i++) {
        u32 r = arc4random();
        if (r % 2) arc4random();
    }
}

int main(int argc, const char * argv[]) {
    int ret = 0;
    
    // load dylib
    
    // check permission
    int force_ctrs = 0;
    if (kpc_force_all_ctrs_get(&force_ctrs)) {
        printf("Permission denied, xnu/kpc requires root privileges.\n");
        return 1;
    }
    
    // load pmc db
    kpep_db *db = NULL;
    if ((ret = kpep_db_create(NULL, &db))) {
        printf("Error: cannot load pmc database: %d.\n", ret);
        return 1;
    }
    printf("loaded db: %s (%s)\n", db->name, db->marketing_name);
    printf("number of fixed counters: %zu\n", db->fixed_counter_count);
    printf("number of configurable counters: %zu\n", db->config_counter_count);
    
    // create a config
    kpep_config *cfg = NULL;
    if ((ret = kpep_config_create(db, &cfg))) {
        printf("Failed to create kpep config: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    if ((ret = kpep_config_force_counters(cfg))) {
        printf("Failed to force counters: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    
    // get events
    const usize ev_count = sizeof(profile_events) / sizeof(profile_events[0]);
    kpep_event *ev_arr[ev_count] = { 0 };
    for (usize i = 0; i < ev_count; i++) {
        const event_alias *alias = profile_events + i;
        ev_arr[i] = get_event(db, alias);
        if (!ev_arr[i]) {
            printf("Cannot find event: %s.\n", alias->alias);
            return 1;
        }
    }
    
    // add event to config
    for (usize i = 0; i < ev_count; i++) {
        kpep_event *ev = ev_arr[i];
        if ((ret = kpep_config_add_event(cfg, &ev, 0, NULL))) {
            printf("Failed to add event: %d (%s).\n",
                   ret, kpep_config_error_desc(ret));
            return 1;
        }
    }
    
    // prepare buffer and config
    u32 classes = 0;
    usize reg_count = 0;
    kpc_config_t regs[KPC_MAX_COUNTERS] = { 0 };
    usize counter_map[KPC_MAX_COUNTERS] = { 0 };
    u64 counters_0[KPC_MAX_COUNTERS] = { 0 };
    u64 counters_1[KPC_MAX_COUNTERS] = { 0 };
    if ((ret = kpep_config_kpc_classes(cfg, &classes))) {
        printf("Failed get kpc classes: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    if ((ret = kpep_config_kpc_count(cfg, &reg_count))) {
        printf("Failed get kpc count: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    if ((ret = kpep_config_kpc_map(cfg, counter_map, sizeof(counter_map)))) {
        printf("Failed get kpc map: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    if ((ret = kpep_config_kpc(cfg, regs, sizeof(regs)))) {
        printf("Failed get kpc registers: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    // for(int i=0;i<KPC_MAX_COUNTERS;i++) {
    //     printf("regs[%d] = %llx \n", i, regs[i]);
    // }
    // for(int i=0;i<KPC_MAX_COUNTERS;i++) {
    //     printf("counter_map[%d] = %zu \n", i, counter_map[i]);
    // }
    
    // set config to kernel
    if ((ret = kpc_force_all_ctrs_set(1))) {
        printf("Failed force all ctrs: %d.\n", ret);
        return 1;
    }
    if ((classes & KPC_CLASS_CONFIGURABLE_MASK) && reg_count) {
        if ((ret = kpc_set_config(classes, regs))) {
            printf("Failed set kpc config: %d.\n", ret);
            return 1;
        }
    }
    
    // start counting
    if ((ret = kpc_set_counting(classes))) {
        printf("Failed set counting: %d.\n", ret);
        return 1;
    }
    if ((ret = kpc_set_thread_counting(classes))) {
        printf("Failed set thread counting: %d.\n", ret);
        return 1;
    }
    
    // get counters before
    if ((ret = kpc_get_thread_counters(0, KPC_MAX_COUNTERS, counters_0))) {
        printf("Failed get thread counters before: %d.\n", ret);
        return 1;
    }
    
    // code to be measured
    profile_func();
    
    // get counters after
    if ((ret = kpc_get_thread_counters(0, KPC_MAX_COUNTERS, counters_1))) {
        printf("Failed get thread counters after: %d.\n", ret);
        return 1;
    }
    
    // stop counting
    kpc_set_counting(0);
    kpc_set_thread_counting(0);
    kpc_force_all_ctrs_set(0);
    
    // result
    printf("counters value:\n");
    for (usize i = 0; i < ev_count; i++) {
        const event_alias *alias = profile_events + i;
        usize idx = counter_map[i];
        u64 val = counters_1[idx] - counters_0[idx];
        printf("%14s: %llu\n", alias->alias, val);
    }
    
    // TODO: free memory
    return 0;
}