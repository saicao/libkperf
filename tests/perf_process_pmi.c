#include "kperf/kperf.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
// -----------------------------------------------------------------------------
// Demo 2: profile a select process
// -----------------------------------------------------------------------------

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

/// Target process pid, -1 for all thread.
static int target_pid = -1;

/// Profile time in seconds.
static double total_profile_time = 1;

/// Profile sampler period in seconds (default 10ms).
static double sample_period = 0.001;

static double get_timestamp(void) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return (double)now.tv_sec + (double)now.tv_usec / (1000.0 * 1000.0);
}

// debugid sub-classes and code from xnu source
#define PERF_KPC        (6)
#define PERF_KPC_DATA_THREAD   (8)

int main(int argc, const char * argv[]) {
    int ret = 0;
    if(argc == 2) {
        int pid = atoi(argv[1]);
        if(pid!=0){
            target_pid = pid;
        } else {
            printf("Invalid pid: %s\n", argv[1]);
            return 1;
        }
    } 

    
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
    printf("CPU tick frequency: %llu\n", (unsigned long long)kperf_tick_frequency());
    
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
    if ((ret = kpep_config_kpc_classes(cfg, &classes))) {
        printf("Failed get kpc classes: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    printf("kpc classes: 0x%x\n", classes);
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
    for(usize i = 0; i < KPC_MAX_COUNTERS; i++) {
        printf("counter_map[%zu] = %zu \n", i, counter_map[i]);
    }
    if ((ret = kpep_config_kpc(cfg, regs, sizeof(regs)))) {
        printf("Failed get kpc registers: %d (%s).\n",
               ret, kpep_config_error_desc(ret));
        return 1;
    }
    
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
    
    u32 counter_count = kpc_get_counter_count(classes);
    if (counter_count == 0) {
        printf("Failed no counter\n");
        return 1;
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
   
    
    // // action id and timer id
    u32 actionid = 1;
    u32 timerid = 1;
    
    // alloc action and timer ids
    if ((ret = kperf_action_count_set(KPERF_ACTION_MAX))) {
        printf("Failed set action count: %d.\n", ret);
        return 1;
    }
    if ((ret = kperf_timer_count_set(KPERF_TIMER_MAX))) {
        printf("Failed set timer count: %d.\n", ret);
        return 1;
    }
    
    // set what to sample: PMC per thread
    if ((ret = kperf_action_samplers_set(actionid, KPERF_SAMPLER_PMC_THREAD))) {
        printf("Failed set sampler type: %d.\n", ret);
        return 1;
    }
    // set filter process
    if ((ret = kperf_action_filter_set_by_pid(actionid, target_pid))) {
        printf("Failed set filter pid: %d.\n", ret);
        return 1;
    }
    
    // setup PET (Profile Every Thread), start sampler
    u64 tick = kperf_ns_to_ticks(sample_period * 1000000000ul);
    if ((ret = kperf_timer_period_set(actionid, 0))) {
        printf("Failed set timer period: %d.\n", ret);
        return 1;
    }
    if ((ret = kperf_timer_action_set(actionid, timerid))) {
        printf("Failed set timer action: %d.\n", ret);
        return 1;
    }
    if ((ret = kperf_timer_pet_set(timerid))) {
        printf("Failed set timer PET: %d.\n", ret);
        return 1;
    }
    
    if ((ret = kperf_lightweight_pet_set(1))) {
        printf("Failed set lightweight PET: %d.\n", ret);
        return 1;
    }
    if ((ret = kperf_sample_set(1))) {
        printf("Failed start sample: %d.\n", ret);
        return 1;
    }
    
    // reset kdebug/ktrace
    if ((ret = kdebug_reset())) {
        printf("Failed reset kdebug: %d.\n", ret);
        return 1;
    }
    
    int nbufs = 1000000;
    if ((ret = kdebug_trace_setbuf(nbufs))) {
        printf("Failed setbuf: %d.\n", ret);
        return 1;
    }
    if ((ret = kdebug_reinit())) {
        printf("Failed init kdebug buffer: %d.\n", ret);
        return 1;
    }
    
    // set trace filter: only log PERF_KPC_DATA_THREAD
    // kd_regtype kdr = { 0 };
    // kdr.type = KDBG_VALCHECK;
    // kdr.value1 = KDBG_EVENTID(DBG_MACH, DBG_MACH_EXCP_INTR, DBG_INTR_TYPE_PMI);
    // if ((ret = kdebug_setreg(&kdr))) {
    //     printf("Failed set kdebug filter: %d.\n", ret);
    // }

    uint64_t period [10] ={0};
    
    period[counter_map[1]]=10000000;
    ret=kpc_set_period(classes,period);
    if(ret){
        printf("Failed to set period: %d.\n", ret);
        return 1;
    }
    ret=kpc_get_period(classes, period);
    if(ret){
        printf("Failed to get period: %d.\n", ret);
        return 1;
    }
    for(int i = 0; i < 10; i++) {
        printf("period[%d]: %llu\n", i, (unsigned long long)period[i]);
    }
    // start trace
    if ((ret = kdebug_trace_enable(1))) {
        printf("Failed enable kdebug trace: %d.\n", ret);
    }
    
    
    
    
    // sample and get buffers
    usize buf_capacity = nbufs * 2;
    kd_buf *buf_hdr = (kd_buf *)malloc(sizeof(kd_buf) * buf_capacity);
    kd_buf *buf_cur = buf_hdr;
    kd_buf *buf_end = buf_hdr + buf_capacity;
    
    double begin = get_timestamp();
    while (buf_hdr) {
        // wait for more buffer
        usleep(2 * sample_period * 1000000);
        
        // expand local buffer for next read
        if (buf_end - buf_cur < nbufs) {
            usize new_capacity = buf_capacity * 2;
            kd_buf *new_buf = (kd_buf *)realloc(buf_hdr, sizeof(kd_buf) * new_capacity);
            if (!new_buf) {
                free(buf_hdr);
                buf_hdr = NULL;
                break;
            }
            buf_capacity = new_capacity;
            buf_cur = new_buf + (buf_cur - buf_hdr);
            buf_end = new_buf + (buf_end - buf_hdr);
            buf_hdr = new_buf;
        }
        
        // read trace buffer from kernel
        usize count = 0;
        kdebug_trace_read(buf_cur, sizeof(kd_buf) * nbufs, &count);
        printf("read %zu trace entries\n", count);
        for (kd_buf *buf = buf_cur, *end = buf_cur + count; buf < end; buf++) {
            u32 debugid = buf->debugid;
            u32 cls = KDBG_EXTRACT_CLASS(debugid);
            u32 subcls = KDBG_EXTRACT_SUBCLASS(debugid);
            u32 code = KDBG_EXTRACT_CODE(debugid);
            
            // keep only thread PMC data
            // if (cls != DBG_PERF) {};
            // if (subcls != PERF_KPC) continue;
            // if (code != PERF_KPC_DATA_THREAD) continue;

            printf("debugid: 0x%x, cls: %d, subcls: 0x%x, code: 0x%x\n", debugid, cls, subcls, code);
            // if(subcls != DBG_MACH_EXCP_INTR) continue; 
            // if(code != DBG_INTR_TYPE_IPI) continue;
            memmove(buf_cur, buf, sizeof(kd_buf));
            buf_cur++;
        }
        
        // stop when time is up
        double now = get_timestamp();
        if (now - begin > total_profile_time + sample_period) break;
    }
  
    
    // stop tracing
    kdebug_trace_enable(0);
    kdebug_reset();
    kperf_sample_set(0);
    kperf_lightweight_pet_set(0);
    
    // stop counting
    kpc_set_counting(0);
    kpc_set_thread_counting(0);
    kpc_force_all_ctrs_set(0);
    int count=kpc_get_thread_counting();
    printf("thread counting: %d\n", count);
    //open file 
    FILE *fp = fopen("perf_process_pmi.trace", "w");
    if (!fp) {
        printf("Failed to open output file.\n");
        return 1;
    }
    
    // aggregate thread PMC data
    if (!buf_hdr) {
        printf("Failed to allocate memory for trace log.\n");
        return 1;
    }
    if (buf_cur - buf_hdr == 0) {
        printf("No thread PMC data collected.\n");
        return 1;
    }
    
    typedef struct  {
        u32 tid;
        u64 timestamp_0;
        u64 timestamp_1;
        u64 counters_0[KPC_MAX_COUNTERS];
        u64 counters_1[KPC_MAX_COUNTERS];
    } kpc_thread_data;
    
    usize thread_capacity = 32;
    usize thread_count = 0;
    kpc_thread_data *thread_data = (kpc_thread_data *)malloc(thread_capacity * sizeof(kpc_thread_data));
    if (!thread_data) {
        printf("Failed to allocate memory for aggregate log.\n");
        return 1;
    }
    uint64_t last_instr_count=0;
    for (kd_buf *buf = buf_hdr; buf < buf_cur; buf++) {
        u32 func = buf->debugid & KDBG_FUNC_MASK;
        if (func != DBG_FUNC_START) continue;
        u32 tid = (u32)buf->arg5;
        if (!tid) continue;
        
        // read one counter log
        u32 ci = 0;
        u64 counters[KPC_MAX_COUNTERS];
        counters[ci++] = buf->arg1;
        counters[ci++] = buf->arg2;
        counters[ci++] = buf->arg3;
        counters[ci++] = buf->arg4;
        if (ci < counter_count) {
            // counter count larger than 4
            // values are split into multiple buffer entities
            for (kd_buf *buf2 = buf + 1; buf2 < buf_cur; buf2++) {
                u32 tid2 = (u32)buf2->arg5;
                if (tid2 != tid) break;
                u32 func2 = buf2->debugid & KDBG_FUNC_MASK;
                if (func2 == DBG_FUNC_START) break;
                if (ci < counter_count) counters[ci++] = buf2->arg1;
                if (ci < counter_count) counters[ci++] = buf2->arg2;
                if (ci < counter_count) counters[ci++] = buf2->arg3;
                if (ci < counter_count) counters[ci++] = buf2->arg4;
                if (ci == counter_count) break;
            }
        }
        if (ci != counter_count) continue; // not enough counters, maybe truncated
        
        
        //save into file 
        // printf("%lld\n",counters[counter_map[1]]-last_instr_count);
        last_instr_count = counters[counter_map[1]];
        fprintf(fp, "cpu %d tid: %u, timestamp: %llu, counters: ", buf->cpuid,tid, (unsigned long long)buf->timestamp);
        // for (u32 i = 0; i < ci; i++) {
        //     fprintf(fp, "%llu ", (unsigned long long)counters[i]); 
        // }
        for(u32 i = 0; i < ev_count; i++) {
            fprintf(fp, "%s: %llu ", profile_events[i].alias, (unsigned long long)counters[counter_map[i]]);
        }
        fprintf(fp, "\n");

        // printf("all threads: %ld\n", thread_count);
        // for (usize i = 0; i < ev_count; i++) {
        //     const event_alias *alias = profile_events + i;
        //     u64 val = counters_sum[counter_map[i]];
        //     printf("%14s: %llu\n", alias->alias, val);
        // }

    }
    fclose(fp);
    
    
    
    // TODO: free memory
    return 0;
}