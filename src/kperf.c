#include "kperf/kperf.h"
#include <dlfcn.h>          // for dlopen() and dlsym()
#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>     // for sysctl()
#include <unistd.h>         // for usleep()
static int (*kpc_cpu_string_internal)(char *buf, usize buf_size);
static u32 (*kpc_pmu_version_internal)(void);
static u32 (*kpc_get_counting_internal)(void);
static int (*kpc_set_counting_internal)(u32 classes);
static u32 (*kpc_get_thread_counting_internal)(void);
static int (*kpc_set_thread_counting_internal)(u32 classes);
static u32 (*kpc_get_config_count_internal)(u32 classes);
static int (*kpc_get_config_internal)(u32 classes, kpc_config_t *config);
static int (*kpc_set_config_internal)(u32 classes, kpc_config_t *config);
static u32 (*kpc_get_counter_count_internal)(u32 classes);
static int (*kpc_get_cpu_counters_internal)(bool all_cpus, u32 classes, int *curcpu, u64 *buf);
static int (*kpc_get_thread_counters_internal)(u32 tid, u32 buf_count, u64 *buf);
static int (*kpc_force_all_ctrs_set_internal)(int val);
static int (*kpc_force_all_ctrs_get_internal)(int *val_out);
static int (*kperf_action_count_set_internal)(u32 count);
static int (*kperf_action_count_get_internal)(u32 *count);
static int (*kperf_action_samplers_set_internal)(u32 actionid, u32 sample);
static int (*kperf_action_samplers_get_internal)(u32 actionid, u32 *sample);
static int (*kperf_action_filter_set_by_task_internal)(u32 actionid, i32 port);
static int (*kperf_action_filter_set_by_pid_internal)(u32 actionid, i32 pid);
static int (*kperf_timer_count_set_internal)(u32 count);
static int (*kperf_timer_count_get_internal)(u32 *count);
static int (*kperf_timer_period_set_internal)(u32 actionid, u64 tick);
static int (*kperf_timer_period_get_internal)(u32 actionid, u64 *tick);
static int (*kperf_timer_action_set_internal)(u32 actionid, u32 timerid);
static int (*kperf_timer_action_get_internal)(u32 actionid, u32 *timerid);
static int (*kperf_timer_pet_set_internal)(u32 timerid);
static int (*kperf_timer_pet_get_internal)(u32 *timerid);
static int (*kperf_sample_set_internal)(u32 enabled);
static int (*kperf_sample_get_internal)(u32 *enabled);
static int (*kperf_reset_internal)(void);
static u64 (*kperf_ns_to_ticks_internal)(u64 ns);
static u64 (*kperf_ticks_to_ns_internal)(u64 ticks);
static u64 (*kperf_tick_frequency_internal)(void);
static int (*kpep_config_create_internal)(kpep_db *db, kpep_config **cfg_ptr);
static void (*kpep_config_free_internal)(kpep_config *cfg);
static int (*kpep_config_add_event_internal)(kpep_config *cfg, kpep_event **ev_ptr, u32 flag, u32 *err);
static int (*kpep_config_remove_event_internal)(kpep_config *cfg, usize idx);
static int (*kpep_config_force_counters_internal)(kpep_config *cfg);
static int (*kpep_config_events_count_internal)(kpep_config *cfg, usize *count_ptr);
static int (*kpep_config_events_internal)(kpep_config *cfg, kpep_event **buf, usize buf_size);
static int (*kpep_config_kpc_internal)(kpep_config *cfg, kpc_config_t *buf, usize buf_size);
static int (*kpep_config_kpc_count_internal)(kpep_config *cfg, usize *count_ptr);
static int (*kpep_config_kpc_classes_internal)(kpep_config *cfg, u32 *classes_ptr);
static int (*kpep_config_kpc_map_internal)(kpep_config *cfg, usize *buf, usize buf_size);
static int (*kpep_db_create_internal)(const char *name, kpep_db **db_ptr);
static void (*kpep_db_free_internal)(kpep_db *db);
static int (*kpep_db_name_internal)(kpep_db *db, const char **name);
static int (*kpep_db_aliases_count_internal)(kpep_db *db, usize *count);
static int (*kpep_db_aliases_internal)(kpep_db *db, const char **buf, usize buf_size);
static int (*kpep_db_counters_count_internal)(kpep_db *db, u8 classes, usize *count);
static int (*kpep_db_events_count_internal)(kpep_db *db, usize *count);
static int (*kpep_db_events_internal)(kpep_db *db, kpep_event **buf, usize buf_size);
static int (*kpep_db_event_internal)(kpep_db *db, const char *name, kpep_event **ev_ptr);
static int (*kpep_event_name_internal)(kpep_event *ev, const char **name_ptr);
static int (*kpep_event_alias_internal)(kpep_event *ev, const char **alias_ptr);
static int (*kpep_event_description_internal)(kpep_event *ev, const char **str_ptr);
static int (*kpc_get_period_internal)(u32 classes, u64 *period);
static int (*kpc_set_period_internal)(u32 classes, u64 *period);
int kperf_lightweight_pet_get(u32 *enabled) {
    if (!enabled) return -1;
    usize size = 4;
    return sysctlbyname("kperf.lightweight_pet", enabled, &size, NULL, 0);
}

int kperf_lightweight_pet_set(u32 enabled) {
    return sysctlbyname("kperf.lightweight_pet", NULL, NULL, &enabled, 4);
}


typedef struct {
    const char *name;
    void **impl;
} lib_symbol;

#define lib_nelems(x)  (sizeof(x) / sizeof((x)[0]))
#define lib_symbol_def(name) { #name, (void **)&name##_internal }
static const lib_symbol lib_symbols_kperf[] = {
    lib_symbol_def(kpc_pmu_version),
    lib_symbol_def(kpc_cpu_string),
    lib_symbol_def(kpc_set_counting),
    lib_symbol_def(kpc_get_counting),
    lib_symbol_def(kpc_set_thread_counting),
    lib_symbol_def(kpc_get_thread_counting),
    lib_symbol_def(kpc_get_config_count),
    lib_symbol_def(kpc_get_counter_count),
    lib_symbol_def(kpc_set_config),
    lib_symbol_def(kpc_get_config),
    lib_symbol_def(kpc_get_cpu_counters),
    lib_symbol_def(kpc_get_thread_counters),
    lib_symbol_def(kpc_force_all_ctrs_set),
    lib_symbol_def(kpc_force_all_ctrs_get),
    lib_symbol_def(kperf_action_count_set),
    lib_symbol_def(kperf_action_count_get),
    lib_symbol_def(kperf_action_samplers_set),
    lib_symbol_def(kperf_action_samplers_get),
    lib_symbol_def(kperf_action_filter_set_by_task),
    lib_symbol_def(kperf_action_filter_set_by_pid),
    lib_symbol_def(kperf_timer_count_set),
    lib_symbol_def(kperf_timer_count_get),
    lib_symbol_def(kperf_timer_period_set),
    lib_symbol_def(kperf_timer_period_get),
    lib_symbol_def(kperf_timer_action_set),
    lib_symbol_def(kperf_timer_action_get),
    lib_symbol_def(kperf_sample_set),
    lib_symbol_def(kperf_sample_get),
    lib_symbol_def(kperf_reset),
    lib_symbol_def(kperf_timer_pet_set),
    lib_symbol_def(kperf_timer_pet_get),
    lib_symbol_def(kperf_ns_to_ticks),
    lib_symbol_def(kperf_ticks_to_ns),
    lib_symbol_def(kperf_tick_frequency),
    lib_symbol_def(kpc_get_period),
    lib_symbol_def(kpc_set_period),
};

static const lib_symbol lib_symbols_kperfdata[] = {
    lib_symbol_def(kpep_config_create),
    lib_symbol_def(kpep_config_free),
    lib_symbol_def(kpep_config_add_event),
    lib_symbol_def(kpep_config_remove_event),
    lib_symbol_def(kpep_config_force_counters),
    lib_symbol_def(kpep_config_events_count),
    lib_symbol_def(kpep_config_events),
    lib_symbol_def(kpep_config_kpc),
    lib_symbol_def(kpep_config_kpc_count),
    lib_symbol_def(kpep_config_kpc_classes),
    lib_symbol_def(kpep_config_kpc_map),
    lib_symbol_def(kpep_db_create),
    lib_symbol_def(kpep_db_free),
    lib_symbol_def(kpep_db_name),
    lib_symbol_def(kpep_db_aliases_count),
    lib_symbol_def(kpep_db_aliases),
    lib_symbol_def(kpep_db_counters_count),
    lib_symbol_def(kpep_db_events_count),
    lib_symbol_def(kpep_db_events),
    lib_symbol_def(kpep_db_event),
    lib_symbol_def(kpep_event_name),
    lib_symbol_def(kpep_event_alias),
    lib_symbol_def(kpep_event_description),

};

#define lib_path_kperf "/System/Library/PrivateFrameworks/kperf.framework/kperf"
#define lib_path_kperfdata "/System/Library/PrivateFrameworks/kperfdata.framework/kperfdata"



int kpc_cpu_string (char *buf, usize buf_size){
    return kpc_cpu_string_internal(buf, buf_size);
}
u32 kpc_pmu_version (void){
    return kpc_pmu_version_internal();
}
u32 kpc_get_counting (void){
    return kpc_get_counting_internal();
}
int kpc_set_counting (u32 classes){
    return kpc_set_counting_internal(classes);
}
u32 kpc_get_thread_counting (void){
    return kpc_get_thread_counting_internal();
}
int kpc_set_thread_counting (u32 classes){
    return kpc_set_thread_counting_internal(classes);
}
u32 kpc_get_config_count (u32 classes){
    return kpc_get_config_count_internal(classes);
}
int kpc_get_config (u32 classes, kpc_config_t *config){
    return kpc_get_config_internal(classes, config);
}
int kpc_set_config (u32 classes, kpc_config_t *config){
    return kpc_set_config_internal(classes, config);
}
u32 kpc_get_counter_count (u32 classes){
    return kpc_get_counter_count_internal(classes);
}
int kpc_get_cpu_counters (bool all_cpus, u32 classes, int *curcpu, u64 *buf){
    return kpc_get_cpu_counters_internal(all_cpus, classes, curcpu, buf);
}
int kpc_get_thread_counters (u32 tid, u32 buf_count, u64 *buf){
    return kpc_get_thread_counters_internal(tid, buf_count, buf);
}
int kpc_force_all_ctrs_set (int val){
    return kpc_force_all_ctrs_set_internal(val);
}
int kpc_force_all_ctrs_get (int *val_out){
    return kpc_force_all_ctrs_get_internal(val_out);
}
int kperf_action_count_set (u32 count){
    return kperf_action_count_set_internal(count);
}
int kperf_action_count_get (u32 *count){
    return kperf_action_count_get_internal(count);
}
int kperf_action_samplers_set (u32 actionid, u32 sample){
    return kperf_action_samplers_set_internal(actionid, sample);
}
int kperf_action_samplers_get (u32 actionid, u32 *sample){
    return kperf_action_samplers_get_internal(actionid, sample);
}
int kperf_action_filter_set_by_task (u32 actionid, i32 port){
    return kperf_action_filter_set_by_task_internal(actionid, port);
}
int kperf_action_filter_set_by_pid (u32 actionid, i32 pid){
    return kperf_action_filter_set_by_pid_internal(actionid, pid);
}
int kperf_timer_count_set (u32 count){
    return kperf_timer_count_set_internal(count);
}
int kperf_timer_count_get (u32 *count){
    return kperf_timer_count_get_internal(count);
}
int kperf_timer_period_set (u32 actionid, u64 tick){
    return kperf_timer_period_set_internal(actionid, tick);
}
int kperf_timer_period_get (u32 actionid, u64 *tick){
    return kperf_timer_period_get_internal(actionid, tick);
}
int kperf_timer_action_set (u32 actionid, u32 timerid){
    return kperf_timer_action_set_internal(actionid, timerid);
}
int kperf_timer_action_get (u32 actionid, u32 *timerid){
    return kperf_timer_action_get_internal(actionid, timerid);
}
int kperf_timer_pet_set (u32 timerid){
    return kperf_timer_pet_set_internal(timerid);
}
int kperf_timer_pet_get (u32 *timerid){
    return kperf_timer_pet_get_internal(timerid);
}
int kperf_sample_set (u32 enabled){
    return kperf_sample_set_internal(enabled);
}
int kperf_sample_get (u32 *enabled){
    return kperf_sample_get_internal(enabled);
}
int kperf_reset (void){
    return kperf_reset_internal();
}
u64 kperf_ns_to_ticks (u64 ns){
    return kperf_ns_to_ticks_internal(ns);
}
u64 kperf_ticks_to_ns (u64 ticks){
    return kperf_ticks_to_ns_internal(ticks);
}
u64 kperf_tick_frequency (void){
    return kperf_tick_frequency_internal();
}
int kpep_config_create (kpep_db *db, kpep_config **cfg_ptr){
    return kpep_config_create_internal(db, cfg_ptr);
}
void kpep_config_free (kpep_config *cfg){
   
    kpep_config_free_internal(cfg);
    
}
int kpep_config_add_event (kpep_config *cfg, kpep_event **ev_ptr, u32 flag, u32 *err){
    return kpep_config_add_event_internal(cfg, ev_ptr, flag, err);
}
int kpep_config_remove_event (kpep_config *cfg, usize idx){
    return kpep_config_remove_event_internal(cfg, idx);
}
int kpep_config_force_counters (kpep_config *cfg){
    return kpep_config_force_counters_internal(cfg);
}
int kpep_config_events_count (kpep_config *cfg, usize *count_ptr){
    return kpep_config_events_count_internal(cfg, count_ptr);
}
int kpep_config_events (kpep_config *cfg, kpep_event **buf, usize buf_size){
    return kpep_config_events_internal(cfg, buf, buf_size);
}
int kpep_config_kpc (kpep_config *cfg, kpc_config_t *buf, usize buf_size){
    return kpep_config_kpc_internal(cfg, buf, buf_size);
}
int kpep_config_kpc_count (kpep_config *cfg, usize *count_ptr){
    return kpep_config_kpc_count_internal(cfg, count_ptr);
}
int kpep_config_kpc_classes (kpep_config *cfg, u32 *classes_ptr){
    return kpep_config_kpc_classes_internal(cfg, classes_ptr);
}
int kpep_config_kpc_map (kpep_config *cfg, usize *buf, usize buf_size){
    return kpep_config_kpc_map_internal(cfg, buf, buf_size);
}
int kpep_db_create (const char *name, kpep_db **db_ptr){
    return kpep_db_create_internal(name, db_ptr);
}
void kpep_db_free (kpep_db *db){
    kpep_db_free_internal(db);
}
int kpep_db_name (kpep_db *db, const char **name){
    return kpep_db_name_internal(db, name);
}
int kpep_db_aliases_count (kpep_db *db, usize *count){
    return kpep_db_aliases_count_internal(db, count);
}
int kpep_db_aliases (kpep_db *db, const char **buf, usize buf_size){
    return kpep_db_aliases_internal(db, buf, buf_size);
}
int kpep_db_counters_count (kpep_db *db, u8 classes, usize *count){
    return kpep_db_counters_count_internal(db, classes, count);
}
int kpep_db_events_count (kpep_db *db, usize *count){
    return kpep_db_events_count_internal(db, count);
}
int kpep_db_events (kpep_db *db, kpep_event **buf, usize buf_size){
    return kpep_db_events_internal(db, buf, buf_size);
}
int kpep_db_event (kpep_db *db, const char *name, kpep_event **ev_ptr){
    return kpep_db_event_internal(db, name, ev_ptr);
}
int kpep_event_name (kpep_event *ev, const char **name_ptr){
    return kpep_event_name_internal(ev, name_ptr);
}
int kpep_event_alias (kpep_event *ev, const char **alias_ptr){
    return kpep_event_alias_internal(ev, alias_ptr);
}
int kpep_event_description (kpep_event *ev, const char **str_ptr){
    return kpep_event_description_internal(ev, str_ptr);
}
int kpc_get_period (u32 classes, u64 *period) {
    return kpc_get_period_internal(classes, period);
}
int kpc_set_period (u32 classes, u64 *period) {
    return kpc_set_period_internal(classes, period);
}
static bool lib_inited = false;
static bool lib_has_err = false;
static char lib_err_msg[256];

static void *lib_handle_kperf = NULL;
static void *lib_handle_kperfdata = NULL;

static void lib_deinit(void) {
    lib_inited = false;
    lib_has_err = false;
    if (lib_handle_kperf) dlclose(lib_handle_kperf);
    if (lib_handle_kperfdata) dlclose(lib_handle_kperfdata);
    lib_handle_kperf = NULL;
    lib_handle_kperfdata = NULL;
    for (usize i = 0; i < lib_nelems(lib_symbols_kperf); i++) {
        const lib_symbol *symbol = &lib_symbols_kperf[i];
        *symbol->impl = NULL;
    }
    for (usize i = 0; i < lib_nelems(lib_symbols_kperfdata); i++) {
        const lib_symbol *symbol = &lib_symbols_kperfdata[i];
        *symbol->impl = NULL;
    }
}

static bool lib_init(void) {
#define return_err() do { \
    lib_deinit(); \
    lib_inited = true; \
    lib_has_err = true; \
    return false; \
} while(false)
    
    if (lib_inited) return !lib_has_err;
    
    // load dynamic library
    lib_handle_kperf = dlopen(lib_path_kperf, RTLD_LAZY);
    if (!lib_handle_kperf) {
        snprintf(lib_err_msg, sizeof(lib_err_msg),
                 "Failed to load kperf.framework, message: %s.", dlerror());
        return_err();
    }
    lib_handle_kperfdata = dlopen(lib_path_kperfdata, RTLD_LAZY);
    if (!lib_handle_kperfdata) {
        snprintf(lib_err_msg, sizeof(lib_err_msg),
                 "Failed to load kperfdata.framework, message: %s.", dlerror());
        return_err();
    }
    
    // load symbol address from dynamic library
    for (usize i = 0; i < lib_nelems(lib_symbols_kperf); i++) {
        const lib_symbol *symbol = &lib_symbols_kperf[i];
        *symbol->impl = dlsym(lib_handle_kperf, symbol->name);
        if (!*symbol->impl) {
            snprintf(lib_err_msg, sizeof(lib_err_msg),
                     "Failed to load kperf function: %s.", symbol->name);
            return_err();
        }
    }
    for (usize i = 0; i < lib_nelems(lib_symbols_kperfdata); i++) {
        const lib_symbol *symbol = &lib_symbols_kperfdata[i];
        *symbol->impl = dlsym(lib_handle_kperfdata, symbol->name);
        if (!*symbol->impl) {
            snprintf(lib_err_msg, sizeof(lib_err_msg),
                     "Failed to load kperfdata function: %s.", symbol->name);
            return_err();
        }
    }
    
    lib_inited = true;
    lib_has_err = false;
    return true;
    
#undef return_err
}
int kdebug_reset(void) {
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDREMOVE };
    return sysctl(mib, 3, NULL, NULL, NULL, 0);
}

int kdebug_reinit(void) {
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETUP };
    return sysctl(mib, 3, NULL, NULL, NULL, 0);
}
int kdebug_setreg(kd_regtype *kdr) {
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETREG };
    usize size = sizeof(kd_regtype);
    return sysctl(mib, 3, kdr, &size, NULL, 0);
}
int kdebug_trace_setbuf(int nbufs) {
    int mib[4] = { CTL_KERN, KERN_KDEBUG, KERN_KDSETBUF, nbufs };
    return sysctl(mib, 4, NULL, NULL, NULL, 0);
}
int kdebug_trace_enable(bool enable) {
    int mib[4] = { CTL_KERN, KERN_KDEBUG, KERN_KDENABLE, enable };
    return sysctl(mib, 4, NULL, 0, NULL, 0);
}
int kdebug_get_bufinfo(kbufinfo_t *info) {
    if (!info) return -1;
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDGETBUF };
    size_t needed = sizeof(kbufinfo_t);
    return sysctl(mib, 3, info, &needed, NULL, 0);
}
int kdebug_trace_read(void *buf, usize len, usize *count) {
    if (count) *count = 0;
    if (!buf || !len) return -1;
    
    // Note: the input and output units are not the same.
    // input: bytes
    // output: number of kd_buf
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDREADTR };
    int ret = sysctl(mib, 3, buf, &len, NULL, 0);
    if (ret != 0) return ret;
    *count = len;
    return 0;
}
int kdebug_wait(usize timeout_ms, bool *suc) {
    if (timeout_ms == 0) return -1;
    int mib[3] = { CTL_KERN, KERN_KDEBUG, KERN_KDBUFWAIT };
    usize val = timeout_ms;
    int ret = sysctl(mib, 3, NULL, &val, NULL, 0);
    if (suc) *suc = !!val;
    return ret;
}

/// Error description for kpep_config_error_code.
const char *kpep_config_error_names[KPEP_CONFIG_ERROR_MAX] = {
    "none",
    "invalid argument",
    "out of memory",
    "I/O",
    "buffer too small",
    "current system unknown",
    "database path invalid",
    "database not found",
    "database architecture unsupported",
    "database version unsupported",
    "database corrupt",
    "event not found",
    "conflicting events",
    "all counters must be forced",
    "event unavailable",
    "check errno"
};
const char* kpep_config_error_desc(int code) {
  if (0 <= code && code < KPEP_CONFIG_ERROR_MAX) {
    return kpep_config_error_names[code];
  }
  return "unknown error";
}
__attribute__((constructor)) static void dylib_initializer(void) {
    if (!lib_init()) {
        fprintf(stderr, "Failed to initialize kperf/kperfdata library: %s\n", lib_err_msg);
        exit(EXIT_FAILURE);
    }
}