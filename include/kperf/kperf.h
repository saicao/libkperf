#ifndef KPERF_H
#define KPERF_H
// =============================================================================
// XNU kperf/kpc demo
// Available for 64-bit Intel/Apple Silicon, macOS/iOS, with root privileges
//
//
// Demo 1 (profile a function in current thread):
// 1. Open directory '/usr/share/kpep/', find your CPU PMC database.
//    M1 (Pro/Max/Ultra): /usr/share/kpep/a14.plist
//    M2 (Pro/Max):       /usr/share/kpep/a15.plist
//    M3:                 /usr/share/kpep/as1.plist
//    M3 (Pro/Max):       /usr/share/kpep/as3.plist
//    M4:                 /usr/share/kpep/as4.plist
// 2. Select a few events that you are interested in,
//    add their names to the `profile_events` array below.
// 3. Put your code in `profile_func` function below.
// 4. Compile and run with root (sudo).
//
//
// Demo 2 (profile a select process):
// Replace step 3 with: set `target_pid` and `total_profile_time`.
// Use main2() as the entry function.
//
//
// References:
//
// XNU source (since xnu 2422.1.72):
// https://github.com/apple/darwin-xnu/blob/main/osfmk/kern/kpc.h
// https://github.com/apple/darwin-xnu/blob/main/bsd/kern/kern_kpc.c
//
// Lightweight PET (Profile Every Thread, since xnu 3789.1.32):
// https://github.com/apple/darwin-xnu/blob/main/osfmk/kperf/pet.c
// https://github.com/apple/darwin-xnu/blob/main/osfmk/kperf/kperf_kpc.c
//
// System Private frameworks (since macOS 10.11, iOS 8.0):
// /System/Library/PrivateFrameworks/kperf.framework
// /System/Library/PrivateFrameworks/kperfdata.framework
//
// Xcode framework (since Xcode 7.0):
// /Applications/Xcode.app/Contents/SharedFrameworks/DVTInstrumentsFoundation.framework
//
// CPU database (plist files)
// macOS (since macOS 10.11):
//     /usr/share/kpep/<name>.plist
// iOS (copied from Xcode, since iOS 10.0, Xcode 8.0):
//     /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform
//     /DeviceSupport/<version>/DeveloperDiskImage.dmg/usr/share/kpep/<name>.plist
//
// Use this shell command to get plist file name for the current host:
// printf "cpu_%s_%s_%s.plist\n" $(sysctl -nx hw.cputype hw.cpusubtype
// hw.cpufamily) | sed -E 's/0x0*//g'
//
// Created by YaoYuan <ibireme@gmail.com> on 2021.
// Released into the public domain (unlicense.org).
// =============================================================================

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>


#include "kdebug.h"         // for kdebug trace decode

typedef float f32;
typedef double f64;
typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef size_t usize;

// -----------------------------------------------------------------------------
// <kperf.framework> header (reverse engineered)
// This framework wraps some sysctl calls to communicate with the kpc in kernel.
// Most functions requires root privileges, or process is "blessed".
// -----------------------------------------------------------------------------

// Cross-platform class constants.
#define KPC_CLASS_FIXED (0)
#define KPC_CLASS_CONFIGURABLE (1)
#define KPC_CLASS_POWER (2)
#define KPC_CLASS_RAWPMU (3)

// Cross-platform class mask constants.
#define KPC_CLASS_FIXED_MASK (1u << KPC_CLASS_FIXED)               // 1
#define KPC_CLASS_CONFIGURABLE_MASK (1u << KPC_CLASS_CONFIGURABLE) // 2
#define KPC_CLASS_POWER_MASK (1u << KPC_CLASS_POWER)               // 4
#define KPC_CLASS_RAWPMU_MASK (1u << KPC_CLASS_RAWPMU)             // 8

// PMU version constants.
#define KPC_PMU_ERROR (0)     // Error
#define KPC_PMU_INTEL_V3 (1)  // Intel
#define KPC_PMU_ARM_APPLE (2) // ARM64
#define KPC_PMU_INTEL_V2 (3)  // Old Intel
#define KPC_PMU_ARM_V2 (4)    // Old ARM

// The maximum number of counters we could read from every class in one go.
// ARMV7: FIXED: 1, CONFIGURABLE: 4
// ARM32: FIXED: 2, CONFIGURABLE: 6
// ARM64: FIXED: 2, CONFIGURABLE: CORE_NCTRS - FIXED (6 or 8)
// x86: 32
#define KPC_MAX_COUNTERS 32

// Bits for defining what to do on an action.
// Defined in https://github.com/apple/darwin-xnu/blob/main/osfmk/kperf/action.h
#define KPERF_SAMPLER_TH_INFO (1U << 0)
#define KPERF_SAMPLER_TH_SNAPSHOT (1U << 1)
#define KPERF_SAMPLER_KSTACK (1U << 2)
#define KPERF_SAMPLER_USTACK (1U << 3)
#define KPERF_SAMPLER_PMC_THREAD (1U << 4)
#define KPERF_SAMPLER_PMC_CPU (1U << 5)
#define KPERF_SAMPLER_PMC_CONFIG (1U << 6)
#define KPERF_SAMPLER_MEMINFO (1U << 7)
#define KPERF_SAMPLER_TH_SCHEDULING (1U << 8)
#define KPERF_SAMPLER_TH_DISPATCH (1U << 9)
#define KPERF_SAMPLER_TK_SNAPSHOT (1U << 10)
#define KPERF_SAMPLER_SYS_MEM (1U << 11)
#define KPERF_SAMPLER_TH_INSCYC (1U << 12)
#define KPERF_SAMPLER_TK_INFO (1U << 13)

// Maximum number of kperf action ids.
#define KPERF_ACTION_MAX (32)

// Maximum number of kperf timer ids.
#define KPERF_TIMER_MAX (8)

// x86/arm config registers are 64-bit
typedef u64 kpc_config_t;

/// Print current CPU identification string to the buffer (same as snprintf),
/// such as "cpu_7_8_10b282dc_46". This string can be used to locate the PMC
/// database in /usr/share/kpep.
/// @return string's length, or negative value if error occurs.
/// @note This method does not requires root privileges.
/// @details sysctl get(hw.cputype), get(hw.cpusubtype),
///                 get(hw.cpufamily), get(machdep.cpu.model)
int kpc_cpu_string(char *buf, usize buf_size);

/// Get the version of KPC that's being run.
/// @return See `PMU version constants` above.
/// @details sysctl get(kpc.pmu_version)
u32 kpc_pmu_version(void);

/// Get running PMC classes.
/// @return See `class mask constants` above,
///         0 if error occurs or no class is set.
/// @details sysctl get(kpc.counting)
u32 kpc_get_counting(void);

/// Set PMC classes to enable counting.
/// @param classes See `class mask constants` above, set 0 to shutdown counting.
/// @return 0 for success.
/// @details sysctl set(kpc.counting)
int kpc_set_counting(u32 classes);

/// Get running PMC classes for current thread.
/// @return See `class mask constants` above,
///         0 if error occurs or no class is set.
/// @details sysctl get(kpc.thread_counting)
u32 kpc_get_thread_counting(void);

/// Set PMC classes to enable counting for current thread.
/// @param classes See `class mask constants` above, set 0 to shutdown counting.
/// @return 0 for success.
/// @details sysctl set(kpc.thread_counting)
int kpc_set_thread_counting(u32 classes);

/// Get how many config registers there are for a given mask.
/// For example: Intel may returns 1 for `KPC_CLASS_FIXED_MASK`,
///                        returns 4 for `KPC_CLASS_CONFIGURABLE_MASK`.
/// @param classes See `class mask constants` above.
/// @return 0 if error occurs or no class is set.
/// @note This method does not requires root privileges.
/// @details sysctl get(kpc.config_count)
u32 kpc_get_config_count(u32 classes);

/// Get config registers.
/// @param classes see `class mask constants` above.
/// @param config Config buffer to receive values, should not smaller than
///               kpc_get_config_count(classes) * sizeof(kpc_config_t).
/// @return 0 for success.
/// @details sysctl get(kpc.config_count), get(kpc.config)
int kpc_get_config(u32 classes, kpc_config_t *config);

/// Set config registers.
/// @param classes see `class mask constants` above.
/// @param config Config buffer, should not smaller than
///               kpc_get_config_count(classes) * sizeof(kpc_config_t).
/// @return 0 for success.
/// @details sysctl get(kpc.config_count), set(kpc.config)
int kpc_set_config(u32 classes, kpc_config_t *config);

/// Get how many counters there are for a given mask.
/// For example: Intel may returns 3 for `KPC_CLASS_FIXED_MASK`,
///                        returns 4 for `KPC_CLASS_CONFIGURABLE_MASK`.
/// @param classes See `class mask constants` above.
/// @note This method does not requires root privileges.
/// @details sysctl get(kpc.counter_count)
u32 kpc_get_counter_count(u32 classes);

/// Get counter accumulations.
/// If `all_cpus` is true, the buffer count should not smaller than
/// (cpu_count * counter_count). Otherwize, the buffer count should not smaller
/// than (counter_count).
/// @see kpc_get_counter_count(), kpc_cpu_count().
/// @param all_cpus true for all CPUs, false for current cpu.
/// @param classes See `class mask constants` above.
/// @param curcpu A pointer to receive current cpu id, can be NULL.
/// @param buf Buffer to receive counter's value.
/// @return 0 for success.
/// @details sysctl get(hw.ncpu), get(kpc.counter_count), get(kpc.counters)
int kpc_get_cpu_counters(bool all_cpus, u32 classes, int *curcpu, u64 *buf);

/// Get counter accumulations for current thread.
/// @param tid Thread id, should be 0.
/// @param buf_count The number of buf's elements (not bytes),
///                  should not smaller than kpc_get_counter_count().
/// @param buf Buffer to receive counter's value.
/// @return 0 for success.
/// @details sysctl get(kpc.thread_counters)
int kpc_get_thread_counters(u32 tid, u32 buf_count, u64 *buf);

/// Acquire/release the counters used by the Power Manager.
/// @param val 1:acquire, 0:release
/// @return 0 for success.
/// @details sysctl set(kpc.force_all_ctrs)
int kpc_force_all_ctrs_set(int val);

/// Get the state of all_ctrs.
/// @return 0 for success.
/// @details sysctl get(kpc.force_all_ctrs)
int kpc_force_all_ctrs_get(int *val_out);

/// Set number of actions, should be `KPERF_ACTION_MAX`.
/// @details sysctl set(kperf.action.count)
int kperf_action_count_set(u32 count);

/// Get number of actions.
/// @details sysctl get(kperf.action.count)
int kperf_action_count_get(u32 *count);

/// Set what to sample when a trigger fires an action, e.g.
/// `KPERF_SAMPLER_PMC_CPU`.
/// @details sysctl set(kperf.action.samplers)
int kperf_action_samplers_set(u32 actionid, u32 sample);

/// Get what to sample when a trigger fires an action.
/// @details sysctl get(kperf.action.samplers)
int kperf_action_samplers_get(u32 actionid, u32 *sample);

/// Apply a task filter to the action, -1 to disable filter.
/// @details sysctl set(kperf.action.filter_by_task)
int kperf_action_filter_set_by_task(u32 actionid, i32 port);

/// Apply a pid filter to the action, -1 to disable filter.
/// @details sysctl set(kperf.action.filter_by_pid)
int kperf_action_filter_set_by_pid(u32 actionid, i32 pid);

/// Set number of time triggers, should be `KPERF_TIMER_MAX`.
/// @details sysctl set(kperf.timer.count)
int kperf_timer_count_set(u32 count);

/// Get number of time triggers.
/// @details sysctl get(kperf.timer.count)
int kperf_timer_count_get(u32 *count);

/// Set timer number and period.
/// @details sysctl set(kperf.timer.period)
int kperf_timer_period_set(u32 actionid, u64 tick);

/// Get timer number and period.
/// @details sysctl get(kperf.timer.period)
int kperf_timer_period_get(u32 actionid, u64 *tick);

/// Set timer number and actionid.
/// @details sysctl set(kperf.timer.action)
int kperf_timer_action_set(u32 actionid, u32 timerid);

/// Get timer number and actionid.
/// @details sysctl get(kperf.timer.action)
int kperf_timer_action_get(u32 actionid, u32 *timerid);

/// Set which timer ID does PET (Profile Every Thread).
/// @details sysctl set(kperf.timer.pet_timer)
int kperf_timer_pet_set(u32 timerid);

/// Get which timer ID does PET (Profile Every Thread).
/// @details sysctl get(kperf.timer.pet_timer)
int kperf_timer_pet_get(u32 *timerid);

/// Enable or disable sampling.
/// @details sysctl set(kperf.sampling)
int kperf_sample_set(u32 enabled);

/// Get is currently sampling.
/// @details sysctl get(kperf.sampling)
int kperf_sample_get(u32 *enabled);

/// Reset kperf: stop sampling, kdebug, timers and actions.
/// @return 0 for success.
int kperf_reset(void);

/// Nanoseconds to CPU ticks.
u64 kperf_ns_to_ticks(u64 ns);

/// CPU ticks to nanoseconds.
u64 kperf_ticks_to_ns(u64 ticks);

/// CPU ticks frequency (mach_absolute_time).
u64 kperf_tick_frequency(void);

/// Get lightweight PET mode (not in kperf.framework).
int kperf_lightweight_pet_get(u32 *enabled);
/// Set lightweight PET mode (not in kperf.framework).
int kperf_lightweight_pet_set(u32 enabled);

// -----------------------------------------------------------------------------
// <kperfdata.framework> header (reverse engineered)
// This framework provides some functions to access the local CPU database.
// These functions do not require root privileges.
// -----------------------------------------------------------------------------

// KPEP CPU archtecture constants.
#define KPEP_ARCH_I386 0
#define KPEP_ARCH_X86_64 1
#define KPEP_ARCH_ARM 2
#define KPEP_ARCH_ARM64 3

/// KPEP event (size: 48/28 bytes on 64/32 bit OS)
typedef struct kpep_event {
  const char *name; ///< Unique name of a event, such as "INST_RETIRED.ANY".
  const char *description; ///< Description for this event.
  const char *errata;      ///< Errata, currently NULL.
  const char *alias;       ///< Alias name, such as "Instructions", "Cycles".
  const char *fallback;    ///< Fallback event name for fixed counter.
  u32 mask;
  u8 number;
  u8 umask;
  u8 reserved;
  u8 is_fixed;
} kpep_event;

/// KPEP database (size: 144/80 bytes on 64/32 bit OS)
typedef struct kpep_db {
  const char *name;           ///< Database name, such as "haswell".
  const char *cpu_id;         ///< Plist name, such as "cpu_7_8_10b282dc".
  const char *marketing_name; ///< Marketing name, such as "Intel Haswell".
  void *plist_data;           ///< Plist data (CFDataRef), currently NULL.
  void *event_map; ///< All events (CFDict<CFSTR(event_name), kpep_event *>).
  kpep_event
      *event_arr; ///< Event struct buffer (sizeof(kpep_event) * events_count).
  kpep_event **fixed_event_arr; ///< Fixed counter events (sizeof(kpep_event *)
                                ///< * fixed_counter_count)
  void *alias_map; ///< All aliases (CFDict<CFSTR(event_name), kpep_event *>).
  usize reserved_1;
  usize reserved_2;
  usize reserved_3;
  usize event_count; ///< All events count.
  usize alias_count;
  usize fixed_counter_count;
  usize config_counter_count;
  usize power_counter_count;
  u32 archtecture; ///< see `KPEP CPU archtecture constants` above.
  u32 fixed_counter_bits;
  u32 config_counter_bits;
  u32 power_counter_bits;
} kpep_db;

/// KPEP config (size: 80/44 bytes on 64/32 bit OS)
typedef struct kpep_config {
  kpep_db *db;
  kpep_event **ev_arr; ///< (sizeof(kpep_event *) * counter_count), init NULL
  usize *ev_map;       ///< (sizeof(usize *) * counter_count), init 0
  usize *ev_idx;       ///< (sizeof(usize *) * counter_count), init -1
  u32 *flags;          ///< (sizeof(u32 *) * counter_count), init 0
  u64 *kpc_periods;    ///< (sizeof(u64 *) * counter_count), init 0
  usize event_count;   /// kpep_config_events_count()
  usize counter_count;
  u32 classes; ///< See `class mask constants` above.
  u32 config_counter;
  u32 power_counter;
  u32 reserved;
} kpep_config;

/// Error code for kpep_config_xxx() and kpep_db_xxx() functions.
typedef enum {
  KPEP_CONFIG_ERROR_NONE = 0,
  KPEP_CONFIG_ERROR_INVALID_ARGUMENT = 1,
  KPEP_CONFIG_ERROR_OUT_OF_MEMORY = 2,
  KPEP_CONFIG_ERROR_IO = 3,
  KPEP_CONFIG_ERROR_BUFFER_TOO_SMALL = 4,
  KPEP_CONFIG_ERROR_CUR_SYSTEM_UNKNOWN = 5,
  KPEP_CONFIG_ERROR_DB_PATH_INVALID = 6,
  KPEP_CONFIG_ERROR_DB_NOT_FOUND = 7,
  KPEP_CONFIG_ERROR_DB_ARCH_UNSUPPORTED = 8,
  KPEP_CONFIG_ERROR_DB_VERSION_UNSUPPORTED = 9,
  KPEP_CONFIG_ERROR_DB_CORRUPT = 10,
  KPEP_CONFIG_ERROR_EVENT_NOT_FOUND = 11,
  KPEP_CONFIG_ERROR_CONFLICTING_EVENTS = 12,
  KPEP_CONFIG_ERROR_COUNTERS_NOT_FORCED = 13,
  KPEP_CONFIG_ERROR_EVENT_UNAVAILABLE = 14,
  KPEP_CONFIG_ERROR_ERRNO = 15,
  KPEP_CONFIG_ERROR_MAX
} kpep_config_error_code;

/// Error description.
const char * kpep_config_error_desc(int code);

/// Create a config.
/// @param db A kpep db, see kpep_db_create()
/// @param cfg_ptr A pointer to receive the new config.
/// @return kpep_config_error_code, 0 for success.
int kpep_config_create(kpep_db *db, kpep_config **cfg_ptr);

/// Free the config.
void kpep_config_free(kpep_config *cfg);

/// Add an event to config.
/// @param cfg The config.
/// @param ev_ptr A event pointer.
/// @param flag 0: all, 1: user space only
/// @param err Error bitmap pointer, can be NULL.
///            If return value is `CONFLICTING_EVENTS`, this bitmap contains
///            the conflicted event indices, e.g. "1 << 2" means index 2.
/// @return kpep_config_error_code, 0 for success.
int kpep_config_add_event(kpep_config *cfg, kpep_event **ev_ptr, u32 flag,
                          u32 *err);

/// Remove event at index.
/// @return kpep_config_error_code, 0 for success.
int kpep_config_remove_event(kpep_config *cfg, usize idx);

/// Force all counters.
/// @return kpep_config_error_code, 0 for success.
int kpep_config_force_counters(kpep_config *cfg);

/// Get events count.
/// @return kpep_config_error_code, 0 for success.
int kpep_config_events_count(kpep_config *cfg, usize *count_ptr);

/// Get all event pointers.
/// @param buf A buffer to receive event pointers.
/// @param buf_size The buffer's size in bytes, should not smaller than
///                 kpep_config_events_count() * sizeof(void *).
/// @return kpep_config_error_code, 0 for success.
int kpep_config_events(kpep_config *cfg, kpep_event **buf, usize buf_size);

/// Get kpc register configs.
/// @param buf A buffer to receive kpc register configs.
/// @param buf_size The buffer's size in bytes, should not smaller than
///                 kpep_config_kpc_count() * sizeof(kpc_config_t).
/// @return kpep_config_error_code, 0 for success.
int kpep_config_kpc(kpep_config *cfg, kpc_config_t *buf, usize buf_size);

/// Get kpc register config count.
/// @return kpep_config_error_code, 0 for success.
int kpep_config_kpc_count(kpep_config *cfg, usize *count_ptr);

/// Get kpc classes.
/// @param classes See `class mask constants` above.
/// @return kpep_config_error_code, 0 for success.
int kpep_config_kpc_classes(kpep_config *cfg, u32 *classes_ptr);

/// Get the index mapping from event to counter.
/// @param buf A buffer to receive indexes.
/// @param buf_size The buffer's size in bytes, should not smaller than
///                 kpep_config_events_count() * sizeof(kpc_config_t).
/// @return kpep_config_error_code, 0 for success.
int kpep_config_kpc_map(kpep_config *cfg, usize *buf, usize buf_size);

/// Open a kpep database file in "/usr/share/kpep/" or "/usr/local/share/kpep/".
/// @param name File name, for example "haswell", "cpu_100000c_1_92fb37c8".
///             Pass NULL for current CPU.
/// @return kpep_config_error_code, 0 for success.
int kpep_db_create(const char *name, kpep_db **db_ptr);

/// Free the kpep database.
void kpep_db_free(kpep_db *db);

/// Get the database's name.
/// @return kpep_config_error_code, 0 for success.
int kpep_db_name(kpep_db *db, const char **name);

/// Get the event alias count.
/// @return kpep_config_error_code, 0 for success.
int kpep_db_aliases_count(kpep_db *db, usize *count);

/// Get all alias.
/// @param buf A buffer to receive all alias strings.
/// @param buf_size The buffer's size in bytes,
///        should not smaller than kpep_db_aliases_count() * sizeof(void *).
/// @return kpep_config_error_code, 0 for success.
int kpep_db_aliases(kpep_db *db, const char **buf, usize buf_size);

/// Get counters count for given classes.
/// @param classes 1: Fixed, 2: Configurable.
/// @return kpep_config_error_code, 0 for success.
int kpep_db_counters_count(kpep_db *db, u8 classes, usize *count);

/// Get all event count.
/// @return kpep_config_error_code, 0 for success.
int kpep_db_events_count(kpep_db *db, usize *count);

/// Get all events.
/// @param buf A buffer to receive all event pointers.
/// @param buf_size The buffer's size in bytes,
///        should not smaller than kpep_db_events_count() * sizeof(void *).
/// @return kpep_config_error_code, 0 for success.
int kpep_db_events(kpep_db *db, kpep_event **buf, usize buf_size);

/// Get one event by name.
/// @return kpep_config_error_code, 0 for success.
int kpep_db_event(kpep_db *db, const char *name, kpep_event **ev_ptr);

/// Get event's name.
/// @return kpep_config_error_code, 0 for success.
int kpep_event_name(kpep_event *ev, const char **name_ptr);

/// Get event's alias.
/// @return kpep_config_error_code, 0 for success.
int kpep_event_alias(kpep_event *ev, const char **alias_ptr);

/// Get event's description.
/// @return kpep_config_error_code, 0 for success.
int kpep_event_description(kpep_event *ev, const char **str_ptr);
/// Get PMI (Performance Monitoring Interrupt) period
int kpc_get_period(u32 classes, u64 *period);
/// Set PMI period.
int kpc_set_period(u32 classes, u64 *period);

// -----------------------------------------------------------------------------
// kdebug private structs
// https://github.com/apple/darwin-xnu/blob/main/bsd/sys_private/kdebug_private.h
// -----------------------------------------------------------------------------

/*
 * Ensure that both LP32 and LP64 variants of arm64 use the same kd_buf
 * structure.
 */
#if defined(__arm64__)
typedef uint64_t kd_buf_argtype;
#else
typedef uintptr_t kd_buf_argtype;
#endif

typedef struct {
    uint64_t timestamp;
    kd_buf_argtype arg1;
    kd_buf_argtype arg2;
    kd_buf_argtype arg3;
    kd_buf_argtype arg4;
    kd_buf_argtype arg5; /* the thread ID */
    uint32_t debugid; /* see <sys/kdebug.h> */
    
/*
 * Ensure that both LP32 and LP64 variants of arm64 use the same kd_buf
 * structure.
 */
#if defined(__LP64__) || defined(__arm64__)
    uint32_t cpuid; /* cpu index, from 0 */
    kd_buf_argtype unused;
#endif
} kd_buf;

/* bits for the type field of kd_regtype */
#define KDBG_CLASSTYPE  0x10000
#define KDBG_SUBCLSTYPE 0x20000
#define KDBG_RANGETYPE  0x40000
#define KDBG_TYPENONE   0x80000
#define KDBG_CKTYPES    0xF0000

/* only trace at most 4 types of events, at the code granularity */
#define KDBG_VALCHECK         0x00200000U

typedef struct {
    unsigned int type;
    unsigned int value1;
    unsigned int value2;
    unsigned int value3;
    unsigned int value4;
} kd_regtype;

typedef struct {
    /* number of events that can fit in the buffers */
    int nkdbufs;
    /* set if trace is disabled */
    int nolog;
    /* kd_ctrl_page.flags */
    unsigned int flags;
    /* number of threads in thread map */
    int nkdthreads;
    /* the owning pid */
    int bufid;
} kbufinfo_t;



// -----------------------------------------------------------------------------
// kdebug utils
// -----------------------------------------------------------------------------

/// Clean up trace buffers and reset ktrace/kdebug/kperf.
/// @return 0 on success.
int kdebug_reset(void);

/// Disable and reinitialize the trace buffers.
/// @return 0 on success.
int kdebug_reinit(void);

/// Set debug filter.
int kdebug_setreg(kd_regtype *kdr);

/// Set maximum number of trace entries (kd_buf).
/// Only allow allocation up to half the available memory (sane_size).
/// @return 0 on success.
int kdebug_trace_setbuf(int nbufs);

/// Enable or disable kdebug trace.
/// Trace buffer must already be initialized.
/// @return 0 on success.
int kdebug_trace_enable(bool enable) ;

/// Retrieve trace buffer information from kernel.
/// @return 0 on success.
int kdebug_get_bufinfo(kbufinfo_t *info);

/// Retrieve trace buffers from kernel.
/// @param buf Memory to receive buffer data, array of `kd_buf`.
/// @param len Length of `buf` in bytes.
/// @param count Number of trace entries (kd_buf) obtained.
/// @return 0 on success.
int kdebug_trace_read(void *buf, usize len, usize *count);

/// Block until there are new buffers filled or `timeout_ms` have passed.
/// @param timeout_ms timeout milliseconds, 0 means wait forever.
/// @param suc set true if new buffers filled.
/// @return 0 on success.
static int kdebug_wait(usize timeout_ms, bool *suc);

#endif // KPERF_H