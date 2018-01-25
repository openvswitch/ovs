/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2016 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OPENVSWITCH_VLOG_H
#define OPENVSWITCH_VLOG_H 1

/* Logging.
 *
 *
 * Thread-safety
 * =============
 *
 * Fully thread safe.
 */

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <openvswitch/compiler.h>
#include <openvswitch/list.h>
#include <openvswitch/thread.h>
#include <openvswitch/token-bucket.h>
#include <openvswitch/util.h>

#ifdef  __cplusplus
extern "C" {
#endif

/* Logging severity levels.
 *
 * ovs-appctl(8) defines each of the log levels. */
#define VLOG_LEVELS                             \
    VLOG_LEVEL(OFF,  LOG_ALERT,   1)            \
    VLOG_LEVEL(EMER, LOG_ALERT,   1)            \
    VLOG_LEVEL(ERR,  LOG_ERR,     3)            \
    VLOG_LEVEL(WARN, LOG_WARNING, 4)            \
    VLOG_LEVEL(INFO, LOG_NOTICE,  5)            \
    VLOG_LEVEL(DBG,  LOG_DEBUG,   7)
enum vlog_level {
#define VLOG_LEVEL(NAME, SYSLOG_LEVEL, RFC5424_LEVEL) VLL_##NAME,
    VLOG_LEVELS
#undef VLOG_LEVEL
    VLL_N_LEVELS
};

const char *vlog_get_level_name(enum vlog_level);
enum vlog_level vlog_get_level_val(const char *name);

/* Destinations that we can log to. */
#define VLOG_DESTINATIONS                                                 \
    VLOG_DESTINATION(SYSLOG, "ovs|%05N|%c%T|%p|%m")                        \
    VLOG_DESTINATION(CONSOLE, "%D{%Y-%m-%dT%H:%M:%SZ}|%05N|%c%T|%p|%m")    \
    VLOG_DESTINATION(FILE, "%D{%Y-%m-%dT%H:%M:%S.###Z}|%05N|%c%T|%p|%m")
enum vlog_destination {
#define VLOG_DESTINATION(NAME, PATTERN) VLF_##NAME,
    VLOG_DESTINATIONS
#undef VLOG_DESTINATION
    VLF_N_DESTINATIONS,
    VLF_ANY_DESTINATION = -1
};

const char *vlog_get_destination_name(enum vlog_destination);
enum vlog_destination vlog_get_destination_val(const char *name);

/* A log module. */
struct vlog_module {
    struct ovs_list list;
    const char *name;             /* User-visible name. */
    int levels[VLF_N_DESTINATIONS]; /* Minimum log level for each
                                       destination. */
    int min_level;                /* Minimum log level for any destination. */
    bool honor_rate_limits;       /* Set false to ignore rate limits. */
};

void vlog_insert_module(struct ovs_list *);

const char *vlog_get_module_name(const struct vlog_module *);
struct vlog_module *vlog_module_from_name(const char *name);

/* Rate-limiter for log messages. */
struct vlog_rate_limit {
    struct token_bucket token_bucket;
    time_t first_dropped;       /* Time first message was dropped. */
    time_t last_dropped;        /* Time of most recent message drop. */
    unsigned int n_dropped;     /* Number of messages dropped. */
    struct ovs_mutex mutex;     /* Mutual exclusion for rate limit. */
};

/* Number of tokens to emit a message.  We add 'rate' tokens per millisecond,
 * thus 60,000 tokens are required to emit one message per minute. */
#define VLOG_MSG_TOKENS (60 * 1000)

/* Initializer for a struct vlog_rate_limit, to set up a maximum rate of RATE
 * messages per minute and a maximum burst size of BURST messages. */
#define VLOG_RATE_LIMIT_INIT(RATE, BURST)                                 \
        {                                                                 \
            TOKEN_BUCKET_INIT(RATE, OVS_SAT_MUL(BURST, VLOG_MSG_TOKENS)), \
            0,                              /* first_dropped */           \
            0,                              /* last_dropped */            \
            0,                              /* n_dropped */               \
            OVS_MUTEX_INITIALIZER           /* mutex */                   \
        }

/* Configuring how each module logs messages. */
enum vlog_level vlog_get_level(const struct vlog_module *,
                               enum vlog_destination);
void vlog_set_levels(struct vlog_module *,
                     enum vlog_destination, enum vlog_level);
char *vlog_set_levels_from_string(const char *) OVS_WARN_UNUSED_RESULT;
void vlog_set_levels_from_string_assert(const char *);
char *vlog_get_levels(void);
char *vlog_get_patterns(void);
bool vlog_is_enabled(const struct vlog_module *, enum vlog_level);
bool vlog_should_drop(const struct vlog_module *, enum vlog_level,
                      struct vlog_rate_limit *);
void vlog_set_verbosity(const char *arg);

/* Configuring log destinations. */
void vlog_set_pattern(enum vlog_destination, const char *pattern);
int vlog_set_log_file(const char *file_name);
int vlog_reopen_log_file(void);
#ifndef _WIN32
void vlog_change_owner_unix(uid_t, gid_t);
#endif

/* Configure method how vlog should send messages to syslog server. */
void vlog_set_syslog_method(const char *method);

/* Configure syslog target. */
void vlog_set_syslog_target(const char *target);

/* Initialization. */
void vlog_init(void);
void vlog_enable_async(void);
void vlog_disable_async(void);

/* Functions for actual logging. */
void vlog(const struct vlog_module *, enum vlog_level, const char *format, ...)
    OVS_PRINTF_FORMAT (3, 4);
void vlog_valist(const struct vlog_module *, enum vlog_level,
                 const char *, va_list)
    OVS_PRINTF_FORMAT (3, 0);

OVS_NO_RETURN void vlog_fatal(const struct vlog_module *, const char *format, ...)
    OVS_PRINTF_FORMAT (2, 3);
OVS_NO_RETURN void vlog_fatal_valist(const struct vlog_module *,
                                 const char *format, va_list)
    OVS_PRINTF_FORMAT (2, 0);

OVS_NO_RETURN void vlog_abort(const struct vlog_module *, const char *format, ...)
    OVS_PRINTF_FORMAT (2, 3);
OVS_NO_RETURN void vlog_abort_valist(const struct vlog_module *,
                                 const char *format, va_list)
    OVS_PRINTF_FORMAT (2, 0);

void vlog_rate_limit(const struct vlog_module *, enum vlog_level,
                     struct vlog_rate_limit *, const char *, ...)
    OVS_PRINTF_FORMAT (4, 5);

/* Defines a logging module whose name is MODULE, which should generally be
 * roughly the name of the source file, and makes it the module used by the
 * logging convenience macros defined below. */
#define VLOG_DEFINE_THIS_MODULE(MODULE)                                 \
        static struct vlog_module this_module = {                       \
            OVS_LIST_INITIALIZER(&this_module.list),                    \
            #MODULE,                                        /* name */  \
            { VLL_INFO, VLL_INFO, VLL_INFO },             /* levels */  \
            VLL_INFO,                                  /* min_level */  \
            true                               /* honor_rate_limits */  \
        };                                                              \
        OVS_CONSTRUCTOR(init_this_module_##MODULE) {                    \
            vlog_insert_module(&this_module.list);                      \
        }                                                               \
                                                                        \
        /* Prevent duplicate module names, via linker error.            \
         * The extra "extern" declaration makes sparse happy. */        \
        extern struct vlog_module *VLM_##MODULE;                        \
        struct vlog_module *VLM_##MODULE = &this_module;

/* Macros for the current module as set up by VLOG_DEFINE_THIS_MODULE.
 * These are usually what you want to use.
 *
 * Guaranteed to preserve errno.
 */
#define VLOG_FATAL(...) vlog_fatal(&this_module, __VA_ARGS__)
#define VLOG_ABORT(...) vlog_abort(&this_module, __VA_ARGS__)
#define VLOG_EMER(...) VLOG(VLL_EMER, __VA_ARGS__)
#define VLOG_ERR(...) VLOG(VLL_ERR, __VA_ARGS__)
#define VLOG_WARN(...) VLOG(VLL_WARN, __VA_ARGS__)
#define VLOG_INFO(...) VLOG(VLL_INFO, __VA_ARGS__)
#define VLOG_DBG(...) VLOG(VLL_DBG, __VA_ARGS__)

/* More convenience macros, for testing whether a given level is enabled.  When
 * constructing a log message is expensive, this enables it to be skipped. */
#define VLOG_IS_ERR_ENABLED() vlog_is_enabled(&this_module, VLL_ERR)
#define VLOG_IS_WARN_ENABLED() vlog_is_enabled(&this_module, VLL_WARN)
#define VLOG_IS_INFO_ENABLED() vlog_is_enabled(&this_module, VLL_INFO)
#define VLOG_IS_DBG_ENABLED() vlog_is_enabled(&this_module, VLL_DBG)

/* Convenience macros for rate-limiting.
 * Guaranteed to preserve errno.
 */
#define VLOG_ERR_RL(RL, ...) VLOG_RL(RL, VLL_ERR, __VA_ARGS__)
#define VLOG_WARN_RL(RL, ...) VLOG_RL(RL, VLL_WARN, __VA_ARGS__)
#define VLOG_INFO_RL(RL, ...) VLOG_RL(RL, VLL_INFO, __VA_ARGS__)
#define VLOG_DBG_RL(RL, ...) VLOG_RL(RL, VLL_DBG, __VA_ARGS__)

/* Convenience macros to additionally store log message in buffer
 * Caller is responsible for freeing *ERRP afterwards */
#define VLOG_ERR_BUF(ERRP, ...) VLOG_ERRP(ERRP, VLL_ERR, __VA_ARGS__)
#define VLOG_WARN_BUF(ERRP, ...) VLOG_ERRP(ERRP, VLL_WARN, __VA_ARGS__)

#define VLOG_DROP_ERR(RL) vlog_should_drop(&this_module, VLL_ERR, RL)
#define VLOG_DROP_WARN(RL) vlog_should_drop(&this_module, VLL_WARN, RL)
#define VLOG_DROP_INFO(RL) vlog_should_drop(&this_module, VLL_INFO, RL)
#define VLOG_DROP_DBG(RL) vlog_should_drop(&this_module, VLL_DBG, RL)

/* Macros for logging at most once per execution. */
#define VLOG_ERR_ONCE(...) VLOG_ONCE(VLL_ERR, __VA_ARGS__)
#define VLOG_WARN_ONCE(...) VLOG_ONCE(VLL_WARN, __VA_ARGS__)
#define VLOG_INFO_ONCE(...) VLOG_ONCE(VLL_INFO, __VA_ARGS__)
#define VLOG_DBG_ONCE(...) VLOG_ONCE(VLL_DBG, __VA_ARGS__)

/* Command line processing. */
#define VLOG_OPTION_ENUMS                       \
        OPT_LOG_FILE,                           \
        OPT_SYSLOG_IMPL,                        \
        OPT_SYSLOG_TARGET

#define VLOG_LONG_OPTIONS                                               \
        {"verbose",       optional_argument, NULL, 'v'},                \
        {"log-file",      optional_argument, NULL, OPT_LOG_FILE},       \
        {"syslog-method", required_argument, NULL, OPT_SYSLOG_IMPL},    \
        {"syslog-target", required_argument, NULL, OPT_SYSLOG_TARGET}

#define VLOG_OPTION_HANDLERS                    \
        case 'v':                               \
            vlog_set_verbosity(optarg);         \
            break;                              \
        case OPT_LOG_FILE:                      \
            vlog_set_log_file(optarg);          \
            break;                              \
        case OPT_SYSLOG_IMPL:                   \
            vlog_set_syslog_method(optarg);     \
            break;                              \
        case OPT_SYSLOG_TARGET:                 \
            vlog_set_syslog_target(optarg);     \
            break;

void vlog_usage(void);

/* Implementation details. */
#define VLOG(LEVEL, ...)                                \
    do {                                                \
        enum vlog_level level__ = LEVEL;                \
        if (this_module.min_level >= level__) {         \
            vlog(&this_module, level__, __VA_ARGS__);   \
        }                                               \
    } while (0)
#define VLOG_RL(RL, LEVEL, ...)                                         \
    do {                                                                \
        enum vlog_level level__ = LEVEL;                                \
        if (this_module.min_level >= level__) {                         \
            vlog_rate_limit(&this_module, level__, RL, __VA_ARGS__);    \
        }                                                               \
    } while (0)
#define VLOG_ONCE(LEVEL, ...)                                           \
    do {                                                                \
        static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER; \
        if (ovsthread_once_start(&once)) {                              \
            vlog(&this_module, LEVEL, __VA_ARGS__);                     \
            ovsthread_once_done(&once);                                 \
        }                                                               \
    } while (0)
#define VLOG_ERRP(ERRP, LEVEL, ...)                                     \
    do {                                                                \
        VLOG(LEVEL, __VA_ARGS__);                                       \
        if (ERRP) {                                                     \
            *(ERRP) = xasprintf(__VA_ARGS__);                           \
        }                                                               \
    } while (0)

#ifdef  __cplusplus
}
#endif

#endif /* vlog.h */
