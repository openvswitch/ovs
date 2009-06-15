/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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

#ifndef VLOG_H
#define VLOG_H 1

#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include "util.h"

/* Logging importance levels. */
#define VLOG_LEVELS                             \
    VLOG_LEVEL(EMER, LOG_ALERT)                 \
    VLOG_LEVEL(ERR, LOG_ERR)                    \
    VLOG_LEVEL(WARN, LOG_WARNING)               \
    VLOG_LEVEL(INFO, LOG_NOTICE)                \
    VLOG_LEVEL(DBG, LOG_DEBUG)
enum vlog_level {
#define VLOG_LEVEL(NAME, SYSLOG_LEVEL) VLL_##NAME,
    VLOG_LEVELS
#undef VLOG_LEVEL
    VLL_N_LEVELS
};

const char *vlog_get_level_name(enum vlog_level);
enum vlog_level vlog_get_level_val(const char *name);

/* Facilities that we can log to. */
#define VLOG_FACILITIES                                         \
    VLOG_FACILITY(SYSLOG, "%05N|%c|%p|%m")                      \
    VLOG_FACILITY(CONSOLE, "%d{%b %d %H:%M:%S}|%05N|%c|%p|%m")  \
    VLOG_FACILITY(FILE, "%d{%b %d %H:%M:%S}|%05N|%c|%p|%m")
enum vlog_facility {
#define VLOG_FACILITY(NAME, PATTERN) VLF_##NAME,
    VLOG_FACILITIES
#undef VLOG_FACILITY
    VLF_N_FACILITIES,
    VLF_ANY_FACILITY = -1
};

const char *vlog_get_facility_name(enum vlog_facility);
enum vlog_facility vlog_get_facility_val(const char *name);

/* VLM_ constant for each vlog module. */
enum vlog_module {
#define VLOG_MODULE(NAME) VLM_##NAME,
#include "vlog-modules.def"
    VLM_N_MODULES,
    VLM_ANY_MODULE = -1
};

const char *vlog_get_module_name(enum vlog_module);
enum vlog_module vlog_get_module_val(const char *name);

/* Rate-limiter for log messages. */
struct vlog_rate_limit {
    /* Configuration settings. */
    unsigned int rate;          /* Tokens per second. */
    unsigned int burst;         /* Max cumulative tokens credit. */

    /* Current status. */
    unsigned int tokens;        /* Current number of tokens. */
    time_t last_fill;           /* Last time tokens added. */
    time_t first_dropped;       /* Time first message was dropped. */
    unsigned int n_dropped;     /* Number of messages dropped. */
};

/* Number of tokens to emit a message.  We add 'rate' tokens per second, which
 * is 60 times the unit used for 'rate', thus 60 tokens are required to emit
 * one message. */
#define VLOG_MSG_TOKENS 60

/* Initializer for a struct vlog_rate_limit, to set up a maximum rate of RATE
 * messages per minute and a maximum burst size of BURST messages. */
#define VLOG_RATE_LIMIT_INIT(RATE, BURST)                   \
        {                                                   \
            RATE,                           /* rate */      \
            (MIN(BURST, UINT_MAX / VLOG_MSG_TOKENS)         \
             * VLOG_MSG_TOKENS),            /* burst */     \
            0,                              /* tokens */    \
            0,                              /* last_fill */ \
            0,                              /* first_dropped */ \
            0,                              /* n_dropped */ \
        }

/* Configuring how each module logs messages. */
enum vlog_level vlog_get_level(enum vlog_module, enum vlog_facility);
void vlog_set_levels(enum vlog_module, enum vlog_facility, enum vlog_level);
char *vlog_set_levels_from_string(const char *);
char *vlog_get_levels(void);
bool vlog_is_enabled(enum vlog_module, enum vlog_level);
bool vlog_should_drop(enum vlog_module, enum vlog_level,
                      struct vlog_rate_limit *);
void vlog_set_verbosity(const char *arg);

/* Configuring log facilities. */
void vlog_set_pattern(enum vlog_facility, const char *pattern);
const char *vlog_get_log_file(void);
int vlog_set_log_file(const char *file_name);
int vlog_reopen_log_file(void);

/* Function for actual logging. */
void vlog_init(void);
void vlog_exit(void);
void vlog(enum vlog_module, enum vlog_level, const char *format, ...)
    __attribute__((format(printf, 3, 4)));
void vlog_valist(enum vlog_module, enum vlog_level, const char *, va_list)
    __attribute__((format(printf, 3, 0)));
void vlog_rate_limit(enum vlog_module, enum vlog_level,
                     struct vlog_rate_limit *, const char *, ...)
    __attribute__((format(printf, 4, 5)));

/* Convenience macros.  To use these, define THIS_MODULE as a macro that
 * expands to the module used by the current source file, e.g.
 *      #include "vlog.h"
 *      #define THIS_MODULE VLM_netlink
 * Guaranteed to preserve errno.
 */
#define VLOG_EMER(...) VLOG(VLL_EMER, __VA_ARGS__)
#define VLOG_ERR(...) VLOG(VLL_ERR, __VA_ARGS__)
#define VLOG_WARN(...) VLOG(VLL_WARN, __VA_ARGS__)
#define VLOG_INFO(...) VLOG(VLL_INFO, __VA_ARGS__)
#define VLOG_DBG(...) VLOG(VLL_DBG, __VA_ARGS__)

/* More convenience macros, for testing whether a given level is enabled in
 * THIS_MODULE.  When constructing a log message is expensive, this enables it
 * to be skipped. */
#define VLOG_IS_EMER_ENABLED() true
#define VLOG_IS_ERR_ENABLED() vlog_is_enabled(THIS_MODULE, VLL_EMER)
#define VLOG_IS_WARN_ENABLED() vlog_is_enabled(THIS_MODULE, VLL_WARN)
#define VLOG_IS_INFO_ENABLED() vlog_is_enabled(THIS_MODULE, VLL_INFO)
#define VLOG_IS_DBG_ENABLED() vlog_is_enabled(THIS_MODULE, VLL_DBG)

/* Convenience macros for rate-limiting.
 * Guaranteed to preserve errno.
 */
#define VLOG_ERR_RL(RL, ...) VLOG_RL(RL, VLL_ERR, __VA_ARGS__)
#define VLOG_WARN_RL(RL, ...) VLOG_RL(RL, VLL_WARN, __VA_ARGS__)
#define VLOG_INFO_RL(RL, ...) VLOG_RL(RL, VLL_INFO, __VA_ARGS__)
#define VLOG_DBG_RL(RL, ...) VLOG_RL(RL, VLL_DBG, __VA_ARGS__)

#define VLOG_DROP_ERR(RL) vlog_should_drop(THIS_MODULE, VLL_ERR, RL)
#define VLOG_DROP_WARN(RL) vlog_should_drop(THIS_MODULE, VLL_WARN, RL)
#define VLOG_DROP_INFO(RL) vlog_should_drop(THIS_MODULE, VLL_INFO, RL)
#define VLOG_DROP_DBG(RL) vlog_should_drop(THIS_MODULE, VLL_DBG, RL)

/* Command line processing. */
#define VLOG_OPTION_ENUMS OPT_LOG_FILE
#define VLOG_LONG_OPTIONS                                   \
        {"verbose",     optional_argument, 0, 'v'},         \
        {"log-file",    optional_argument, 0, OPT_LOG_FILE}
#define VLOG_OPTION_HANDLERS                    \
        case 'v':                               \
            vlog_set_verbosity(optarg);         \
            break;                              \
        case OPT_LOG_FILE:                      \
            vlog_set_log_file(optarg);          \
            break;
void vlog_usage(void);

/* Implementation details. */
#define VLOG(LEVEL, ...)                                \
    do {                                                \
        if (min_vlog_levels[THIS_MODULE] >= LEVEL) {    \
            vlog(THIS_MODULE, LEVEL, __VA_ARGS__);      \
        }                                               \
    } while (0)
#define VLOG_RL(RL, LEVEL, ...)                                     \
    do {                                                            \
        if (min_vlog_levels[THIS_MODULE] >= LEVEL) {                \
            vlog_rate_limit(THIS_MODULE, LEVEL, RL, __VA_ARGS__);   \
        }                                                           \
    } while (0)
extern enum vlog_level min_vlog_levels[VLM_N_MODULES];


#endif /* vlog.h */
