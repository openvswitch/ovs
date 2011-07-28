/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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

#include <config.h>
#include "vlog.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "dirs.h"
#include "dynamic-string.h"
#include "sat-math.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(vlog);

/* Name for each logging level. */
static const char *level_names[VLL_N_LEVELS] = {
#define VLOG_LEVEL(NAME, SYSLOG_LEVEL) #NAME,
    VLOG_LEVELS
#undef VLOG_LEVEL
};

/* Syslog value for each logging level. */
static int syslog_levels[VLL_N_LEVELS] = {
#define VLOG_LEVEL(NAME, SYSLOG_LEVEL) SYSLOG_LEVEL,
    VLOG_LEVELS
#undef VLOG_LEVEL
};

/* The log modules. */
#if USE_LINKER_SECTIONS
extern struct vlog_module *__start_vlog_modules[];
extern struct vlog_module *__stop_vlog_modules[];
#define vlog_modules __start_vlog_modules
#define n_vlog_modules (__stop_vlog_modules - __start_vlog_modules)
#else
#define VLOG_MODULE VLOG_DEFINE_MODULE__
#include "vlog-modules.def"
#undef VLOG_MODULE

struct vlog_module *vlog_modules[] = {
#define VLOG_MODULE(NAME) &VLM_##NAME,
#include "vlog-modules.def"
#undef VLOG_MODULE
};
#define n_vlog_modules ARRAY_SIZE(vlog_modules)
#endif

/* Information about each facility. */
struct facility {
    const char *name;           /* Name. */
    char *pattern;              /* Current pattern. */
    bool default_pattern;       /* Whether current pattern is the default. */
};
static struct facility facilities[VLF_N_FACILITIES] = {
#define VLOG_FACILITY(NAME, PATTERN) {#NAME, PATTERN, true},
    VLOG_FACILITIES
#undef VLOG_FACILITY
};

/* Time at which vlog was initialized, in milliseconds. */
static long long int boot_time;

/* VLF_FILE configuration. */
static char *log_file_name;
static FILE *log_file;

/* vlog initialized? */
static bool vlog_inited;

static void format_log_message(const struct vlog_module *, enum vlog_level,
                               enum vlog_facility, unsigned int msg_num,
                               const char *message, va_list, struct ds *)
    PRINTF_FORMAT(5, 0);

/* Searches the 'n_names' in 'names'.  Returns the index of a match for
 * 'target', or 'n_names' if no name matches. */
static size_t
search_name_array(const char *target, const char **names, size_t n_names)
{
    size_t i;

    for (i = 0; i < n_names; i++) {
        assert(names[i]);
        if (!strcasecmp(names[i], target)) {
            break;
        }
    }
    return i;
}

/* Returns the name for logging level 'level'. */
const char *
vlog_get_level_name(enum vlog_level level)
{
    assert(level < VLL_N_LEVELS);
    return level_names[level];
}

/* Returns the logging level with the given 'name', or VLL_N_LEVELS if 'name'
 * is not the name of a logging level. */
enum vlog_level
vlog_get_level_val(const char *name)
{
    return search_name_array(name, level_names, ARRAY_SIZE(level_names));
}

/* Returns the name for logging facility 'facility'. */
const char *
vlog_get_facility_name(enum vlog_facility facility)
{
    assert(facility < VLF_N_FACILITIES);
    return facilities[facility].name;
}

/* Returns the logging facility named 'name', or VLF_N_FACILITIES if 'name' is
 * not the name of a logging facility. */
enum vlog_facility
vlog_get_facility_val(const char *name)
{
    size_t i;

    for (i = 0; i < VLF_N_FACILITIES; i++) {
        if (!strcasecmp(facilities[i].name, name)) {
            break;
        }
    }
    return i;
}

/* Returns the name for logging module 'module'. */
const char *
vlog_get_module_name(const struct vlog_module *module)
{
    return module->name;
}

/* Returns the logging module named 'name', or NULL if 'name' is not the name
 * of a logging module. */
struct vlog_module *
vlog_module_from_name(const char *name)
{
    struct vlog_module **mp;

    for (mp = vlog_modules; mp < &vlog_modules[n_vlog_modules]; mp++) {
        if (!strcasecmp(name, (*mp)->name)) {
            return *mp;
        }
    }
    return NULL;
}

/* Returns the current logging level for the given 'module' and 'facility'. */
enum vlog_level
vlog_get_level(const struct vlog_module *module, enum vlog_facility facility)
{
    assert(facility < VLF_N_FACILITIES);
    return module->levels[facility];
}

static void
update_min_level(struct vlog_module *module)
{
    enum vlog_facility facility;

    module->min_level = VLL_OFF;
    for (facility = 0; facility < VLF_N_FACILITIES; facility++) {
        if (log_file || facility != VLF_FILE) {
            enum vlog_level level = module->levels[facility];
            if (level > module->min_level) {
                module->min_level = level;
            }
        }
    }
}

static void
set_facility_level(enum vlog_facility facility, struct vlog_module *module,
                   enum vlog_level level)
{
    assert(facility >= 0 && facility < VLF_N_FACILITIES);
    assert(level < VLL_N_LEVELS);

    if (!module) {
        struct vlog_module **mp;

        for (mp = vlog_modules; mp < &vlog_modules[n_vlog_modules]; mp++) {
            (*mp)->levels[facility] = level;
            update_min_level(*mp);
        }
    } else {
        module->levels[facility] = level;
        update_min_level(module);
    }
}

/* Sets the logging level for the given 'module' and 'facility' to 'level'.  A
 * null 'module' or a 'facility' of VLF_ANY_FACILITY is treated as a wildcard
 * across all modules or facilities, respectively. */
void
vlog_set_levels(struct vlog_module *module, enum vlog_facility facility,
                enum vlog_level level)
{
    assert(facility < VLF_N_FACILITIES || facility == VLF_ANY_FACILITY);
    if (facility == VLF_ANY_FACILITY) {
        for (facility = 0; facility < VLF_N_FACILITIES; facility++) {
            set_facility_level(facility, module, level);
        }
    } else {
        set_facility_level(facility, module, level);
    }
}

static void
do_set_pattern(enum vlog_facility facility, const char *pattern)
{
    struct facility *f = &facilities[facility];
    if (!f->default_pattern) {
        free(f->pattern);
    } else {
        f->default_pattern = false;
    }
    f->pattern = xstrdup(pattern);
}

/* Sets the pattern for the given 'facility' to 'pattern'. */
void
vlog_set_pattern(enum vlog_facility facility, const char *pattern)
{
    assert(facility < VLF_N_FACILITIES || facility == VLF_ANY_FACILITY);
    if (facility == VLF_ANY_FACILITY) {
        for (facility = 0; facility < VLF_N_FACILITIES; facility++) {
            do_set_pattern(facility, pattern);
        }
    } else {
        do_set_pattern(facility, pattern);
    }
}

/* Returns the name of the log file used by VLF_FILE, or a null pointer if no
 * log file has been set.  (A non-null return value does not assert that the
 * named log file is in use: if vlog_set_log_file() or vlog_reopen_log_file()
 * fails, it still sets the log file name.) */
const char *
vlog_get_log_file(void)
{
    return log_file_name;
}

/* Sets the name of the log file used by VLF_FILE to 'file_name', or to the
 * default file name if 'file_name' is null.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
vlog_set_log_file(const char *file_name)
{
    char *old_log_file_name;
    struct vlog_module **mp;
    int error;

    /* Close old log file. */
    if (log_file) {
        VLOG_INFO("closing log file");
        fclose(log_file);
        log_file = NULL;
    }

    /* Update log file name and free old name.  The ordering is important
     * because 'file_name' might be 'log_file_name' or some suffix of it. */
    old_log_file_name = log_file_name;
    log_file_name = (file_name
                     ? xstrdup(file_name)
                     : xasprintf("%s/%s.log", ovs_logdir(), program_name));
    free(old_log_file_name);
    file_name = NULL;           /* Might have been freed. */

    /* Open new log file and update min_levels[] to reflect whether we actually
     * have a log_file. */
    log_file = fopen(log_file_name, "a");
    for (mp = vlog_modules; mp < &vlog_modules[n_vlog_modules]; mp++) {
        update_min_level(*mp);
    }

    /* Log success or failure. */
    if (!log_file) {
        VLOG_WARN("failed to open %s for logging: %s",
                  log_file_name, strerror(errno));
        error = errno;
    } else {
        VLOG_INFO("opened log file %s", log_file_name);
        error = 0;
    }

    return error;
}

/* Closes and then attempts to re-open the current log file.  (This is useful
 * just after log rotation, to ensure that the new log file starts being used.)
 * Returns 0 if successful, otherwise a positive errno value. */
int
vlog_reopen_log_file(void)
{
    return log_file_name ? vlog_set_log_file(log_file_name) : 0;
}

/* Set debugging levels:
 *
 *  mod[:facility[:level]] mod2[:facility[:level]] ...
 *
 * Return null if successful, otherwise an error message that the caller must
 * free().
 */
char *
vlog_set_levels_from_string(const char *s_)
{
    char *save_ptr = NULL;
    char *s = xstrdup(s_);
    char *module, *facility;

    for (module = strtok_r(s, ": \t", &save_ptr); module != NULL;
         module = strtok_r(NULL, ": \t", &save_ptr)) {
        struct vlog_module *e_module;
        enum vlog_facility e_facility;

        facility = strtok_r(NULL, ":", &save_ptr);

        if (!facility || !strcmp(facility, "ANY")) {
            e_facility = VLF_ANY_FACILITY;
        } else {
            e_facility = vlog_get_facility_val(facility);
            if (e_facility >= VLF_N_FACILITIES) {
                char *msg = xasprintf("unknown facility \"%s\"", facility);
                free(s);
                return msg;
            }
        }

        if (!strcmp(module, "PATTERN")) {
            vlog_set_pattern(e_facility, save_ptr);
            break;
        } else {
            char *level;
            enum vlog_level e_level;

            if (!strcmp(module, "ANY")) {
                e_module = NULL;
            } else {
                e_module = vlog_module_from_name(module);
                if (!e_module) {
                    char *msg = xasprintf("unknown module \"%s\"", module);
                    free(s);
                    return msg;
                }
            }

            level = strtok_r(NULL, ":", &save_ptr);
            e_level = level ? vlog_get_level_val(level) : VLL_DBG;
            if (e_level >= VLL_N_LEVELS) {
                char *msg = xasprintf("unknown level \"%s\"", level);
                free(s);
                return msg;
            }

            vlog_set_levels(e_module, e_facility, e_level);
        }
    }
    free(s);
    return NULL;
}

/* If 'arg' is null, configure maximum verbosity.  Otherwise, sets
 * configuration according to 'arg' (see vlog_set_levels_from_string()). */
void
vlog_set_verbosity(const char *arg)
{
    if (arg) {
        char *msg = vlog_set_levels_from_string(arg);
        if (msg) {
            ovs_fatal(0, "processing \"%s\": %s", arg, msg);
        }
    } else {
        vlog_set_levels(NULL, VLF_ANY_FACILITY, VLL_DBG);
    }
}

static void
vlog_unixctl_set(struct unixctl_conn *conn,
                 const char *args, void *aux OVS_UNUSED)
{
    char *msg = vlog_set_levels_from_string(args);
    unixctl_command_reply(conn, msg ? 501 : 202, msg);
    free(msg);
}

static void
vlog_unixctl_list(struct unixctl_conn *conn,
                  const char *args OVS_UNUSED, void *aux OVS_UNUSED)
{
    char *msg = vlog_get_levels();
    unixctl_command_reply(conn, 200, msg);
    free(msg);
}

static void
vlog_unixctl_reopen(struct unixctl_conn *conn,
                    const char *args OVS_UNUSED, void *aux OVS_UNUSED)
{
    if (log_file_name) {
        int error = vlog_reopen_log_file();
        if (error) {
            unixctl_command_reply(conn, 503, strerror(errno));
        } else {
            unixctl_command_reply(conn, 202, NULL);
        }
    } else {
        unixctl_command_reply(conn, 403, "Logging to file not configured");
    }
}

/* Initializes the logging subsystem and registers its unixctl server
 * commands. */
void
vlog_init(void)
{
    time_t now;

    if (vlog_inited) {
        return;
    }
    vlog_inited = true;

    openlog(program_name, LOG_NDELAY, LOG_DAEMON);

    boot_time = time_msec();
    now = time_wall();
    if (now < 0) {
        struct tm tm;
        char s[128];

        localtime_r(&now, &tm);
        strftime(s, sizeof s, "%a, %d %b %Y %H:%M:%S %z", &tm);
        VLOG_ERR("current time is negative: %s (%ld)", s, (long int) now);
    }

    unixctl_command_register("vlog/set", vlog_unixctl_set, NULL);
    unixctl_command_register("vlog/list", vlog_unixctl_list, NULL);
    unixctl_command_register("vlog/reopen", vlog_unixctl_reopen, NULL);
}

/* Closes the logging subsystem. */
void
vlog_exit(void)
{
    if (vlog_inited) {
        closelog();
        vlog_inited = false;
    }
}

/* Print the current logging level for each module. */
char *
vlog_get_levels(void)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    struct vlog_module **mp;
    struct svec lines = SVEC_EMPTY_INITIALIZER;
    char *line;
    size_t i;

    ds_put_format(&s, "                 console    syslog    file\n");
    ds_put_format(&s, "                 -------    ------    ------\n");

    for (mp = vlog_modules; mp < &vlog_modules[n_vlog_modules]; mp++) {
        line = xasprintf("%-16s  %4s       %4s       %4s\n",
           vlog_get_module_name(*mp),
           vlog_get_level_name(vlog_get_level(*mp, VLF_CONSOLE)),
           vlog_get_level_name(vlog_get_level(*mp, VLF_SYSLOG)),
           vlog_get_level_name(vlog_get_level(*mp, VLF_FILE)));
        svec_add_nocopy(&lines, line);
    }

    svec_sort(&lines);
    SVEC_FOR_EACH (i, line, &lines) {
        ds_put_cstr(&s, line);
    }
    svec_destroy(&lines);

    return ds_cstr(&s);
}

/* Returns true if a log message emitted for the given 'module' and 'level'
 * would cause some log output, false if that module and level are completely
 * disabled. */
bool
vlog_is_enabled(const struct vlog_module *module, enum vlog_level level)
{
    return module->min_level >= level;
}

static const char *
fetch_braces(const char *p, const char *def, char *out, size_t out_size)
{
    if (*p == '{') {
        size_t n = strcspn(p + 1, "}");
        size_t n_copy = MIN(n, out_size - 1);
        memcpy(out, p + 1, n_copy);
        out[n_copy] = '\0';
        p += n + 2;
    } else {
        ovs_strlcpy(out, def, out_size);
    }
    return p;
}

static void
format_log_message(const struct vlog_module *module, enum vlog_level level,
                   enum vlog_facility facility, unsigned int msg_num,
                   const char *message, va_list args_, struct ds *s)
{
    char tmp[128];
    va_list args;
    const char *p;

    ds_clear(s);
    for (p = facilities[facility].pattern; *p != '\0'; ) {
        enum { LEFT, RIGHT } justify = RIGHT;
        int pad = '0';
        size_t length, field, used;

        if (*p != '%') {
            ds_put_char(s, *p++);
            continue;
        }

        p++;
        if (*p == '-') {
            justify = LEFT;
            p++;
        }
        if (*p == '0') {
            pad = '0';
            p++;
        }
        field = 0;
        while (isdigit((unsigned char)*p)) {
            field = (field * 10) + (*p - '0');
            p++;
        }

        length = s->length;
        switch (*p++) {
        case 'A':
            ds_put_cstr(s, program_name);
            break;
        case 'c':
            p = fetch_braces(p, "", tmp, sizeof tmp);
            ds_put_cstr(s, vlog_get_module_name(module));
            break;
        case 'd':
            p = fetch_braces(p, "%Y-%m-%d %H:%M:%S", tmp, sizeof tmp);
            ds_put_strftime(s, tmp, NULL);
            break;
        case 'm':
            /* Format user-supplied log message and trim trailing new-lines. */
            length = s->length;
            va_copy(args, args_);
            ds_put_format_valist(s, message, args);
            va_end(args);
            while (s->length > length && s->string[s->length - 1] == '\n') {
                s->length--;
            }
            break;
        case 'N':
            ds_put_format(s, "%u", msg_num);
            break;
        case 'n':
            ds_put_char(s, '\n');
            break;
        case 'p':
            ds_put_cstr(s, vlog_get_level_name(level));
            break;
        case 'P':
            ds_put_format(s, "%ld", (long int) getpid());
            break;
        case 'r':
            ds_put_format(s, "%lld", time_msec() - boot_time);
            break;
        default:
            ds_put_char(s, p[-1]);
            break;
        }
        used = s->length - length;
        if (used < field) {
            size_t n_pad = field - used;
            if (justify == RIGHT) {
                ds_put_uninit(s, n_pad);
                memmove(&s->string[length + n_pad], &s->string[length], used);
                memset(&s->string[length], pad, n_pad);
            } else {
                ds_put_char_multiple(s, pad, n_pad);
            }
        }
    }
}

/* Writes 'message' to the log at the given 'level' and as coming from the
 * given 'module'.
 *
 * Guaranteed to preserve errno. */
void
vlog_valist(const struct vlog_module *module, enum vlog_level level,
            const char *message, va_list args)
{
    bool log_to_console = module->levels[VLF_CONSOLE] >= level;
    bool log_to_syslog = module->levels[VLF_SYSLOG] >= level;
    bool log_to_file = module->levels[VLF_FILE] >= level && log_file;
    if (log_to_console || log_to_syslog || log_to_file) {
        int save_errno = errno;
        static unsigned int msg_num;
        struct ds s;

        vlog_init();

        ds_init(&s);
        ds_reserve(&s, 1024);
        msg_num++;

        if (log_to_console) {
            format_log_message(module, level, VLF_CONSOLE, msg_num,
                               message, args, &s);
            ds_put_char(&s, '\n');
            fputs(ds_cstr(&s), stderr);
        }

        if (log_to_syslog) {
            int syslog_level = syslog_levels[level];
            char *save_ptr = NULL;
            char *line;

            format_log_message(module, level, VLF_SYSLOG, msg_num,
                               message, args, &s);
            for (line = strtok_r(s.string, "\n", &save_ptr); line;
                 line = strtok_r(NULL, "\n", &save_ptr)) {
                syslog(syslog_level, "%s", line);
            }
        }

        if (log_to_file) {
            format_log_message(module, level, VLF_FILE, msg_num,
                               message, args, &s);
            ds_put_char(&s, '\n');
            fputs(ds_cstr(&s), log_file);
            fflush(log_file);
        }

        ds_destroy(&s);
        errno = save_errno;
    }
}

void
vlog(const struct vlog_module *module, enum vlog_level level,
     const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vlog_valist(module, level, message, args);
    va_end(args);
}

void
vlog_fatal_valist(const struct vlog_module *module_,
                  const char *message, va_list args)
{
    struct vlog_module *module = (struct vlog_module *) module_;

    /* Don't log this message to the console to avoid redundancy with the
     * message written by the later ovs_fatal_valist(). */
    module->levels[VLF_CONSOLE] = VLL_OFF;

    vlog_valist(module, VLL_EMER, message, args);
    ovs_fatal_valist(0, message, args);
}

void
vlog_fatal(const struct vlog_module *module, const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vlog_fatal_valist(module, message, args);
    va_end(args);
}

bool
vlog_should_drop(const struct vlog_module *module, enum vlog_level level,
                 struct vlog_rate_limit *rl)
{
    if (!vlog_is_enabled(module, level)) {
        return true;
    }

    if (rl->tokens < VLOG_MSG_TOKENS) {
        time_t now = time_now();
        if (rl->last_fill > now) {
            /* Last filled in the future?  Time must have gone backward, or
             * 'rl' has not been used before. */
            rl->tokens = rl->burst;
        } else if (rl->last_fill < now) {
            unsigned int add = sat_mul(rl->rate, now - rl->last_fill);
            unsigned int tokens = sat_add(rl->tokens, add);
            rl->tokens = MIN(tokens, rl->burst);
            rl->last_fill = now;
        }
        if (rl->tokens < VLOG_MSG_TOKENS) {
            if (!rl->n_dropped) {
                rl->first_dropped = now;
            }
            rl->last_dropped = now;
            rl->n_dropped++;
            return true;
        }
    }
    rl->tokens -= VLOG_MSG_TOKENS;

    if (rl->n_dropped) {
        time_t now = time_now();
        unsigned int first_dropped_elapsed = now - rl->first_dropped;
        unsigned int last_dropped_elapsed = now - rl->last_dropped;

        vlog(module, level,
             "Dropped %u log messages in last %u seconds (most recently, "
             "%u seconds ago) due to excessive rate",
             rl->n_dropped, first_dropped_elapsed, last_dropped_elapsed);

        rl->n_dropped = 0;
    }
    return false;
}

void
vlog_rate_limit(const struct vlog_module *module, enum vlog_level level,
                struct vlog_rate_limit *rl, const char *message, ...)
{
    if (!vlog_should_drop(module, level, rl)) {
        va_list args;

        va_start(args, message);
        vlog_valist(module, level, message, args);
        va_end(args);
    }
}

void
vlog_usage(void)
{
    printf("\nLogging options:\n"
           "  -v, --verbose=MODULE[:FACILITY[:LEVEL]]  set logging levels\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  --log-file[=FILE]       enable logging to specified FILE\n"
           "                          (default: %s/%s.log)\n",
           ovs_logdir(), program_name);
}
