/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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
#include "timeval.h"
#include "util.h"

#define THIS_MODULE VLM_vlog

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

/* Name for each logging module */
static const char *module_names[VLM_N_MODULES] = { 
#define VLOG_MODULE(NAME) #NAME,
#include "vlog-modules.def"
#undef VLOG_MODULE
};

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

/* Current log levels. */
static int levels[VLM_N_MODULES][VLF_N_FACILITIES];

/* For fast checking whether we're logging anything for a given module and
 * level.*/
enum vlog_level min_vlog_levels[VLM_N_MODULES];

/* Time at which vlog was initialized, in milliseconds. */
static long long int boot_time;

/* VLF_FILE configuration. */
static char *log_file_name;
static FILE *log_file;

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
const char *vlog_get_module_name(enum vlog_module module) 
{
    assert(module < VLM_N_MODULES);
    return module_names[module];
}

/* Returns the logging module named 'name', or VLM_N_MODULES if 'name' is not
 * the name of a logging module. */
enum vlog_module
vlog_get_module_val(const char *name) 
{
    return search_name_array(name, module_names, ARRAY_SIZE(module_names));
}

/* Returns the current logging level for the given 'module' and 'facility'. */
enum vlog_level
vlog_get_level(enum vlog_module module, enum vlog_facility facility) 
{
    assert(module < VLM_N_MODULES);
    assert(facility < VLF_N_FACILITIES);
    return levels[module][facility];
}

static void
update_min_level(enum vlog_module module)
{
    enum vlog_level min_level = VLL_EMER;
    enum vlog_facility facility;

    for (facility = 0; facility < VLF_N_FACILITIES; facility++) {
        if (log_file || facility != VLF_FILE) {
            min_level = MAX(min_level, levels[module][facility]); 
        }
    }
    min_vlog_levels[module] = min_level;
}

static void
set_facility_level(enum vlog_facility facility, enum vlog_module module,
                   enum vlog_level level)
{
    assert(facility >= 0 && facility < VLF_N_FACILITIES);
    assert(level < VLL_N_LEVELS);

    if (module == VLM_ANY_MODULE) {
        for (module = 0; module < VLM_N_MODULES; module++) {
            levels[module][facility] = level;
            update_min_level(module);
        }
    } else {
        levels[module][facility] = level;
        update_min_level(module);
    }
}

/* Sets the logging level for the given 'module' and 'facility' to 'level'. */
void
vlog_set_levels(enum vlog_module module, enum vlog_facility facility,
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
    enum vlog_module module;
    int error;

    /* Close old log file. */
    if (log_file) {
        VLOG_WARN("closing log file");
        fclose(log_file);
        log_file = NULL;
    }

    /* Update log file name and free old name.  The ordering is important
     * because 'file_name' might be 'log_file_name' or some suffix of it. */
    old_log_file_name = log_file_name;
    log_file_name = (file_name
                     ? xstrdup(file_name)
                     : xasprintf("%s/%s.log", ofp_logdir, program_name));
    free(old_log_file_name);
    file_name = NULL;           /* Might have been freed. */

    /* Open new log file and update min_levels[] to reflect whether we actually
     * have a log_file. */
    log_file = fopen(log_file_name, "a");
    for (module = 0; module < VLM_N_MODULES; module++) {
        update_min_level(module);
    }

    /* Log success or failure. */
    if (!log_file) {
        VLOG_WARN("failed to open %s for logging: %s",
                  log_file_name, strerror(errno));
        error = errno;
    } else {
        VLOG_WARN("opened log file %s", log_file_name);
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
    return vlog_set_log_file(log_file_name);
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
    char *save_ptr;
    char *s = xstrdup(s_);
    char *module, *facility;

    for (module = strtok_r(s, ": \t", &save_ptr); module != NULL;
         module = strtok_r(NULL, ": \t", &save_ptr)) {
        enum vlog_module e_module;
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
                e_module = VLM_ANY_MODULE;
            } else {
                e_module = vlog_get_module_val(module);
                if (e_module >= VLM_N_MODULES) {
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
            ofp_fatal(0, "processing \"%s\": %s", arg, msg);
        }
    } else {
        vlog_set_levels(VLM_ANY_MODULE, VLF_ANY_FACILITY, VLL_DBG);
    }
}

/* Initializes the logging subsystem. */
void
vlog_init(void) 
{
    time_t now;

    openlog(program_name, LOG_NDELAY, LOG_DAEMON);
    vlog_set_levels(VLM_ANY_MODULE, VLF_ANY_FACILITY, VLL_WARN);

    boot_time = time_msec();
    now = time_now();
    if (now < 0) {
        struct tm tm;
        char s[128];

        localtime_r(&now, &tm);
        strftime(s, sizeof s, "%a, %d %b %Y %H:%M:%S %z", &tm);
        VLOG_ERR("current time is negative: %s (%ld)", s, (long int) now);
    }
}

/* Closes the logging subsystem. */
void
vlog_exit(void) 
{
    closelog(); 
}

/* Print the current logging level for each module. */
char *
vlog_get_levels(void)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    enum vlog_module module;

    ds_put_format(&s, "                 console    syslog    file\n");
    ds_put_format(&s, "                 -------    ------    ------\n");

    for (module = 0; module < VLM_N_MODULES; module++) {
        ds_put_format(&s, "%-16s  %4s       %4s       %4s\n",
           vlog_get_module_name(module),
           vlog_get_level_name(vlog_get_level(module, VLF_CONSOLE)),
           vlog_get_level_name(vlog_get_level(module, VLF_SYSLOG)),
           vlog_get_level_name(vlog_get_level(module, VLF_FILE)));
    }

    return ds_cstr(&s);
}

/* Returns true if a log message emitted for the given 'module' and 'level'
 * would cause some log output, false if that module and level are completely
 * disabled. */
bool
vlog_is_enabled(enum vlog_module module, enum vlog_level level)
{
    return min_vlog_levels[module] >= level;
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
        strlcpy(out, def, out_size);
    }
    return p;
}

static void
format_log_message(enum vlog_module module, enum vlog_level level,
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
        while (isdigit(*p)) {
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
            va_copy(args, args_);
            ds_put_format_valist(s, message, args);
            va_end(args);
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
vlog_valist(enum vlog_module module, enum vlog_level level,
            const char *message, va_list args)
{
    bool log_to_console = levels[module][VLF_CONSOLE] >= level;
    bool log_to_syslog = levels[module][VLF_SYSLOG] >= level;
    bool log_to_file = levels[module][VLF_FILE] >= level && log_file;
    if (log_to_console || log_to_syslog || log_to_file) {
        int save_errno = errno;
        static unsigned int msg_num;
        struct ds s;

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
vlog(enum vlog_module module, enum vlog_level level, const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vlog_valist(module, level, message, args);
    va_end(args);
}

void
vlog_rate_limit(enum vlog_module module, enum vlog_level level,
                struct vlog_rate_limit *rl, const char *message, ...)
{
    va_list args;

    if (!vlog_is_enabled(module, level)) {
        return;
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
            rl->n_dropped++;
            return;
        }
    }
    rl->tokens -= VLOG_MSG_TOKENS;

    va_start(args, message);
    vlog_valist(module, level, message, args);
    va_end(args);

    if (rl->n_dropped) {
        vlog(module, level,
             "Dropped %u messages in last %u seconds due to excessive rate",
             rl->n_dropped, (unsigned int) (time_now() - rl->first_dropped));
        rl->n_dropped = 0;
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
           ofp_logdir, program_name);
}
