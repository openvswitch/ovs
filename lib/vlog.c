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
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <syslog.h>
#include <time.h>
#include "dynamic-string.h"
#include "util.h"

#define THIS_MODULE VLM_vlog

/* Name for each logging level. */
static const char *level_names[VLL_N_LEVELS] = {
    [VLL_EMER] = "EMER",
    [VLL_ERR] = "ERR",
    [VLL_WARN] = "WARN",
    [VLL_DBG] = "DBG",
};

/* Name for each logging facility. */
static const char *facility_names[VLF_N_FACILITIES] = { 
    [VLF_CONSOLE] = "console",
    [VLF_SYSLOG] = "syslog",
};

/* Name for each logging module */
static const char *module_names[VLM_N_MODULES] = { 
#define VLOG_MODULE(NAME) #NAME,
    VLOG_MODULES
#undef VLOG_MODULES
};

static int levels[VLM_N_MODULES][VLF_N_FACILITIES];

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
    return facility_names[facility];
}

/* Returns the logging facility named 'name', or VLF_N_FACILITIES if 'name' is
 * not the name of a logging facility. */
enum vlog_facility
vlog_get_facility_val(const char *name) 
{
    return search_name_array(name, facility_names, ARRAY_SIZE(facility_names));
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
set_facility_level(enum vlog_facility facility, enum vlog_module module,
                   enum vlog_level level)
{
    assert(facility >= 0 && facility < VLF_N_FACILITIES);
    assert(level < VLL_N_LEVELS);

    if (module == VLM_ANY_MODULE) {
        for (module = 0; module < VLM_N_MODULES; module++) {
            levels[module][facility] = level;
        }
    } else {
        levels[module][facility] = level;
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
    char *module, *level, *facility;

    for (module = strtok_r(s, ": \t", &save_ptr); module != NULL;
         module = strtok_r(NULL, ": \t", &save_ptr)) {
        enum vlog_module e_module;
        enum vlog_level e_level;
        enum vlog_facility e_facility;

        facility = strtok_r(NULL, ":", &save_ptr);
        level = strtok_r(NULL, ":", &save_ptr);

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

        e_level = level ? vlog_get_level_val(level) : VLL_DBG;
        if (e_level >= VLL_N_LEVELS) {
            char *msg = xasprintf("unknown level \"%s\"", level);
            free(s);
            return msg;
        }

        vlog_set_levels(e_module, e_facility, e_level);
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
            fatal(0, "processing \"%s\": %s", arg, msg);
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

    now = time(0);
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

    ds_put_format(&s, "                 console    syslog\n");
    ds_put_format(&s, "                 -------    ------\n");

    for (module = 0; module < VLM_N_MODULES; module++) {
        ds_put_format(&s, "%-16s  %4s       %4s\n",
           vlog_get_module_name(module),
           vlog_get_level_name(vlog_get_level(module, VLF_CONSOLE)),
           vlog_get_level_name(vlog_get_level(module, VLF_SYSLOG)));
    }

    return ds_cstr(&s);
}

/* Returns true if a log message emitted for the given 'module' and 'level'
 * would cause some log output, false if that module and level are completely
 * disabled. */
bool
vlog_is_enabled(enum vlog_module module, enum vlog_level level)
{
    return (levels[module][VLF_CONSOLE] >= level
            || levels[module][VLF_SYSLOG] >= level);
}

/* Writes 'message' to the log at the given 'level' and as coming from the
 * given 'module'.
 *
 * Guaranteed to preserve errno. */
void
vlog(enum vlog_module module, enum vlog_level level, const char *message, ...)
{
    bool log_console = levels[module][VLF_CONSOLE] >= level;
    bool log_syslog = levels[module][VLF_SYSLOG] >= level;
    if (log_console || log_syslog) {
        int save_errno = errno;
        static int msg_num;
        const char *module_name = vlog_get_module_name(module);
        const char *level_name = vlog_get_level_name(level);
        time_t now;
        struct tm tm;
        va_list args;
        char s[1024];
        size_t len, time_len;

        now = time(0);
        localtime_r(&now, &tm);

        len = time_len = strftime(s, sizeof s, "%b %d %H:%M:%S|", &tm);
        len += sprintf(s + len, "%05d|%s|%s:",
                       ++msg_num, module_name, level_name);
        va_start(args, message);
        len += vsnprintf(s + len, sizeof s - len, message, args);
        va_end(args);
        if (len >= sizeof s) {
            len = sizeof s;
        }
        if (s[len - 1] == '\n') {
            s[len - 1] = '\0';
        }

        if (log_console) {
            fprintf(stderr, "%s\n", s);
        }

        if (log_syslog) {
            static const int syslog_levels[VLL_N_LEVELS] = {
                [VLL_EMER] = LOG_ALERT,
                [VLL_ERR] = LOG_ERR,
                [VLL_WARN] = LOG_WARNING,
                [VLL_DBG] = LOG_DEBUG,
            };
            char *save_ptr = NULL;
            char *line;

            for (line = strtok_r(s + time_len, "\n", &save_ptr); line != NULL;
                 line = strtok_r(NULL, "\n", &save_ptr)) {
                syslog(syslog_levels[level], "%s", line);
            }
        }
        errno = save_errno;
    }
}
