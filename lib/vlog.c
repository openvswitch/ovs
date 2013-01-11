/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "coverage.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "ofpbuf.h"
#include "sat-math.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "worker.h"

VLOG_DEFINE_THIS_MODULE(vlog);

COVERAGE_DEFINE(vlog_recursive);

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

/* VLF_FILE configuration. */
static char *log_file_name;
static int log_fd = -1;

/* vlog initialized? */
static bool vlog_inited;

static void format_log_message(const struct vlog_module *, enum vlog_level,
                               enum vlog_facility, unsigned int msg_num,
                               const char *message, va_list, struct ds *)
    PRINTF_FORMAT(5, 0);
static void vlog_write_file(struct ds *);
static void vlog_update_async_log_fd(void);

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
        if (log_fd >= 0 || facility != VLF_FILE) {
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
    if (log_fd >= 0) {
        VLOG_INFO("closing log file");
        close(log_fd);
        log_fd = -1;
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
    log_fd = open(log_file_name, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (log_fd >= 0) {
        vlog_update_async_log_fd();
    }
    for (mp = vlog_modules; mp < &vlog_modules[n_vlog_modules]; mp++) {
        update_min_level(*mp);
    }

    /* Log success or failure. */
    if (log_fd < 0) {
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
    struct stat old, new;

    /* Skip re-opening if there's nothing to reopen. */
    if (!log_file_name) {
        return 0;
    }

    /* Skip re-opening if it would be a no-op because the old and new files are
     * the same.  (This avoids writing "closing log file" followed immediately
     * by "opened log file".) */
    if (log_fd >= 0
        && !fstat(log_fd, &old)
        && !stat(log_file_name, &new)
        && old.st_dev == new.st_dev
        && old.st_ino == new.st_ino) {
        return 0;
    }

    return vlog_set_log_file(log_file_name);
}

/* Set debugging levels.  Returns null if successful, otherwise an error
 * message that the caller must free(). */
char *
vlog_set_levels_from_string(const char *s_)
{
    char *s = xstrdup(s_);
    char *save_ptr = NULL;
    char *msg = NULL;
    char *word;

    word = strtok_r(s, " ,:\t", &save_ptr);
    if (word && !strcasecmp(word, "PATTERN")) {
        enum vlog_facility facility;

        word = strtok_r(NULL, " ,:\t", &save_ptr);
        if (!word) {
            msg = xstrdup("missing facility");
            goto exit;
        }

        facility = (!strcasecmp(word, "ANY")
                    ? VLF_ANY_FACILITY
                    : vlog_get_facility_val(word));
        if (facility == VLF_N_FACILITIES) {
            msg = xasprintf("unknown facility \"%s\"", word);
            goto exit;
        }
        vlog_set_pattern(facility, save_ptr);
    } else {
        struct vlog_module *module = NULL;
        enum vlog_level level = VLL_N_LEVELS;
        enum vlog_facility facility = VLF_N_FACILITIES;

        for (; word != NULL; word = strtok_r(NULL, " ,:\t", &save_ptr)) {
            if (!strcasecmp(word, "ANY")) {
                continue;
            } else if (vlog_get_facility_val(word) != VLF_N_FACILITIES) {
                if (facility != VLF_N_FACILITIES) {
                    msg = xstrdup("cannot specify multiple facilities");
                    goto exit;
                }
                facility = vlog_get_facility_val(word);
            } else if (vlog_get_level_val(word) != VLL_N_LEVELS) {
                if (level != VLL_N_LEVELS) {
                    msg = xstrdup("cannot specify multiple levels");
                    goto exit;
                }
                level = vlog_get_level_val(word);
            } else if (vlog_module_from_name(word)) {
                if (module) {
                    msg = xstrdup("cannot specify multiple modules");
                    goto exit;
                }
                module = vlog_module_from_name(word);
            } else {
                msg = xasprintf("no facility, level, or module \"%s\"", word);
                goto exit;
            }
        }

        if (facility == VLF_N_FACILITIES) {
            facility = VLF_ANY_FACILITY;
        }
        if (level == VLL_N_LEVELS) {
            level = VLL_DBG;
        }
        vlog_set_levels(module, facility, level);
    }

exit:
    free(s);
    return msg;
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
vlog_unixctl_set(struct unixctl_conn *conn, int argc, const char *argv[],
                 void *aux OVS_UNUSED)
{
    int i;

    for (i = 1; i < argc; i++) {
        char *msg = vlog_set_levels_from_string(argv[i]);
        if (msg) {
            unixctl_command_reply_error(conn, msg);
            free(msg);
            return;
        }
    }
    unixctl_command_reply(conn, NULL);
}

static void
vlog_unixctl_list(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    char *msg = vlog_get_levels();
    unixctl_command_reply(conn, msg);
    free(msg);
}

static void
vlog_unixctl_reopen(struct unixctl_conn *conn, int argc OVS_UNUSED,
                    const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    if (log_file_name) {
        int error = vlog_reopen_log_file();
        if (error) {
            unixctl_command_reply_error(conn, strerror(errno));
        } else {
            unixctl_command_reply(conn, NULL);
        }
    } else {
        unixctl_command_reply_error(conn, "Logging to file not configured");
    }
}

/* Initializes the logging subsystem and registers its unixctl server
 * commands. */
void
vlog_init(void)
{
    static char *program_name_copy;
    time_t now;

    if (vlog_inited) {
        return;
    }
    vlog_inited = true;

    /* openlog() is allowed to keep the pointer passed in, without making a
     * copy.  The daemonize code sometimes frees and replaces 'program_name',
     * so make a private copy just for openlog().  (We keep a pointer to the
     * private copy to suppress memory leak warnings in case openlog() does
     * make its own copy.) */
    program_name_copy = program_name ? xstrdup(program_name) : NULL;
    openlog(program_name_copy, LOG_NDELAY, LOG_DAEMON);

    now = time_wall();
    if (now < 0) {
        struct tm tm;
        char s[128];

        gmtime_r(&now, &tm);
        strftime(s, sizeof s, "%a, %d %b %Y %H:%M:%S", &tm);
        VLOG_ERR("current time is negative: %s (%ld)", s, (long int) now);
    }

    unixctl_command_register(
        "vlog/set", "{spec | PATTERN:facility:pattern}",
        1, INT_MAX, vlog_unixctl_set, NULL);
    unixctl_command_register("vlog/list", "", 0, 0, vlog_unixctl_list, NULL);
    unixctl_command_register("vlog/reopen", "", 0, 0,
                             vlog_unixctl_reopen, NULL);
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
            ds_put_strftime(s, tmp, false);
            break;
        case 'D':
            p = fetch_braces(p, "%Y-%m-%d %H:%M:%S", tmp, sizeof tmp);
            ds_put_strftime(s, tmp, true);
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
            ds_put_format(s, "%lld", time_msec() - time_boot_msec());
            break;
        case 't':
            ds_put_cstr(s, subprogram_name[0] ? subprogram_name : "main");
            break;
        case 'T':
            if (subprogram_name[0]) {
                ds_put_format(s, "(%s)", subprogram_name);
            }
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
    bool log_to_file = module->levels[VLF_FILE] >= level && log_fd >= 0;
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
            vlog_write_file(&s);
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

/* Logs 'message' to 'module' at maximum verbosity, then exits with a failure
 * exit code.  Always writes the message to stderr, even if the console
 * facility is disabled.
 *
 * Choose this function instead of vlog_abort_valist() if the daemon monitoring
 * facility shouldn't automatically restart the current daemon.  */
void
vlog_fatal_valist(const struct vlog_module *module_,
                  const char *message, va_list args)
{
    struct vlog_module *module = CONST_CAST(struct vlog_module *, module_);

    /* Don't log this message to the console to avoid redundancy with the
     * message written by the later ovs_fatal_valist(). */
    module->levels[VLF_CONSOLE] = VLL_OFF;

    vlog_valist(module, VLL_EMER, message, args);
    ovs_fatal_valist(0, message, args);
}

/* Logs 'message' to 'module' at maximum verbosity, then exits with a failure
 * exit code.  Always writes the message to stderr, even if the console
 * facility is disabled.
 *
 * Choose this function instead of vlog_abort() if the daemon monitoring
 * facility shouldn't automatically restart the current daemon.  */
void
vlog_fatal(const struct vlog_module *module, const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vlog_fatal_valist(module, message, args);
    va_end(args);
}

/* Logs 'message' to 'module' at maximum verbosity, then calls abort().  Always
 * writes the message to stderr, even if the console facility is disabled.
 *
 * Choose this function instead of vlog_fatal_valist() if the daemon monitoring
 * facility should automatically restart the current daemon.  */
void
vlog_abort_valist(const struct vlog_module *module_,
                  const char *message, va_list args)
{
    struct vlog_module *module = (struct vlog_module *) module_;

    /* Don't log this message to the console to avoid redundancy with the
     * message written by the later ovs_abort_valist(). */
    module->levels[VLF_CONSOLE] = VLL_OFF;

    vlog_valist(module, VLL_EMER, message, args);
    ovs_abort_valist(0, message, args);
}

/* Logs 'message' to 'module' at maximum verbosity, then calls abort().  Always
 * writes the message to stderr, even if the console facility is disabled.
 *
 * Choose this function instead of vlog_fatal() if the daemon monitoring
 * facility should automatically restart the current daemon.  */
void
vlog_abort(const struct vlog_module *module, const char *message, ...)
{
    va_list args;

    va_start(args, message);
    vlog_abort_valist(module, message, args);
    va_end(args);
}

bool
vlog_should_drop(const struct vlog_module *module, enum vlog_level level,
                 struct vlog_rate_limit *rl)
{
    if (!vlog_is_enabled(module, level)) {
        return true;
    }

    if (!token_bucket_withdraw(&rl->token_bucket, VLOG_MSG_TOKENS)) {
        time_t now = time_now();
        if (!rl->n_dropped) {
            rl->first_dropped = now;
        }
        rl->last_dropped = now;
        rl->n_dropped++;
        return true;
    }

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
           "  -v, --verbose=[SPEC]    set logging levels\n"
           "  -v, --verbose           set maximum verbosity level\n"
           "  --log-file[=FILE]       enable logging to specified FILE\n"
           "                          (default: %s/%s.log)\n",
           ovs_logdir(), program_name);
}

static bool vlog_async_inited = false;

static worker_request_func vlog_async_write_request_cb;

static void
vlog_write_file(struct ds *s)
{
    if (worker_is_running()) {
        static bool in_worker_request = false;
        if (!in_worker_request) {
            in_worker_request = true;

            worker_request(s->string, s->length,
                           &log_fd, vlog_async_inited ? 0 : 1,
                           vlog_async_write_request_cb, NULL, NULL);
            vlog_async_inited = true;

            in_worker_request = false;
            return;
        } else {
            /* We've been entered recursively.  This can happen if
             * worker_request(), or a function that it calls, tries to log
             * something.  We can't call worker_request() recursively, so fall
             * back to writing the log file directly. */
            COVERAGE_INC(vlog_recursive);
        }
    }
    ignore(write(log_fd, s->string, s->length));
}

static void
vlog_update_async_log_fd(void)
{
    if (worker_is_running()) {
        worker_request(NULL, 0, &log_fd, 1, vlog_async_write_request_cb,
                       NULL, NULL);
        vlog_async_inited = true;
    }
}

static void
vlog_async_write_request_cb(struct ofpbuf *request,
                            const int *fd, size_t n_fds)
{
    if (n_fds > 0) {
        if (log_fd >= 0) {
            close(log_fd);
        }
        log_fd = *fd;
    }

    if (request->size > 0) {
        ignore(write(log_fd, request->data, request->size));
    }
}
