/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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
#include "command-line.h"
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include "util.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(command_line);

/* Given the GNU-style long options in 'options', returns a string that may be
 * passed to getopt() with the corresponding short options.  The caller is
 * responsible for freeing the string. */
char *
long_options_to_short_options(const struct option options[])
{
    char short_options[UCHAR_MAX * 3 + 1];
    char *p = short_options;

    for (; options->name; options++) {
        const struct option *o = options;
        if (o->flag == NULL && o->val > 0 && o->val <= UCHAR_MAX) {
            *p++ = o->val;
            if (o->has_arg == required_argument) {
                *p++ = ':';
            } else if (o->has_arg == optional_argument) {
                *p++ = ':';
                *p++ = ':';
            }
        }
    }
    *p = '\0';

    return xstrdup(short_options);
}

/* Runs the command designated by argv[0] within the command table specified by
 * 'commands', which must be terminated by a command whose 'name' member is a
 * null pointer.
 *
 * Command-line options should be stripped off, so that a typical invocation
 * looks like "run_command(argc - optind, argv + optind, my_commands);". */
void
run_command(int argc, char *argv[], const struct command commands[])
{
    const struct command *p;

    if (argc < 1) {
        ovs_fatal(0, "missing command name; use --help for help");
    }

    for (p = commands; p->name != NULL; p++) {
        if (!strcmp(p->name, argv[0])) {
            int n_arg = argc - 1;
            if (n_arg < p->min_args) {
                VLOG_FATAL( "'%s' command requires at least %d arguments",
                            p->name, p->min_args);
            } else if (n_arg > p->max_args) {
                VLOG_FATAL("'%s' command takes at most %d arguments",
                           p->name, p->max_args);
            } else {
                p->handler(argc, argv);
                if (ferror(stdout)) {
                    VLOG_FATAL("write to stdout failed");
                }
                if (ferror(stderr)) {
                    VLOG_FATAL("write to stderr failed");
                }
                return;
            }
        }
    }

    VLOG_FATAL("unknown command '%s'; use --help for help", argv[0]);
}

/* Process title. */

#ifdef LINUX_DATAPATH
static char *argv_start;       /* Start of command-line arguments in memory. */
static size_t argv_size;       /* Number of bytes of command-line arguments. */
static char *saved_proctitle;  /* Saved command-line arguments. */

/* Prepares the process so that proctitle_set() can later succeed.
 *
 * This modifies the argv[] array so that it no longer points into the memory
 * that it originally does.  Later, proctitle_set() might overwrite that
 * memory.  That means that this function should be called before anything else
 * that accesses the process's argv[] array.  Ideally, it should be called
 * before anything else, period, at the very beginning of program
 * execution.  */
void
proctitle_init(int argc, char **argv)
{
    int i;

    if (!argc || !argv[0]) {
        /* This situation should never occur, but... */
        return;
    }

    /* Specialized version of first loop iteration below. */
    argv_start = argv[0];
    argv_size = strlen(argv[0]) + 1;
    argv[0] = xstrdup(argv[0]);

    for (i = 1; i < argc; i++) {
        size_t size = strlen(argv[i]) + 1;

        /* Add (argv[i], strlen(argv[i])+1) to (argv_start, argv_size). */
        if (argv[i] + size == argv_start) {
            /* Arguments grow downward in memory. */
            argv_start -= size;
            argv_size += size;
        } else if (argv[i] == argv_start + argv_size) {
            /* Arguments grow upward in memory. */
            argv_size += size;
        } else {
            /* Arguments not contiguous.  (Is this really Linux?) */
        }

        /* Copy out the old argument so we can reuse the space. */
        argv[i] = xstrdup(argv[i]);
    }
}

/* Changes the name of the process, as shown by "ps", to the program name
 * followed by 'format', which is formatted as if by printf(). */
void
proctitle_set(const char *format, ...)
{
    va_list args;
    int n;

    if (!argv_start || argv_size < 8) {
        return;
    }

    if (!saved_proctitle) {
        saved_proctitle = xmemdup(argv_start, argv_size);
    }

    va_start(args, format);
    n = snprintf(argv_start, argv_size, "%s: ", program_name);
    if (n < argv_size) {
        n += vsnprintf(argv_start + n, argv_size - n, format, args);
    }
    if (n >= argv_size) {
        /* The name is too long, so add an ellipsis at the end. */
        strcpy(&argv_start[argv_size - 4], "...");
    } else {
        /* Fill the extra space with null bytes, so that trailing bytes don't
         * show up in the command line. */
        memset(&argv_start[n], '\0', argv_size - n);
    }
    va_end(args);
}

/* Restores the process's original command line, as seen by "ps". */
void
proctitle_restore(void)
{
    if (saved_proctitle) {
        memcpy(argv_start, saved_proctitle, argv_size);
        free(saved_proctitle);
        saved_proctitle = NULL;
    }
}
#else  /* !LINUX_DATAPATH*/
/* Stubs that don't do anything on non-Linux systems. */

void
proctitle_init(int argc OVS_UNUSED, char **argv OVS_UNUSED)
{
}

#ifndef __FreeBSD__
/* On FreeBSD we #define this to setproctitle. */
void
proctitle_set(const char *format OVS_UNUSED, ...)
{
}
#endif

void
proctitle_restore(void)
{
}
#endif  /* !LINUX_DATAPATH */
