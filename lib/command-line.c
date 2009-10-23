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

#include <config.h>
#include "command-line.h"
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include "util.h"
#include "vlog.h"

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
                ovs_fatal(0, "'%s' command requires at least %d arguments",
                          p->name, p->min_args);
            } else if (n_arg > p->max_args) {
                ovs_fatal(0, "'%s' command takes at most %d arguments",
                          p->name, p->max_args);
            } else {
                p->handler(argc, argv);
                if (ferror(stdout)) {
                    ovs_fatal(0, "write to stdout failed");
                }
                if (ferror(stderr)) {
                    ovs_fatal(0, "write to stderr failed");
                }
                return;
            }
        }
    }

    ovs_fatal(0, "unknown command '%s'; use --help for help", argv[0]);
}
