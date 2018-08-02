/*
 * Copyright (c) 2008, 2009, 2010 Nicira, Inc.
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

#ifndef COMMAND_LINE_H
#define COMMAND_LINE_H 1

/* Utilities for command-line parsing. */

#include "compiler.h"

struct option;

/* Command handler context */
struct ovs_cmdl_context {
    /* number of command line arguments */
    int argc;
    /* array of command line arguments */
    char **argv;
    /* private context data defined by the API user */
    void *pvt;
};

typedef void (*ovs_cmdl_handler)(struct ovs_cmdl_context *);

struct ovs_cmdl_command {
    const char *name;
    const char *usage;
    int min_args;
    int max_args;
    ovs_cmdl_handler handler;
    enum { OVS_RO, OVS_RW } mode;    /* Does this command modify things? */
};

char *ovs_cmdl_long_options_to_short_options(const struct option *options);

struct ovs_cmdl_parsed_option {
    const struct option *o;
    char *arg;
};
char *ovs_cmdl_parse_all(int argc, char *argv[], const struct option *,
                         struct ovs_cmdl_parsed_option **, size_t *)
    OVS_WARN_UNUSED_RESULT;

void ovs_cmdl_print_options(const struct option *options);
void ovs_cmdl_print_commands(const struct ovs_cmdl_command *commands);

void ovs_cmdl_run_command(struct ovs_cmdl_context *,
                          const struct ovs_cmdl_command[]);
void ovs_cmdl_run_command_read_only(struct ovs_cmdl_context *,
                                    const struct ovs_cmdl_command[]);

void ovs_cmdl_proctitle_init(int argc, char **argv);
#if defined(__FreeBSD__) || defined(__NetBSD__)
#define ovs_cmdl_proctitle_set setproctitle
#else
void ovs_cmdl_proctitle_set(const char *, ...)
    OVS_PRINTF_FORMAT(1, 2);
#endif
void ovs_cmdl_proctitle_restore(void);

#endif /* command-line.h */
