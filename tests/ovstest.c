/*
 * Copyright (c) 2014 Nicira, Inc.
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

/* The mother of all test programs that links with libopevswitch.la */

#include <config.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include "command-line.h"
#include "ovstest.h"
#include "dynamic-string.h"
#include "util.h"

static struct command *commands = NULL;
static size_t n_commands = 0;
static size_t allocated_commands = 0;

static void
add_command(struct command *cmd)
{
    const struct command nil = {NULL, 0, 0, NULL};

    while (n_commands + 1 >= allocated_commands) {
        commands = x2nrealloc(commands, &allocated_commands,
                              sizeof *cmd);
    }

    commands[n_commands] = *cmd;
    commands[n_commands + 1] = nil;
    n_commands++;
}

#define OVSTEST_USAGE \
"TEST [TESTARGS] where 'TEST' is a string, 'TESTARGS' are optional \n"\
"arguments of the TEST"

static void
flush_help_string(struct ds *ds)
{
    if (ds->length > 2 ) {
        ds->length -= 2;
        printf ("%s\n", ds_cstr(ds));
        ds_clear(ds);
    }
}

static void
help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const struct command *p;
    struct ds test_names = DS_EMPTY_INITIALIZER;
    const int linesize = 70;

    printf("%s: the big test executable\n"
           "usage: %s TEST [TESTARGS]\n"
           "where TEST is one of the following. \n\n",
           program_name, program_name);

    for(p = commands; p->name != NULL; p++) {
        if (*p->name != '-') { /* Skip internal commands */
            ds_put_format(&test_names, "%s, ", p->name);
            if ((test_names.length) >= linesize) {
                flush_help_string(&test_names);
            }
        }
    }
    flush_help_string(&test_names);
    ds_destroy(&test_names);
}

static void
add_top_level_commands(void)
{
    struct command help_cmd = {"--help", 0, 0, help};

    add_command(&help_cmd);
}

void
ovstest_register(const char *test_name, ovstest_func f)
{
    struct command test_cmd;

    test_cmd.name = test_name;
    test_cmd.min_args = 0;
    test_cmd.max_args = INT_MAX;
    test_cmd.handler = f;

    add_command(&test_cmd);
}

static void
cleanup(void)
{
    if (allocated_commands) {
        free(commands);
    }
}

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);

    if (argc < 2) {
        ovs_fatal(0, "expect test program to be specified; "
                  "use --help for usage");
    }

    add_top_level_commands();
    if (argc > 1) {
        run_command(argc - 1, argv + 1, commands);
    }
    cleanup();

    return 0;
}
