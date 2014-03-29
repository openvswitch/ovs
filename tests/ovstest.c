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

static void
list(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    const struct command *p;

    for(p = commands; p->name != NULL; p++) {
        printf("%s, %d, %d\n", p->name,p->min_args, p->max_args);
    }
}

static void
add_top_level_commands(void)
{
    struct command help_cmd = {"--help", 0, 0, list};

    add_command(&help_cmd);
}

void
ovstest_register(const char *test_name, ovstest_func f,
                  const struct command *sub_commands)
{
    struct command test_cmd;
    int max_args = 0;

    if (sub_commands) {
        const struct command *p;

        for(p = sub_commands; p->name != NULL; p++) {
            if (p->max_args > max_args) {
                max_args = p->max_args;
            }
        }
    }
    max_args++;  /* adding in the sub program */

    test_cmd.name = test_name;
    test_cmd.min_args = 1;
    test_cmd.max_args = max_args;
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

    add_top_level_commands();
    if (argc > 1) {
        run_command(argc - 1, argv + 1, commands);
    }
    cleanup();

    return 0;
}
