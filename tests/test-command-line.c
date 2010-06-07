/*
 * Copyright (c) 2010 Nicira Networks.
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
#include "test-command-line.h"
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include "command-line.h"
#include "timeval.h"
#include "util.h"
#include "vlog.h"

static void
test_usage(const struct command commands[])
{
    const struct command *p;

    printf("%s: an Open vSwitch test utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n\n"
           "Valid commands:\n" ,
           program_name, program_name);

    for (p = commands; p->name; p++) {
        int i;

        printf("  %s", p->name);
        for (i = 0; i < p->min_args; i++) {
            printf(" ARG%d", i + 1);
        }
        if (p->max_args == INT_MAX) {
            printf(" [ARG...]");
        } else if (p->max_args > p->min_args) {
            for (i = p->min_args; i < p->max_args; i++) {
                putchar(' ');
                if (i == p->min_args) {
                    putchar('[');
                }
                printf("ARG%d", i + 1);
            }
            putchar(']');
        }
        putchar('\n');
    }
    vlog_usage();
    printf("\nOther options:\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n");
    exit(EXIT_SUCCESS);
}

/* Parses options for test programs that don't have any special needs.
 * Prints --help output based on 'commands'. */
void
parse_test_options(int argc, char *argv[],
                   const struct command commands[])
{
    static struct option long_options[] = {
        {"timeout", required_argument, 0, 't'},
        {"verbose", optional_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ovs_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;

        case 'h':
            test_usage(commands);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

