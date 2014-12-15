/*
 * Copyright (C) 2014 Cisco Systems, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <openvswitch/compiler.h>
#include <openvswitch/thread.h>
#include <openvswitch/types.h>
#include <openvswitch/util.h>
#include <openvswitch/vconn.h>
#include <openvswitch/vlog.h>

static void
show_version(void)
{
    printf("%s - %s\n",
           ovs_get_program_name(), ovs_get_program_version());
    exit(EXIT_SUCCESS);
}

static void
usage(void)
{
    printf("%s: Open vSwitch library test utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n\n",
           ovs_get_program_name(), ovs_get_program_name());
    vlog_usage();
    exit(EXIT_SUCCESS);
}

static void
parse_options(int argc, char *argv[])
{
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
		{"verbose", optional_argument, NULL, 'v'},
        {NULL, 0, NULL, 0},
    };
    char *short_options = "hVv";

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'V':
            show_version();
            break;

        case 'h':
            usage();
            break;

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
}

int
main(int argc, char *argv[])
{
    ovs_set_program_name(argv[0], "1.0");
    parse_options(argc, argv);

    return 0;
}
