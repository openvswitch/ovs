/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "dpctl.h"
#include "fatal-signal.h"
#include "odp-util.h"
#include "ofp-parse.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

static struct dpctl_params dpctl_p;

OVS_NO_RETURN static void usage(void *userdata OVS_UNUSED);
static void parse_options(int argc, char *argv[]);

static void
dpctl_print(void *userdata OVS_UNUSED, bool error, const char *msg)
{
    FILE *outfile = error ? stderr : stdout;
    fputs(msg, outfile);
}

int
main(int argc, char *argv[])
{
    int error;
    set_program_name(argv[0]);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    dpctl_p.is_appctl = false;
    dpctl_p.output = dpctl_print;
    dpctl_p.usage = usage;

    error = dpctl_run_command(argc - optind, (const char **) argv + optind,
                              &dpctl_p);
    return error ? EXIT_FAILURE : EXIT_SUCCESS;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_CLEAR = UCHAR_MAX + 1,
        OPT_MAY_CREATE,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"statistics", no_argument, NULL, 's'},
        {"clear", no_argument, NULL, OPT_CLEAR},
        {"may-create", no_argument, NULL, OPT_MAY_CREATE},
        {"more", no_argument, NULL, 'm'},
        {"timeout", required_argument, NULL, 't'},
        {"help", no_argument, NULL, 'h'},
        {"option", no_argument, NULL, 'o'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 's':
            dpctl_p.print_statistics = true;
            break;

        case OPT_CLEAR:
            dpctl_p.zero_statistics = true;
            break;

        case OPT_MAY_CREATE:
            dpctl_p.may_create = true;
            break;

        case 'm':
            dpctl_p.verbosity++;
            break;

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
            usage(NULL);

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);
}

static void
usage(void *userdata OVS_UNUSED)
{
    printf("%s: Open vSwitch datapath management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "  add-dp DP [IFACE...]     add new datapath DP (with IFACEs)\n"
           "  del-dp DP                delete local datapath DP\n"
           "  add-if DP IFACE...       add each IFACE as a port on DP\n"
           "  set-if DP IFACE...       reconfigure each IFACE within DP\n"
           "  del-if DP IFACE...       delete each IFACE from DP\n"
           "  dump-dps                 display names of all datapaths\n"
           "  show                     show basic info on all datapaths\n"
           "  show DP...               show basic info on each DP\n"
           "  dump-flows [DP]          display flows in DP\n"
           "  add-flow [DP] FLOW ACTIONS add FLOW with ACTIONS to DP\n"
           "  mod-flow [DP] FLOW ACTIONS change FLOW actions to ACTIONS in DP\n"
           "  get-flow [DP] ufid:UFID    fetch flow corresponding to UFID\n"
           "  del-flow [DP] FLOW         delete FLOW from DP\n"
           "  del-flows [DP]             delete all flows from DP\n"
           "Each IFACE on add-dp, add-if, and set-if may be followed by\n"
           "comma-separated options.  See ovs-dpctl(8) for syntax, or the\n"
           "Interface table in ovs-vswitchd.conf.db(5) for an options list.\n"
           "For COMMAND dump-flows, add-flow, mod-flow, del-flow and\n"
           "del-flows, DP is optional if there is only one datapath.\n",
           program_name, program_name);
    vlog_usage();
    printf("\nOptions for show and mod-flow:\n"
           "  -s,  --statistics           print statistics for port or flow\n"
           "\nOptions for dump-flows:\n"
           "  -m, --more                  increase verbosity of output\n"
           "\nOptions for mod-flow:\n"
           "  --may-create                create flow if it doesn't exist\n"
           "  --clear                     reset existing stats to zero\n"
           "\nOther options:\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}
