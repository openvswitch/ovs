/* Copyright (c) 2015 Nicira, Inc.
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

#include <getopt.h>

#include "command-line.h"
#include "daemon.h"
#include "fatal-signal.h"
#include "openvswitch/vlog.h"
#include "ovstest.h"
#include "openvswitch/poll-loop.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(test_unixctl);

static void parse_options(int *argc, char **argvp[], char **unixctl_pathp);
OVS_NO_RETURN static void usage(void);

static void
test_unixctl_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void
test_unixctl_echo(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[], void *aux OVS_UNUSED)
{
    unixctl_command_reply(conn, argv[1]);
}

static void
test_unixctl_echo_error(struct unixctl_conn *conn, int argc OVS_UNUSED,
                        const char *argv[], void *aux OVS_UNUSED)
{
    unixctl_command_reply_error(conn, argv[1]);
}

static void
test_unixctl_log(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[], void *aux OVS_UNUSED)
{
    VLOG_INFO("%s", argv[1]);
    unixctl_command_reply(conn, NULL);
}

static void
test_unixctl_block(struct unixctl_conn *conn OVS_UNUSED, int argc OVS_UNUSED,
                   const char *argv[] OVS_UNUSED, void *aux OVS_UNUSED)
{
    VLOG_INFO("%s", argv[1]);
    unixctl_command_reply(conn, NULL);
}

static int
test_unixctl_main(int argc, char *argv[])
{
    char *unixctl_path = NULL;
    struct unixctl_server *unixctl;
    bool exiting = false;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    fatal_ignore_sigpipe();
    parse_options(&argc, &argv, &unixctl_path);

    daemonize_start(false);
    int retval = unixctl_server_create(unixctl_path, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, test_unixctl_exit, &exiting);
    unixctl_command_register("echo", "ARG", 1, 1, test_unixctl_echo, NULL);
    unixctl_command_register("echo_error", "ARG", 1, 1,
                             test_unixctl_echo_error, NULL);
    unixctl_command_register("log", "ARG", 1, 1, test_unixctl_log, NULL);
    unixctl_command_register("block", "", 0, 0, test_unixctl_block, NULL);
    daemonize_complete();

    VLOG_INFO("Entering run loop.");
    while (!exiting) {
        unixctl_server_run(unixctl);
        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }
        poll_block();
    }
    unixctl_server_destroy(unixctl);

    service_stop();
    return 0;
}

static void
parse_options(int *argcp, char **argvp[], char **unixctl_pathp)
{
    enum {
        OPT_REMOTE = UCHAR_MAX + 1,
        OPT_UNIXCTL,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        {"help",        no_argument, NULL, 'h'},
        {"version",     no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);
    int argc = *argcp;
    char **argv = *argvp;

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(0, 0);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    *argcp -= optind;
    *argvp += optind;
}

static void
usage(void)
{
    printf("%s: Open vSwitch unixctl test program\n"
           "usage: %s [OPTIONS]\n",
           program_name, program_name);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}

OVSTEST_REGISTER("test-unixctl", test_unixctl_main);
