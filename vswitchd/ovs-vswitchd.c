/* Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks
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

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_MLOCKALL
#include <sys/mman.h>
#endif

#include "bridge.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dummy.h"
#include "leak-checker.h"
#include "netdev.h"
#include "ovsdb-idl.h"
#include "poll-loop.h"
#include "process.h"
#include "signals.h"
#include "stream-ssl.h"
#include "stream.h"
#include "stress.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"
#include "vswitchd/vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(vswitchd);

static unixctl_cb_func ovs_vswitchd_exit;

static const char *parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct signal *sighup;
    const char *remote;
    bool exiting;
    int retval;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    stress_init_command();
    remote = parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    sighup = signal_register(SIGHUP);
    process_init();
    ovsrec_init();

    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", ovs_vswitchd_exit, &exiting);

    bridge_init(remote);
    exiting = false;
    while (!exiting) {
        if (signal_poll(sighup)) {
            vlog_reopen_log_file();
        }
        bridge_run();
        unixctl_server_run(unixctl);
        netdev_run();

        signal_wait(sighup);
        bridge_wait();
        unixctl_server_wait(unixctl);
        netdev_wait();
        if (exiting) {
            poll_immediate_wake();
        }
        poll_block();
    }
    bridge_exit();
    unixctl_server_destroy(unixctl);

    return 0;
}

static const char *
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_MLOCKALL,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_ENABLE_DUMMY,
        DAEMON_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        {"mlockall",    no_argument, 0, OPT_MLOCKALL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        STREAM_SSL_LONG_OPTIONS
        {"peer-ca-cert", required_argument, 0, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
#endif
        {"enable-dummy", no_argument, 0, OPT_ENABLE_DUMMY},
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'H':
        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(OFP_VERSION, OFP_VERSION);
            exit(EXIT_SUCCESS);

        case OPT_MLOCKALL:
#ifdef HAVE_MLOCKALL
            if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
                VLOG_ERR("mlockall failed: %s", strerror(errno));
            }
#else
            VLOG_ERR("mlockall not supported on this system");
#endif
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        LEAK_CHECKER_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;
#endif

        case OPT_ENABLE_DUMMY:
            dummy_enable();
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    if (argc != 1) {
        VLOG_FATAL("database socket is only non-option argument; "
                   "use --help for usage");
    }

    return argv[0];
}

static void
usage(void)
{
    printf("%s: Open vSwitch daemon\n"
           "usage: %s [OPTIONS] DATABASE\n"
           "where DATABASE is a socket on which ovsdb-server is listening.\n",
           program_name, program_name);
    stream_usage("DATABASE", true, false, true);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    exit(EXIT_SUCCESS);
}

static void
ovs_vswitchd_exit(struct unixctl_conn *conn, const char *args OVS_UNUSED,
                  void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, 200, NULL);
}
