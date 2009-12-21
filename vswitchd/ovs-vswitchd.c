/* Copyright (c) 2008, 2009 Nicira Networks
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

#include "bridge.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dpif.h"
#include "fault.h"
#include "leak-checker.h"
#include "netdev.h"
#include "ovsdb-idl.h"
#include "poll-loop.h"
#include "proc-net-compat.h"
#include "process.h"
#include "signals.h"
#include "stream.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "vswitchd/vswitch-idl.h"

#include "vlog.h"
#define THIS_MODULE VLM_vswitchd

static const char *parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct signal *sighup;
    struct ovsdb_idl *idl;
    const char *remote;
    bool need_reconfigure;
    bool inited;
    unsigned int idl_seqno;
    int retval;

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    remote = parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    sighup = signal_register(SIGHUP);
    process_init();

    die_if_already_running();
    daemonize_start();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        ovs_fatal(retval, "could not listen for control connections");
    }

    daemonize_complete();

    idl = ovsdb_idl_create(remote, &ovsrec_idl_class);
    idl_seqno = ovsdb_idl_get_seqno(idl);

    need_reconfigure = false;
    inited = false;
    for (;;) {
        if (signal_poll(sighup)) {
            vlog_reopen_log_file();
        }
        if (inited && bridge_run()) {
            need_reconfigure = true;
        }
        ovsdb_idl_run(idl);
        if (idl_seqno != ovsdb_idl_get_seqno(idl)) {
            idl_seqno = ovsdb_idl_get_seqno(idl);
            need_reconfigure = true;
        }
        if (need_reconfigure) {
            const struct ovsrec_open_vswitch *cfg;

            need_reconfigure = false;
            cfg = ovsrec_open_vswitch_first(idl);
            if (cfg) {
                if (inited) {
                    bridge_reconfigure(cfg);
                } else {
                    bridge_init(cfg);
                    inited = true;
                }
            }
        }
        unixctl_server_run(unixctl);
        dp_run();
        netdev_run();

        signal_wait(sighup);
        if (inited) {
            bridge_wait();
        }
        ovsdb_idl_wait(idl);
        unixctl_server_wait(unixctl);
        dp_wait();
        netdev_wait();
        poll_block();
    }

    return 0;
}

static const char *
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_FAKE_PROC_NET,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        {"fake-proc-net", no_argument, 0, OPT_FAKE_PROC_NET},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        VCONN_SSL_LONG_OPTIONS
        {"peer-ca-cert", required_argument, 0, OPT_PEER_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    int error;

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

        case OPT_FAKE_PROC_NET:
            error = proc_net_compat_init();
            if (error) {
                ovs_fatal(error, "failed to initialize /proc/net "
                          "compatibility");
            }
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        VCONN_SSL_OPTION_HANDLERS
        LEAK_CHECKER_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        case OPT_PEER_CA_CERT:
            vconn_ssl_set_peer_ca_cert_file(optarg);
            break;
#endif

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
        ovs_fatal(0, "database socket is only non-option argument; "
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
    printf("\nLegacy compatibility options:\n"
           " --fake-proc-net          simulate some files in /proc/net\n"
           "\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    exit(EXIT_SUCCESS);
}
