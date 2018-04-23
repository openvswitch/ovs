/* Copyright (c) 2015, 2016 Nicira, Inc.
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

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "openvswitch/dynamic-string.h"
#include "fatal-signal.h"
#include "openvswitch/poll-loop.h"
#include "stream.h"
#include "stream-ssl.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "ovn/lib/ovn-sb-idl.h"
#include "ovn/lib/ovn-util.h"
#include "vtep/vtep-idl.h"

#include "binding.h"
#include "gateway.h"
#include "vtep.h"
#include "ovn-controller-vtep.h"

static unixctl_cb_func ovn_controller_vtep_exit;

static void parse_options(int argc, char *argv[]);
OVS_NO_RETURN static void usage(void);

static char *vtep_remote;
static char *ovnsb_remote;
static char *default_db_;

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    bool exiting;
    int retval;

    ovs_cmdl_proctitle_init(argc, argv);
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();

    daemonize_start(false);

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }
    unixctl_command_register("exit", "", 0, 0, ovn_controller_vtep_exit,
                             &exiting);

    daemonize_complete();

    /* Connect to VTEP database. */
    struct ovsdb_idl_loop vtep_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(vtep_remote, &vteprec_idl_class, true, true));
    ovsdb_idl_get_initial_snapshot(vtep_idl_loop.idl);

    /* Connect to OVN SB database. */
    struct ovsdb_idl_loop ovnsb_idl_loop = OVSDB_IDL_LOOP_INITIALIZER(
        ovsdb_idl_create(ovnsb_remote, &sbrec_idl_class, true, true));
    ovsdb_idl_get_initial_snapshot(ovnsb_idl_loop.idl);

    /* Main loop. */
    exiting = false;
    while (!exiting) {
        struct controller_vtep_ctx ctx = {
            .vtep_idl = vtep_idl_loop.idl,
            .vtep_idl_txn = ovsdb_idl_loop_run(&vtep_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        gateway_run(&ctx);
        binding_run(&ctx);
        vtep_run(&ctx);
        unixctl_server_run(unixctl);

        unixctl_server_wait(unixctl);
        if (exiting) {
            poll_immediate_wake();
        }
        ovsdb_idl_loop_commit_and_wait(&vtep_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
        poll_block();
        if (should_service_stop()) {
            exiting = true;
        }
    }

    /* It's time to exit.  Clean up the databases. */
    bool done = false;
    while (!done) {
        struct controller_vtep_ctx ctx = {
            .vtep_idl = vtep_idl_loop.idl,
            .vtep_idl_txn = ovsdb_idl_loop_run(&vtep_idl_loop),
            .ovnsb_idl = ovnsb_idl_loop.idl,
            .ovnsb_idl_txn = ovsdb_idl_loop_run(&ovnsb_idl_loop),
        };

        /* Run all of the cleanup functions, even if one of them returns false.
         * We're done if all of them return true. */
        done = binding_cleanup(&ctx);
        done = gateway_cleanup(&ctx) && done;
        done = vtep_cleanup(&ctx) && done;
        if (done) {
            poll_immediate_wake();
        }

        ovsdb_idl_loop_commit_and_wait(&vtep_idl_loop);
        ovsdb_idl_loop_commit_and_wait(&ovnsb_idl_loop);
        poll_block();
    }

    unixctl_server_destroy(unixctl);

    ovsdb_idl_loop_destroy(&vtep_idl_loop);
    ovsdb_idl_loop_destroy(&ovnsb_idl_loop);

    free(ovnsb_remote);
    free(vtep_remote);
    free(default_db_);
    service_stop();

    exit(retval);
}

static const char *
default_db(void)
{
    if (!default_db_) {
        default_db_ = xasprintf("unix:%s/db.sock", ovs_rundir());
    }
    return default_db_;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_PEER_CA_CERT = UCHAR_MAX + 1,
        OPT_BOOTSTRAP_CA_CERT,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
    };

    static struct option long_options[] = {
        {"ovnsb-db", required_argument, NULL, 'd'},
        {"vtep-db", required_argument, NULL, 'D'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        VLOG_LONG_OPTIONS,
        DAEMON_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"peer-ca-cert", required_argument, NULL, OPT_PEER_CA_CERT},
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {NULL, 0, NULL, 0}
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'd':
            ovnsb_remote = xstrdup(optarg);
            break;

        case 'D':
            vtep_remote = xstrdup(optarg);
            break;

        case 'h':
            usage();

        case 'V':
            ovs_print_version(OFP13_VERSION, OFP13_VERSION);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case OPT_PEER_CA_CERT:
            stream_ssl_set_peer_ca_cert_file(optarg);
            break;

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
            break;

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    if (!ovnsb_remote) {
        ovnsb_remote = xstrdup(default_sb_db());
    }

    if (!vtep_remote) {
        vtep_remote = xstrdup(default_db());
    }
}

static void
usage(void)
{
    printf("\
%s: OVN controller VTEP\n\
usage %s [OPTIONS]\n\
\n\
Options:\n\
  --vtep-db=DATABASE        connect to vtep database at DATABASE\n\
                            (default: %s)\n\
  --ovnsb-db=DATABASE       connect to ovn-sb database at DATABASE\n\
                            (default: %s)\n\
  -h, --help                display this help message\n\
  -o, --options             list available options\n\
  -V, --version             display version information\n\
", program_name, program_name, default_db(), default_db());
    stream_usage("database", true, false, true);
    daemon_usage();
    vlog_usage();
    exit(EXIT_SUCCESS);
}


static void
ovn_controller_vtep_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                       const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;

    unixctl_command_reply(conn, NULL);
}
