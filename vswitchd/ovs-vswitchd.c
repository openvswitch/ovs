/* Copyright (c) 2008, 2009 Nicira Networks
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, Nicira Networks gives permission
 * to link the code of its release of vswitchd with the OpenSSL project's
 * "OpenSSL" library (or with modified versions of it that use the same
 * license as the "OpenSSL" library), and distribute the linked
 * executables.  You must obey the GNU General Public License in all
 * respects for all of the code used other than "OpenSSL".  If you modify
 * this file, you may extend this exception to your version of the file,
 * but you are not obligated to do so.  If you do not wish to do so,
 * delete this exception statement from your version.
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
#include "cfg.h"
#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "fault.h"
#include "leak-checker.h"
#include "mgmt.h"
#include "ovs-vswitchd.h"
#include "poll-loop.h"
#include "port.h"
#include "proc-net-compat.h"
#include "process.h"
#include "signals.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"

#include "vlog.h"
#define THIS_MODULE VLM_vswitchd

static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;
static void reload(struct unixctl_conn *, const char *args);

static bool need_reconfigure;
static struct unixctl_conn **conns;
static size_t n_conns;

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct signal *sighup;
    int retval;

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    sighup = signal_register(SIGHUP);
    process_init();

    die_if_already_running();
    daemonize();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        ovs_fatal(retval, "could not listen for control connections");
    }
    unixctl_command_register("vswitchd/reload", reload);

    cfg_read();
    mgmt_init();
    bridge_init();
    port_init();
    mgmt_reconfigure();

    need_reconfigure = false;
    for (;;) {
        if (need_reconfigure || signal_poll(sighup)) {
            need_reconfigure = false;
            vlog_reopen_log_file();
            reconfigure();
        }
        mgmt_run();
        if (bridge_run()) {
            need_reconfigure = true;
        }
        unixctl_server_run(unixctl);

        if (need_reconfigure) {
            poll_immediate_wake();
        }
        signal_wait(sighup);
        mgmt_wait();
        bridge_wait();
        unixctl_server_wait(unixctl);
        poll_block();
    }

    return 0;
}

static void
reload(struct unixctl_conn *conn, const char *args UNUSED)
{
    need_reconfigure = true;
    conns = xrealloc(conns, sizeof *conns * (n_conns + 1));
    conns[n_conns++] = conn;
}

void
reconfigure(void)
{
    size_t i;

    cfg_read();
    bridge_reconfigure();
    mgmt_reconfigure();
    port_reconfigure();

    for (i = 0; i < n_conns; i++) {
        unixctl_command_reply(conns[i], 202, NULL);
    }
    free(conns);
    conns = NULL;
    n_conns = 0;
}

static void
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
    const char *config_file;
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
        ovs_fatal(0, "config file is only non-option argument; "
                "use --help for usage");
    }

    config_file = argv[0];
    error = cfg_set_file(config_file);
    if (error) {
       ovs_fatal(error, "failed to add configuration file \"%s\"", 
                config_file);
    }
}

static void
usage(void)
{
    printf("%s: virtual switch daemon\n"
           "usage: %s [OPTIONS] CONFIG\n"
           "CONFIG is a configuration file in ovs-vswitchd.conf(5) format.\n",
           program_name, program_name);
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
