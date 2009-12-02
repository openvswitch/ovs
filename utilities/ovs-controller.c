/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "fault.h"
#include "learning-switch.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "rconn.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"

#include "vlog.h"
#define THIS_MODULE VLM_controller

#define MAX_SWITCHES 16
#define MAX_LISTENERS 16

struct switch_ {
    struct lswitch *lswitch;
    struct rconn *rconn;
};

/* Learn the ports on which MAC addresses appear? */
static bool learn_macs = true;

/* Set up flows?  (If not, every packet is processed at the controller.) */
static bool set_up_flows = true;

/* -N, --normal: Use "NORMAL" action instead of explicit port? */
static bool action_normal = false;

/* -w, --wildcard: Set up exact match or wildcard flow entries? */
static bool exact_flows = true;

/* --max-idle: Maximum idle time, in seconds, before flows expire. */
static int max_idle = 60;

/* --mute: If true, accept connections from switches but do not reply to any
 * of their messages (for debugging fail-open mode). */
static bool mute = false;

static int do_switching(struct switch_ *);
static void new_switch(struct switch_ *, struct vconn *, const char *name);
static void parse_options(int argc, char *argv[]);
static void usage(void) NO_RETURN;

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct switch_ switches[MAX_SWITCHES];
    struct pvconn *listeners[MAX_LISTENERS];
    int n_switches, n_listeners;
    int retval;
    int i;

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);

    if (argc - optind < 1) {
        ovs_fatal(0, "at least one vconn argument required; "
                  "use --help for usage");
    }

    n_switches = n_listeners = 0;
    for (i = optind; i < argc; i++) {
        const char *name = argv[i];
        struct vconn *vconn;
        int retval;

        retval = vconn_open(name, OFP_VERSION, &vconn);
        if (!retval) {
            if (n_switches >= MAX_SWITCHES) {
                ovs_fatal(0, "max %d switch connections", n_switches);
            }
            new_switch(&switches[n_switches++], vconn, name);
            continue;
        } else if (retval == EAFNOSUPPORT) {
            struct pvconn *pvconn;
            retval = pvconn_open(name, &pvconn);
            if (!retval) {
                if (n_listeners >= MAX_LISTENERS) {
                    ovs_fatal(0, "max %d passive connections", n_listeners);
                }
                listeners[n_listeners++] = pvconn;
            }
        }
        if (retval) {
            VLOG_ERR("%s: connect: %s", name, strerror(retval));
        }
    }
    if (n_switches == 0 && n_listeners == 0) {
        ovs_fatal(0, "no active or passive switch connections");
    }

    die_if_already_running();
    daemonize();

    retval = unixctl_server_create(NULL, &unixctl);
    if (retval) {
        ovs_fatal(retval, "Could not listen for unixctl connections");
    }

    while (n_switches > 0 || n_listeners > 0) {
        int iteration;
        int i;

        /* Accept connections on listening vconns. */
        for (i = 0; i < n_listeners && n_switches < MAX_SWITCHES; ) {
            struct vconn *new_vconn;
            int retval;

            retval = pvconn_accept(listeners[i], OFP_VERSION, &new_vconn);
            if (!retval || retval == EAGAIN) {
                if (!retval) {
                    new_switch(&switches[n_switches++], new_vconn, "tcp");
                }
                i++;
            } else {
                pvconn_close(listeners[i]);
                listeners[i] = listeners[--n_listeners];
            }
        }

        /* Do some switching work.  Limit the number of iterations so that
         * callbacks registered with the poll loop don't starve. */
        for (iteration = 0; iteration < 50; iteration++) {
            bool progress = false;
            for (i = 0; i < n_switches; ) {
                struct switch_ *this = &switches[i];
                int retval = do_switching(this);
                if (!retval || retval == EAGAIN) {
                    if (!retval) {
                        progress = true;
                    }
                    i++;
                } else {
                    rconn_destroy(this->rconn);
                    lswitch_destroy(this->lswitch);
                    switches[i] = switches[--n_switches];
                }
            }
            if (!progress) {
                break;
            }
        }
        for (i = 0; i < n_switches; i++) {
            struct switch_ *this = &switches[i];
            lswitch_run(this->lswitch, this->rconn);
        }

        unixctl_server_run(unixctl);

        /* Wait for something to happen. */
        if (n_switches < MAX_SWITCHES) {
            for (i = 0; i < n_listeners; i++) {
                pvconn_wait(listeners[i]);
            }
        }
        for (i = 0; i < n_switches; i++) {
            struct switch_ *sw = &switches[i];
            rconn_run_wait(sw->rconn);
            rconn_recv_wait(sw->rconn);
            lswitch_wait(sw->lswitch);
        }
        unixctl_server_wait(unixctl);
        poll_block();
    }

    return 0;
}

static void
new_switch(struct switch_ *sw, struct vconn *vconn, const char *name)
{
    sw->rconn = rconn_new_from_vconn(name, vconn);
    sw->lswitch = lswitch_create(sw->rconn, learn_macs, exact_flows,
                                 set_up_flows ? max_idle : -1,
                                 action_normal);
}

static int
do_switching(struct switch_ *sw)
{
    unsigned int packets_sent;
    struct ofpbuf *msg;

    packets_sent = rconn_packets_sent(sw->rconn);

    msg = rconn_recv(sw->rconn);
    if (msg) {
        if (!mute) {
            lswitch_process_packet(sw->lswitch, sw->rconn, msg);
        }
        ofpbuf_delete(msg);
    }
    rconn_run(sw->rconn);

    return (!rconn_is_alive(sw->rconn) ? EOF
            : rconn_packets_sent(sw->rconn) != packets_sent ? 0
            : EAGAIN);
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_MAX_IDLE = UCHAR_MAX + 1,
        OPT_PEER_CA_CERT,
        OPT_MUTE,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"hub",         no_argument, 0, 'H'},
        {"noflow",      no_argument, 0, 'n'},
        {"normal",      no_argument, 0, 'N'},
        {"wildcard",    no_argument, 0, 'w'},
        {"max-idle",    required_argument, 0, OPT_MAX_IDLE},
        {"mute",        no_argument, 0, OPT_MUTE},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        VCONN_SSL_LONG_OPTIONS
        {"peer-ca-cert", required_argument, 0, OPT_PEER_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int indexptr;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, &indexptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'H':
            learn_macs = false;
            break;

        case 'n':
            set_up_flows = false;
            break;

        case OPT_MUTE:
            mute = true;
            break;

        case 'N':
            action_normal = true;
            break;

        case 'w':
            exact_flows = false;
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                max_idle = OFP_FLOW_PERMANENT;
            } else {
                max_idle = atoi(optarg);
                if (max_idle < 1 || max_idle > 65535) {
                    ovs_fatal(0, "--max-idle argument must be between 1 and "
                              "65535 or the word 'permanent'");
                }
            }
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(OFP_VERSION, OFP_VERSION);
            exit(EXIT_SUCCESS);

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        VCONN_SSL_OPTION_HANDLERS

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
}

static void
usage(void)
{
    printf("%s: OpenFlow controller\n"
           "usage: %s [OPTIONS] METHOD\n"
           "where METHOD is any OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, true, false);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -H, --hub               act as hub instead of learning switch\n"
           "  -n, --noflow            pass traffic, but don't add flows\n"
           "  --max-idle=SECS         max idle time for new flows\n"
           "  -N, --normal            use OFPAT_NORMAL action\n"
           "  -w, --wildcard          use wildcards, not exact-match rules\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    exit(EXIT_SUCCESS);
}
