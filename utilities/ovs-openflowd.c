/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "command-line.h"
#include "compiler.h"
#include "daemon.h"
#include "dirs.h"
#include "dpif.h"
#include "leak-checker.h"
#include "list.h"
#include "netdev.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "rconn.h"
#include "stream-ssl.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(openflowd)

/* Settings that may be configured by the user. */
struct ofsettings {
    /* Controller configuration. */
    struct ofproto_controller *controllers;
    size_t n_controllers;
    enum ofproto_fail_mode fail_mode;

    /* Datapath. */
    uint64_t datapath_id;       /* Datapath ID. */
    char *dp_name;              /* Name of local datapath. */
    char *dp_type;              /* Type of local datapath. */
    struct svec ports;          /* Set of ports to add to datapath (if any). */

    /* Description strings. */
    const char *mfr_desc;       /* Manufacturer. */
    const char *hw_desc;        /* Hardware. */
    const char *sw_desc;        /* Software version. */
    const char *serial_desc;    /* Serial number. */
    const char *dp_desc;        /* Datapath description. */

    /* Related vconns and network devices. */
    struct svec snoops;          /* Listen for controller snooping conns. */

    /* Failure behavior. */
    int max_idle;             /* Idle time for flows in fail-open mode. */

    /* NetFlow. */
    struct svec netflow;        /* NetFlow targets. */
};

static void parse_options(int argc, char *argv[], struct ofsettings *);
static void usage(void) NO_RETURN;

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct ofproto *ofproto;
    struct ofsettings s;
    int error;
    struct dpif *dpif;
    struct netflow_options nf_options;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    parse_options(argc, argv, &s);
    signal(SIGPIPE, SIG_IGN);

    die_if_already_running();
    daemonize_start();

    /* Start listening for ovs-appctl requests. */
    error = unixctl_server_create(NULL, &unixctl);
    if (error) {
        exit(EXIT_FAILURE);
    }

    VLOG_INFO("Open vSwitch version %s", VERSION BUILDNR);
    VLOG_INFO("OpenFlow protocol version 0x%02x", OFP_VERSION);

    error = dpif_create_and_open(s.dp_name, s.dp_type, &dpif);
    if (error) {
        ovs_fatal(error, "could not create datapath");
    }

    /* Add ports to the datapath if requested by the user. */
    if (s.ports.n) {
        const char *port;
        size_t i;

        SVEC_FOR_EACH (i, port, &s.ports) {
            error = dpif_port_add(dpif, port, 0, NULL);
            if (error) {
                ovs_fatal(error, "failed to add %s as a port", port);
            }
        }
    }

    /* Start OpenFlow processing. */
    error = ofproto_create(s.dp_name, s.dp_type, NULL, NULL, &ofproto);
    if (error) {
        ovs_fatal(error, "could not initialize openflow switch");
    }
    if (s.datapath_id) {
        ofproto_set_datapath_id(ofproto, s.datapath_id);
    }
    ofproto_set_desc(ofproto, s.mfr_desc, s.hw_desc, s.sw_desc,
                     s.serial_desc, s.dp_desc);
    error = ofproto_set_snoops(ofproto, &s.snoops);
    if (error) {
        ovs_fatal(error,
                  "failed to configure controller snooping connections");
    }
    memset(&nf_options, 0, sizeof nf_options);
    nf_options.collectors = s.netflow;
    error = ofproto_set_netflow(ofproto, &nf_options);
    if (error) {
        ovs_fatal(error, "failed to configure NetFlow collectors");
    }
    ofproto_set_controllers(ofproto, s.controllers, s.n_controllers);
    ofproto_set_fail_mode(ofproto, s.fail_mode);

    daemonize_complete();

    while (ofproto_is_alive(ofproto)) {
        error = ofproto_run(ofproto);
        if (error) {
            ovs_fatal(error, "unrecoverable datapath error");
        }
        unixctl_server_run(unixctl);
        dp_run();
        netdev_run();

        ofproto_wait(ofproto);
        unixctl_server_wait(unixctl);
        dp_wait();
        netdev_wait();
        poll_block();
    }

    dpif_close(dpif);

    return 0;
}

/* User interface. */

static void
parse_options(int argc, char *argv[], struct ofsettings *s)
{
    enum {
        OPT_DATAPATH_ID = UCHAR_MAX + 1,
        OPT_MFR_DESC,
        OPT_HW_DESC,
        OPT_SW_DESC,
        OPT_SERIAL_DESC,
        OPT_DP_DESC,
        OPT_ACCEPT_VCONN,
        OPT_NO_RESOLV_CONF,
        OPT_BR_NAME,
        OPT_FAIL_MODE,
        OPT_INACTIVITY_PROBE,
        OPT_MAX_IDLE,
        OPT_MAX_BACKOFF,
        OPT_SNOOP,
        OPT_RATE_LIMIT,
        OPT_BURST_LIMIT,
        OPT_BOOTSTRAP_CA_CERT,
        OPT_OUT_OF_BAND,
        OPT_IN_BAND,
        OPT_NETFLOW,
        OPT_PORTS,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"datapath-id", required_argument, 0, OPT_DATAPATH_ID},
        {"mfr-desc", required_argument, 0, OPT_MFR_DESC},
        {"hw-desc", required_argument, 0, OPT_HW_DESC},
        {"sw-desc", required_argument, 0, OPT_SW_DESC},
        {"serial-desc", required_argument, 0, OPT_SERIAL_DESC},
        {"dp-desc", required_argument, 0, OPT_DP_DESC},
        {"accept-vconn", required_argument, 0, OPT_ACCEPT_VCONN},
        {"no-resolv-conf", no_argument, 0, OPT_NO_RESOLV_CONF},
        {"config",      required_argument, 0, 'F'},
        {"br-name",     required_argument, 0, OPT_BR_NAME},
        {"fail",        required_argument, 0, OPT_FAIL_MODE},
        {"inactivity-probe", required_argument, 0, OPT_INACTIVITY_PROBE},
        {"max-idle",    required_argument, 0, OPT_MAX_IDLE},
        {"max-backoff", required_argument, 0, OPT_MAX_BACKOFF},
        {"listen",      required_argument, 0, 'l'},
        {"snoop",      required_argument, 0, OPT_SNOOP},
        {"rate-limit",  optional_argument, 0, OPT_RATE_LIMIT},
        {"burst-limit", required_argument, 0, OPT_BURST_LIMIT},
        {"out-of-band", no_argument, 0, OPT_OUT_OF_BAND},
        {"in-band",     no_argument, 0, OPT_IN_BAND},
        {"netflow",     required_argument, 0, OPT_NETFLOW},
        {"ports",       required_argument, 0, OPT_PORTS},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        STREAM_SSL_LONG_OPTIONS
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    struct ofproto_controller controller_opts;
    struct svec controllers;
    int i;

    /* Set defaults that we can figure out before parsing options. */
    controller_opts.target = NULL;
    controller_opts.max_backoff = 8;
    controller_opts.probe_interval = 5;
    controller_opts.band = OFPROTO_IN_BAND;
    controller_opts.accept_re = NULL;
    controller_opts.update_resolv_conf = true;
    controller_opts.rate_limit = 0;
    controller_opts.burst_limit = 0;
    s->fail_mode = OFPROTO_FAIL_STANDALONE;
    s->datapath_id = 0;
    s->mfr_desc = NULL;
    s->hw_desc = NULL;
    s->sw_desc = NULL;
    s->serial_desc = NULL;
    s->dp_desc = NULL;
    svec_init(&controllers);
    svec_init(&s->snoops);
    s->max_idle = 0;
    svec_init(&s->netflow);
    svec_init(&s->ports);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DATAPATH_ID:
            if (!dpid_from_string(optarg, &s->datapath_id)) {
                ovs_fatal(0, "argument to --datapath-id must be "
                          "exactly 16 hex digits and may not be all-zero");
            }
            break;

        case OPT_MFR_DESC:
            s->mfr_desc = optarg;
            break;

        case OPT_HW_DESC:
            s->hw_desc = optarg;
            break;

        case OPT_SW_DESC:
            s->sw_desc = optarg;
            break;

        case OPT_SERIAL_DESC:
            s->serial_desc = optarg;
            break;

        case OPT_DP_DESC:
            s->dp_desc = optarg;
            break;

        case OPT_ACCEPT_VCONN:
            controller_opts.accept_re = optarg;
            break;

        case OPT_NO_RESOLV_CONF:
            controller_opts.update_resolv_conf = false;
            break;

        case OPT_FAIL_MODE:
            if (!strcmp(optarg, "open") || !strcmp(optarg, "standalone")) {
                s->fail_mode = OFPROTO_FAIL_STANDALONE;
            } else if (!strcmp(optarg, "closed")
                       || !strcmp(optarg, "secure")) {
                s->fail_mode = OFPROTO_FAIL_SECURE;
            } else {
                ovs_fatal(0, "--fail argument must be \"standalone\" "
                          "or \"secure\"");
            }
            break;

        case OPT_INACTIVITY_PROBE:
            controller_opts.probe_interval = atoi(optarg);
            if (controller_opts.probe_interval < 5) {
                ovs_fatal(0, "--inactivity-probe argument must be at least 5");
            }
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                s->max_idle = OFP_FLOW_PERMANENT;
            } else {
                s->max_idle = atoi(optarg);
                if (s->max_idle < 1 || s->max_idle > 65535) {
                    ovs_fatal(0, "--max-idle argument must be between 1 and "
                              "65535 or the word 'permanent'");
                }
            }
            break;

        case OPT_MAX_BACKOFF:
            controller_opts.max_backoff = atoi(optarg);
            if (controller_opts.max_backoff < 1) {
                ovs_fatal(0, "--max-backoff argument must be at least 1");
            } else if (controller_opts.max_backoff > 3600) {
                controller_opts.max_backoff = 3600;
            }
            break;

        case OPT_RATE_LIMIT:
            if (optarg) {
                controller_opts.rate_limit = atoi(optarg);
                if (controller_opts.rate_limit < 1) {
                    ovs_fatal(0, "--rate-limit argument must be at least 1");
                }
            } else {
                controller_opts.rate_limit = 1000;
            }
            break;

        case OPT_BURST_LIMIT:
            controller_opts.burst_limit = atoi(optarg);
            if (controller_opts.burst_limit < 1) {
                ovs_fatal(0, "--burst-limit argument must be at least 1");
            }
            break;

        case OPT_OUT_OF_BAND:
            controller_opts.band = OFPROTO_OUT_OF_BAND;
            break;

        case OPT_IN_BAND:
            controller_opts.band = OFPROTO_IN_BAND;
            break;

        case OPT_NETFLOW:
            svec_add(&s->netflow, optarg);
            break;

        case 'l':
            svec_add(&controllers, optarg);
            break;

        case OPT_SNOOP:
            svec_add(&s->snoops, optarg);
            break;

        case OPT_PORTS:
            svec_split(&s->ports, optarg, ",");
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(OFP_VERSION, OFP_VERSION);
            exit(EXIT_SUCCESS);

        DAEMON_OPTION_HANDLERS

        VLOG_OPTION_HANDLERS

        LEAK_CHECKER_OPTION_HANDLERS

#ifdef HAVE_OPENSSL
        STREAM_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            stream_ssl_set_ca_cert_file(optarg, true);
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
    if (argc < 1) {
        ovs_fatal(0, "need at least one non-option arguments; "
                  "use --help for usage");
    }

    /* Set accept_controller_regex. */
    if (!controller_opts.accept_re) {
        controller_opts.accept_re
            = stream_ssl_is_configured() ? "^ssl:.*" : "^tcp:.*";
    }

    /* Rate limiting. */
    if (controller_opts.rate_limit && controller_opts.rate_limit < 100) {
        VLOG_WARN("Rate limit set to unusually low value %d",
                  controller_opts.rate_limit);
    }

    /* Local vconns. */
    dp_parse_name(argv[0], &s->dp_name, &s->dp_type);

    /* Figure out controller names. */
    if (!controllers.n) {
        svec_add_nocopy(&controllers,
                        xasprintf("punix:%s/%s.mgmt", ovs_rundir, s->dp_name));
    }
    for (i = 1; i < argc; i++) {
        svec_add(&controllers, argv[i]);
    }
    if (argc < 2) {
        svec_add(&controllers, "discover");
    }

    /* Set up controllers. */
    s->n_controllers = controllers.n;
    s->controllers = xmalloc(s->n_controllers * sizeof *s->controllers);
    if (argc > 1) {
        size_t i;

        for (i = 0; i < s->n_controllers; i++) {
            s->controllers[i] = controller_opts;
            s->controllers[i].target = controllers.names[i];
        }
    }

    /* Sanity check. */
    if (controller_opts.band == OFPROTO_OUT_OF_BAND) {
        size_t i;

        for (i = 0; i < s->n_controllers; i++) {
            if (!strcmp(s->controllers[i].target, "discover")) {
                ovs_fatal(0, "Cannot perform discovery with out-of-band "
                          "control");
            }
        }
    }
}

static void
usage(void)
{
    printf("%s: an OpenFlow switch implementation.\n"
           "usage: %s [OPTIONS] DATAPATH [CONTROLLER...]\n"
           "DATAPATH is a local datapath (e.g. \"dp0\").\n"
           "Each CONTROLLER is an active OpenFlow connection method.  If\n"
           "none is given, ovs-openflowd performs controller discovery.\n",
           program_name, program_name);
    vconn_usage(true, true, true);
    printf("\nOpenFlow options:\n"
           "  -d, --datapath-id=ID    Use ID as the OpenFlow switch ID\n"
           "                          (ID must consist of 16 hex digits)\n"
           "  --mfr-desc=MFR          Identify manufacturer as MFR\n"
           "  --hw-desc=HW            Identify hardware as HW\n"
           "  --sw-desc=SW            Identify software as SW\n"
           "  --serial-desc=SERIAL    Identify serial number as SERIAL\n"
           "  --dp-desc=DP_DESC       Identify dp description as DP_DESC\n"
           "\nController discovery options:\n"
           "  --accept-vconn=REGEX    accept matching discovered controllers\n"
           "  --no-resolv-conf        do not update /etc/resolv.conf\n"
           "\nNetworking options:\n"
           "  --fail=open|closed      when controller connection fails:\n"
           "                            closed: drop all packets\n"
           "                            open (default): act as learning switch\n"
           "  --inactivity-probe=SECS time between inactivity probes\n"
           "  --max-idle=SECS         max idle for flows set up by switch\n"
           "  --max-backoff=SECS      max time between controller connection\n"
           "                          attempts (default: 8 seconds)\n"
           "  -l, --listen=METHOD     allow management connections on METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "  --snoop=METHOD          allow controller snooping on METHOD\n"
           "                          (a passive OpenFlow connection method)\n"
           "  --out-of-band           controller connection is out-of-band\n"
           "  --netflow=HOST:PORT     configure NetFlow output target\n"
           "\nRate-limiting of \"packet-in\" messages to the controller:\n"
           "  --rate-limit[=PACKETS]  max rate, in packets/s (default: 1000)\n"
           "  --burst-limit=BURST     limit on packet credit for idle time\n");
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    exit(EXIT_SUCCESS);
}
