/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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
#include "dummy.h"
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
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(openflowd);

/* Settings that may be configured by the user. */
struct ofsettings {
    const char *unixctl_path;   /* File name for unixctl socket. */

    /* Controller configuration. */
    struct ofproto_controller *controllers;
    size_t n_controllers;
    enum ofproto_fail_mode fail_mode;
    bool run_forever;           /* Continue running even with no controller? */

    /* Datapath. */
    uint64_t datapath_id;       /* Datapath ID. */
    char *dp_name;              /* Name of local datapath. */
    char *dp_type;              /* Type of local datapath. */
    struct sset ports;          /* Set of ports to add to datapath (if any). */

    /* Description strings. */
    const char *mfr_desc;       /* Manufacturer. */
    const char *hw_desc;        /* Hardware. */
    const char *sw_desc;        /* Software version. */
    const char *serial_desc;    /* Serial number. */
    const char *dp_desc;        /* Datapath description. */

    /* Related vconns and network devices. */
    struct sset snoops;          /* Listen for controller snooping conns. */

    /* Failure behavior. */
    int max_idle;             /* Idle time for flows in fail-open mode. */

    /* NetFlow. */
    struct sset netflow;        /* NetFlow targets. */
};

static unixctl_cb_func test_openflowd_exit;

static void parse_options(int argc, char *argv[], struct ofsettings *);
static void usage(void) NO_RETURN;

int
main(int argc, char *argv[])
{
    struct unixctl_server *unixctl;
    struct ofproto *ofproto;
    struct ofsettings s;
    int error;
    struct netflow_options nf_options;
    const char *port;
    bool exiting;

    proctitle_init(argc, argv);
    set_program_name(argv[0]);
    parse_options(argc, argv, &s);
    signal(SIGPIPE, SIG_IGN);

    daemonize_start();

    /* Start listening for ovs-appctl requests. */
    error = unixctl_server_create(s.unixctl_path, &unixctl);
    if (error) {
        exit(EXIT_FAILURE);
    }

    unixctl_command_register("exit", test_openflowd_exit, &exiting);

    VLOG_INFO("Open vSwitch version %s", VERSION BUILDNR);
    VLOG_INFO("OpenFlow protocol version 0x%02x", OFP_VERSION);

    error = ofproto_create(s.dp_name, s.dp_type, &ofproto);
    if (error) {
        VLOG_FATAL("could not initialize OpenFlow switch (%s)",
                   strerror(error));
    }

    /* Add ports to the datapath if requested by the user. */
    SSET_FOR_EACH (port, &s.ports) {
        struct netdev *netdev;

        error = netdev_open_default(port, &netdev);
        if (error) {
            VLOG_FATAL("%s: failed to open network device (%s)",
                       port, strerror(error));
        }

        error = ofproto_port_add(ofproto, netdev, NULL);
        if (error) {
            VLOG_FATAL("failed to add %s as a port (%s)",
                       port, strerror(error));
        }

        netdev_close(netdev);
    }

    /* Configure OpenFlow switch. */
    if (s.datapath_id) {
        ofproto_set_datapath_id(ofproto, s.datapath_id);
    }
    ofproto_set_desc(ofproto, s.mfr_desc, s.hw_desc, s.sw_desc,
                     s.serial_desc, s.dp_desc);
    error = ofproto_set_snoops(ofproto, &s.snoops);
    if (error) {
        VLOG_FATAL("failed to configure controller snooping connections (%s)",
                   strerror(error));
    }
    memset(&nf_options, 0, sizeof nf_options);
    nf_options.collectors = s.netflow;
    error = ofproto_set_netflow(ofproto, &nf_options);
    if (error) {
        VLOG_FATAL("failed to configure NetFlow collectors (%s)",
                   strerror(error));
    }
    ofproto_set_controllers(ofproto, s.controllers, s.n_controllers);
    ofproto_set_fail_mode(ofproto, s.fail_mode);

    daemonize_complete();

    exiting = false;
    while (!exiting && (s.run_forever || ofproto_is_alive(ofproto))) {
        error = ofproto_run(ofproto);
        if (error) {
            VLOG_FATAL("unrecoverable datapath error (%s)", strerror(error));
        }
        unixctl_server_run(unixctl);
        netdev_run();

        ofproto_wait(ofproto);
        unixctl_server_wait(unixctl);
        netdev_wait();
        if (exiting) {
            poll_immediate_wake();
        }
        poll_block();
    }

    ofproto_destroy(ofproto);

    return 0;
}

static void
test_openflowd_exit(struct unixctl_conn *conn, const char *args OVS_UNUSED,
                   void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, 200, NULL);
}

/* User interface. */

/* Breaks 'ports' apart at commas and adds each resulting word to 'ports'. */
static void
parse_ports(const char *s_, struct sset *ports)
{
    char *s = xstrdup(s_);
    char *save_ptr = NULL;
    char *token;

    for (token = strtok_r(s, ",", &save_ptr); token != NULL;
         token = strtok_r(NULL, ",", &save_ptr)) {
        sset_add(ports, token);
    }
    free(s);
}

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
        OPT_UNIXCTL,
        OPT_ENABLE_DUMMY,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"datapath-id", required_argument, NULL, OPT_DATAPATH_ID},
        {"mfr-desc", required_argument, NULL, OPT_MFR_DESC},
        {"hw-desc", required_argument, NULL, OPT_HW_DESC},
        {"sw-desc", required_argument, NULL, OPT_SW_DESC},
        {"serial-desc", required_argument, NULL, OPT_SERIAL_DESC},
        {"dp-desc", required_argument, NULL, OPT_DP_DESC},
        {"config",      required_argument, NULL, 'F'},
        {"br-name",     required_argument, NULL, OPT_BR_NAME},
        {"fail",        required_argument, NULL, OPT_FAIL_MODE},
        {"inactivity-probe", required_argument, NULL, OPT_INACTIVITY_PROBE},
        {"max-idle",    required_argument, NULL, OPT_MAX_IDLE},
        {"max-backoff", required_argument, NULL, OPT_MAX_BACKOFF},
        {"listen",      required_argument, NULL, 'l'},
        {"snoop",      required_argument, NULL, OPT_SNOOP},
        {"rate-limit",  optional_argument, NULL, OPT_RATE_LIMIT},
        {"burst-limit", required_argument, NULL, OPT_BURST_LIMIT},
        {"out-of-band", no_argument, NULL, OPT_OUT_OF_BAND},
        {"in-band",     no_argument, NULL, OPT_IN_BAND},
        {"netflow",     required_argument, NULL, OPT_NETFLOW},
        {"ports",       required_argument, NULL, OPT_PORTS},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        {"enable-dummy", no_argument, NULL, OPT_ENABLE_DUMMY},
        {"verbose",     optional_argument, NULL, 'v'},
        {"help",        no_argument, NULL, 'h'},
        {"version",     no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {"bootstrap-ca-cert", required_argument, NULL, OPT_BOOTSTRAP_CA_CERT},
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);
    struct ofproto_controller controller_opts;
    struct sset controllers;
    const char *name;
    int i;

    /* Set defaults that we can figure out before parsing options. */
    controller_opts.target = NULL;
    controller_opts.max_backoff = 8;
    controller_opts.probe_interval = 5;
    controller_opts.band = OFPROTO_IN_BAND;
    controller_opts.rate_limit = 0;
    controller_opts.burst_limit = 0;
    s->unixctl_path = NULL;
    s->fail_mode = OFPROTO_FAIL_STANDALONE;
    s->datapath_id = 0;
    s->mfr_desc = NULL;
    s->hw_desc = NULL;
    s->sw_desc = NULL;
    s->serial_desc = NULL;
    s->dp_desc = NULL;
    sset_init(&controllers);
    sset_init(&s->snoops);
    s->max_idle = 0;
    sset_init(&s->netflow);
    sset_init(&s->ports);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DATAPATH_ID:
            if (!dpid_from_string(optarg, &s->datapath_id)) {
                VLOG_FATAL("argument to --datapath-id must be exactly 16 hex "
                           "digits and may not be all-zero");
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

        case OPT_FAIL_MODE:
            if (!strcmp(optarg, "open") || !strcmp(optarg, "standalone")) {
                s->fail_mode = OFPROTO_FAIL_STANDALONE;
            } else if (!strcmp(optarg, "closed")
                       || !strcmp(optarg, "secure")) {
                s->fail_mode = OFPROTO_FAIL_SECURE;
            } else {
                VLOG_FATAL("--fail argument must be \"standalone\" "
                           "or \"secure\"");
            }
            break;

        case OPT_INACTIVITY_PROBE:
            controller_opts.probe_interval = atoi(optarg);
            if (controller_opts.probe_interval < 5) {
                VLOG_FATAL("--inactivity-probe argument must be at least 5");
            }
            break;

        case OPT_MAX_IDLE:
            if (!strcmp(optarg, "permanent")) {
                s->max_idle = OFP_FLOW_PERMANENT;
            } else {
                s->max_idle = atoi(optarg);
                if (s->max_idle < 1 || s->max_idle > 65535) {
                    VLOG_FATAL("--max-idle argument must be between 1 and "
                               "65535 or the word 'permanent'");
                }
            }
            break;

        case OPT_MAX_BACKOFF:
            controller_opts.max_backoff = atoi(optarg);
            if (controller_opts.max_backoff < 1) {
                VLOG_FATAL("--max-backoff argument must be at least 1");
            } else if (controller_opts.max_backoff > 3600) {
                controller_opts.max_backoff = 3600;
            }
            break;

        case OPT_RATE_LIMIT:
            if (optarg) {
                controller_opts.rate_limit = atoi(optarg);
                if (controller_opts.rate_limit < 1) {
                    VLOG_FATAL("--rate-limit argument must be at least 1");
                }
            } else {
                controller_opts.rate_limit = 1000;
            }
            break;

        case OPT_BURST_LIMIT:
            controller_opts.burst_limit = atoi(optarg);
            if (controller_opts.burst_limit < 1) {
                VLOG_FATAL("--burst-limit argument must be at least 1");
            }
            break;

        case OPT_OUT_OF_BAND:
            controller_opts.band = OFPROTO_OUT_OF_BAND;
            break;

        case OPT_IN_BAND:
            controller_opts.band = OFPROTO_IN_BAND;
            break;

        case OPT_NETFLOW:
            sset_add(&s->netflow, optarg);
            break;

        case 'l':
            sset_add(&controllers, optarg);
            break;

        case OPT_SNOOP:
            sset_add(&s->snoops, optarg);
            break;

        case OPT_PORTS:
            parse_ports(optarg, &s->ports);
            break;

        case OPT_UNIXCTL:
            s->unixctl_path = optarg;
            break;

        case OPT_ENABLE_DUMMY:
            dummy_enable();
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(OFP_VERSION, OFP_VERSION);
            exit(EXIT_SUCCESS);

        DAEMON_OPTION_HANDLERS

        VLOG_OPTION_HANDLERS

        LEAK_CHECKER_OPTION_HANDLERS

        STREAM_SSL_OPTION_HANDLERS

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

    argc -= optind;
    argv += optind;
    if (argc < 2) {
        VLOG_FATAL("need at least two non-option arguments; "
                   "use --help for usage");
    }

    /* Rate limiting. */
    if (controller_opts.rate_limit && controller_opts.rate_limit < 100) {
        VLOG_WARN("Rate limit set to unusually low value %d",
                  controller_opts.rate_limit);
    }

    /* Local vconns. */
    ofproto_parse_name(argv[0], &s->dp_name, &s->dp_type);

    /* Figure out controller names. */
    s->run_forever = false;
    if (sset_is_empty(&controllers)) {
        sset_add_and_free(&controllers, xasprintf("punix:%s/%s.mgmt",
                                                  ovs_rundir(), s->dp_name));
    }
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "none")) {
            s->run_forever = true;
        } else {
            sset_add(&controllers, argv[i]);
        }
    }

    /* Set up controllers. */
    s->n_controllers = sset_count(&controllers);
    s->controllers = xmalloc(s->n_controllers * sizeof *s->controllers);
    i = 0;
    SSET_FOR_EACH (name, &controllers) {
        s->controllers[i] = controller_opts;
        s->controllers[i].target = xstrdup(name);
        i++;
    }
    sset_destroy(&controllers);
}

static void
usage(void)
{
    printf("%s: an OpenFlow switch implementation.\n"
           "usage: %s [OPTIONS] [TYPE@]DATAPATH CONTROLLER...\n"
           "where DATAPATH is a local datapath (e.g. \"dp0\")\n"
           "optionally with an explicit TYPE (default: \"system\").\n"
           "Each CONTROLLER is an active OpenFlow connection method.\n",
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
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    exit(EXIT_SUCCESS);
}
