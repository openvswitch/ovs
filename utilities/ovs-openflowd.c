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
#include "fault.h"
#include "leak-checker.h"
#include "list.h"
#include "netdev.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "rconn.h"
#include "svec.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"

#include "vlog.h"
#define THIS_MODULE VLM_openflowd

/* Behavior when the connection to the controller fails. */
enum fail_mode {
    FAIL_OPEN,                  /* Act as learning switch. */
    FAIL_CLOSED                 /* Drop all packets. */
};

/* Settings that may be configured by the user. */
struct ofsettings {
    /* Overall mode of operation. */
    bool discovery;           /* Discover the controller automatically? */
    bool in_band;             /* Connect to controller in-band? */

    /* Datapath. */
    uint64_t datapath_id;       /* Datapath ID. */
    const char *dp_name;        /* Name of local datapath. */
    struct svec ports;          /* Set of ports to add to datapath (if any). */

    /* Description strings. */
    const char *mfr_desc;       /* Manufacturer. */
    const char *hw_desc;        /* Hardware. */
    const char *sw_desc;        /* Software version. */
    const char *serial_desc;    /* Serial number. */
    const char *dp_desc;        /* Serial number. */

    /* Related vconns and network devices. */
    const char *controller_name; /* Controller (if not discovery mode). */
    struct svec listeners;       /* Listen for management connections. */
    struct svec snoops;          /* Listen for controller snooping conns. */

    /* Failure behavior. */
    enum fail_mode fail_mode; /* Act as learning switch if no controller? */
    int max_idle;             /* Idle time for flows in fail-open mode. */
    int probe_interval;       /* # seconds idle before sending echo request. */
    int max_backoff;          /* Max # seconds between connection attempts. */

    /* Packet-in rate-limiting. */
    int rate_limit;           /* Tokens added to bucket per second. */
    int burst_limit;          /* Maximum number token bucket size. */

    /* Discovery behavior. */
    const char *accept_controller_re; /* Controller vconns to accept. */
    bool update_resolv_conf;          /* Update /etc/resolv.conf? */

    /* Spanning tree protocol. */
    bool enable_stp;

    /* Remote command execution. */
    char *command_acl;          /* Command white/blacklist, as shell globs. */
    char *command_dir;          /* Directory that contains commands. */

    /* Management. */
    uint64_t mgmt_id;           /* Management ID. */

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
    struct netflow_options nf_options;

    set_program_name(argv[0]);
    register_fault_handlers();
    time_init();
    vlog_init();
    parse_options(argc, argv, &s);
    signal(SIGPIPE, SIG_IGN);

    die_if_already_running();
    daemonize();

    /* Start listening for ovs-appctl requests. */
    error = unixctl_server_create(NULL, &unixctl);
    if (error) {
        ovs_fatal(error, "Could not listen for unixctl connections");
    }

    VLOG_INFO("Open vSwitch version %s", VERSION BUILDNR);
    VLOG_INFO("OpenFlow protocol version 0x%02x", OFP_VERSION);

    /* Create the datapath and add ports to it, if requested by the user. */
    if (s.ports.n) {
        struct dpif *dpif;
        const char *port;
        size_t i;

        error = dpif_create_and_open(s.dp_name, &dpif);
        if (error) {
            ovs_fatal(error, "could not create datapath");
        }

        SVEC_FOR_EACH (i, port, &s.ports) {
            error = dpif_port_add(dpif, port, 0, NULL);
            if (error) {
                ovs_fatal(error, "failed to add %s as a port", port);
            }
        }
        dpif_close(dpif);
    }

    /* Start OpenFlow processing. */
    error = ofproto_create(s.dp_name, NULL, NULL, &ofproto);
    if (error) {
        ovs_fatal(error, "could not initialize openflow switch");
    }
    error = ofproto_set_in_band(ofproto, s.in_band);
    if (error) {
        ovs_fatal(error, "failed to configure in-band control");
    }
    error = ofproto_set_discovery(ofproto, s.discovery, s.accept_controller_re,
                                  s.update_resolv_conf);
    if (error) {
        ovs_fatal(error, "failed to configure controller discovery");
    }
    if (s.datapath_id) {
        ofproto_set_datapath_id(ofproto, s.datapath_id);
    }
    if (s.mgmt_id) {
        ofproto_set_mgmt_id(ofproto, s.mgmt_id);
    }
    ofproto_set_desc(ofproto, s.mfr_desc, s.hw_desc, s.sw_desc,
                     s.serial_desc, s.dp_desc);
    if (!s.listeners.n) {
        svec_add_nocopy(&s.listeners, xasprintf("punix:%s/%s.mgmt",
                                              ovs_rundir, s.dp_name));
    } else if (s.listeners.n == 1 && !strcmp(s.listeners.names[0], "none")) {
        svec_clear(&s.listeners);
    }
    error = ofproto_set_listeners(ofproto, &s.listeners);
    if (error) {
        ovs_fatal(error, "failed to configure management connections");
    }
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
    ofproto_set_failure(ofproto, s.fail_mode == FAIL_OPEN);
    ofproto_set_probe_interval(ofproto, s.probe_interval);
    ofproto_set_max_backoff(ofproto, s.max_backoff);
    ofproto_set_rate_limit(ofproto, s.rate_limit, s.burst_limit);
    error = ofproto_set_stp(ofproto, s.enable_stp);
    if (error) {
        ovs_fatal(error, "failed to configure STP");
    }
    error = ofproto_set_remote_execution(ofproto, s.command_acl,
                                         s.command_dir);
    if (error) {
        ovs_fatal(error, "failed to configure remote command execution");
    }
    if (!s.discovery) {
        error = ofproto_set_controller(ofproto, s.controller_name);
        if (error) {
            ovs_fatal(error, "failed to configure controller");
        }
    }

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

    return 0;
}

/* User interface. */

static void
parse_options(int argc, char *argv[], struct ofsettings *s)
{
    enum {
        OPT_DATAPATH_ID = UCHAR_MAX + 1,
        OPT_MANUFACTURER,
        OPT_HARDWARE,
        OPT_SOFTWARE,
        OPT_SERIAL,
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
        OPT_STP,
        OPT_NO_STP,
        OPT_OUT_OF_BAND,
        OPT_IN_BAND,
        OPT_COMMAND_ACL,
        OPT_COMMAND_DIR,
        OPT_NETFLOW,
        OPT_MGMT_ID,
        OPT_PORTS,
        VLOG_OPTION_ENUMS,
        LEAK_CHECKER_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"datapath-id", required_argument, 0, OPT_DATAPATH_ID},
        {"manufacturer", required_argument, 0, OPT_MANUFACTURER},
        {"hardware", required_argument, 0, OPT_HARDWARE},
        {"software", required_argument, 0, OPT_SOFTWARE},
        {"serial", required_argument, 0, OPT_SERIAL},
        {"dp_desc", required_argument, 0, OPT_DP_DESC},
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
        {"stp",         no_argument, 0, OPT_STP},
        {"no-stp",      no_argument, 0, OPT_NO_STP},
        {"out-of-band", no_argument, 0, OPT_OUT_OF_BAND},
        {"in-band",     no_argument, 0, OPT_IN_BAND},
        {"command-acl", required_argument, 0, OPT_COMMAND_ACL},
        {"command-dir", required_argument, 0, OPT_COMMAND_DIR},
        {"netflow",     required_argument, 0, OPT_NETFLOW},
        {"mgmt-id",     required_argument, 0, OPT_MGMT_ID},
        {"ports",       required_argument, 0, OPT_PORTS},
        {"verbose",     optional_argument, 0, 'v'},
        {"help",        no_argument, 0, 'h'},
        {"version",     no_argument, 0, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        LEAK_CHECKER_LONG_OPTIONS,
#ifdef HAVE_OPENSSL
        VCONN_SSL_LONG_OPTIONS
        {"bootstrap-ca-cert", required_argument, 0, OPT_BOOTSTRAP_CA_CERT},
#endif
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    /* Set defaults that we can figure out before parsing options. */
    s->datapath_id = 0;
    s->mfr_desc = NULL;
    s->hw_desc = NULL;
    s->sw_desc = NULL;
    s->serial_desc = NULL;
    s->dp_desc = NULL;
    svec_init(&s->listeners);
    svec_init(&s->snoops);
    s->fail_mode = FAIL_OPEN;
    s->max_idle = 0;
    s->probe_interval = 0;
    s->max_backoff = 8;
    s->update_resolv_conf = true;
    s->rate_limit = 0;
    s->burst_limit = 0;
    s->accept_controller_re = NULL;
    s->enable_stp = false;
    s->in_band = true;
    s->command_acl = "";
    s->command_dir = NULL;
    svec_init(&s->netflow);
    s->mgmt_id = 0;
    svec_init(&s->ports);
    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case OPT_DATAPATH_ID:
            if (strlen(optarg) != 16
                || strspn(optarg, "0123456789abcdefABCDEF") != 16) {
                ovs_fatal(0, "argument to --datapath-id must be "
                          "exactly 16 hex digits");
            }
            s->datapath_id = strtoll(optarg, NULL, 16);
            if (!s->datapath_id) {
                ovs_fatal(0, "argument to --datapath-id must be nonzero");
            }
            break;

        case OPT_MANUFACTURER:
            s->mfr_desc = optarg;
            break;

        case OPT_HARDWARE:
            s->hw_desc = optarg;
            break;

        case OPT_SOFTWARE:
            s->sw_desc = optarg;
            break;

        case OPT_SERIAL:
            s->serial_desc = optarg;
            break;

        case OPT_DP_DESC:
            s->dp_desc = optarg;
            break;

        case OPT_ACCEPT_VCONN:
            s->accept_controller_re = optarg;
            break;

        case OPT_NO_RESOLV_CONF:
            s->update_resolv_conf = false;
            break;

        case OPT_FAIL_MODE:
            if (!strcmp(optarg, "open")) {
                s->fail_mode = FAIL_OPEN;
            } else if (!strcmp(optarg, "closed")) {
                s->fail_mode = FAIL_CLOSED;
            } else {
                ovs_fatal(0, "--fail argument must be \"open\" or \"closed\"");
            }
            break;

        case OPT_INACTIVITY_PROBE:
            s->probe_interval = atoi(optarg);
            if (s->probe_interval < 5) {
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
            s->max_backoff = atoi(optarg);
            if (s->max_backoff < 1) {
                ovs_fatal(0, "--max-backoff argument must be at least 1");
            } else if (s->max_backoff > 3600) {
                s->max_backoff = 3600;
            }
            break;

        case OPT_RATE_LIMIT:
            if (optarg) {
                s->rate_limit = atoi(optarg);
                if (s->rate_limit < 1) {
                    ovs_fatal(0, "--rate-limit argument must be at least 1");
                }
            } else {
                s->rate_limit = 1000;
            }
            break;

        case OPT_BURST_LIMIT:
            s->burst_limit = atoi(optarg);
            if (s->burst_limit < 1) {
                ovs_fatal(0, "--burst-limit argument must be at least 1");
            }
            break;

        case OPT_STP:
            s->enable_stp = true;
            break;

        case OPT_NO_STP:
            s->enable_stp = false;
            break;

        case OPT_OUT_OF_BAND:
            s->in_band = false;
            break;

        case OPT_IN_BAND:
            s->in_band = true;
            break;

        case OPT_COMMAND_ACL:
            s->command_acl = (s->command_acl[0]
                              ? xasprintf("%s,%s", s->command_acl, optarg)
                              : optarg);
            break;

        case OPT_COMMAND_DIR:
            s->command_dir = optarg;
            break;

        case OPT_NETFLOW:
            svec_add(&s->netflow, optarg);
            break;

        case OPT_MGMT_ID:
            if (strlen(optarg) != 16
                || strspn(optarg, "0123456789abcdefABCDEF") != 16) {
                ovs_fatal(0, "argument to --mgmt-id must be "
                          "exactly 16 hex digits");
            }
            s->mgmt_id = strtoll(optarg, NULL, 16);
            if (!s->mgmt_id) {
                ovs_fatal(0, "argument to --mgmt-id must be nonzero");
            }
            break;

        case 'l':
            svec_add(&s->listeners, optarg);
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
        VCONN_SSL_OPTION_HANDLERS

        case OPT_BOOTSTRAP_CA_CERT:
            vconn_ssl_set_ca_cert_file(optarg, true);
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
    if (argc < 1 || argc > 2) {
        ovs_fatal(0, "need one or two non-option arguments; "
                  "use --help for usage");
    }

    /* Local and remote vconns. */
    s->dp_name = argv[0];
    s->controller_name = argc > 1 ? xstrdup(argv[1]) : NULL;

    /* Set accept_controller_regex. */
    if (!s->accept_controller_re) {
        s->accept_controller_re
            = vconn_ssl_is_configured() ? "^ssl:.*" : "^tcp:.*";
    }

    /* Mode of operation. */
    s->discovery = s->controller_name == NULL;
    if (s->discovery && !s->in_band) {
        ovs_fatal(0, "Cannot perform discovery with out-of-band control");
    }

    /* Rate limiting. */
    if (s->rate_limit && s->rate_limit < 100) {
        VLOG_WARN("Rate limit set to unusually low value %d", s->rate_limit);
    }
}

static void
usage(void)
{
    printf("%s: an OpenFlow switch implementation.\n"
           "usage: %s [OPTIONS] DATAPATH [CONTROLLER]\n"
           "DATAPATH is a local datapath (e.g. \"dp0\").\n"
           "CONTROLLER is an active OpenFlow connection method; if it is\n"
           "omitted, then ovs-openflowd performs controller discovery.\n",
           program_name, program_name);
    vconn_usage(true, true, true);
    printf("\nOpenFlow options:\n"
           "  -d, --datapath-id=ID    Use ID as the OpenFlow switch ID\n"
           "                          (ID must consist of 16 hex digits)\n"
           "  --mgmt-id=ID            Use ID as the management ID\n"
           "                          (ID must consist of 16 hex digits)\n"
           "  --manufacturer=MFR      Identify manufacturer as MFR\n"
           "  --hardware=HW           Identify hardware as HW\n"
           "  --software=SW           Identify software as SW\n"
           "  --serial=SERIAL         Identify serial number as SERIAL\n"
           "  --dp_desc=DP_DESC       Identify dp description as DP_DESC\n"
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
           "  --burst-limit=BURST     limit on packet credit for idle time\n"
           "\nRemote command execution options:\n"
           "  --command-acl=[!]GLOB[,[!]GLOB...] set allowed/denied commands\n"
           "  --command-dir=DIR       set command dir (default: %s/commands)\n",
           ovs_pkgdatadir);
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  -h, --help              display this help message\n"
           "  -V, --version           display version information\n");
    leak_checker_usage();
    exit(EXIT_SUCCESS);
}
