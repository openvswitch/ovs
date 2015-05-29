/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "byte-order.h"
#include "classifier.h"
#include "command-line.h"
#include "daemon.h"
#include "compiler.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "fatal-signal.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-msgs.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofp-version-opt.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "dp-packet.h"
#include "packets.h"
#include "pcap-file.h"
#include "poll-loop.h"
#include "random.h"
#include "stream-ssl.h"
#include "socket-util.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "meta-flow.h"
#include "sort.h"

VLOG_DEFINE_THIS_MODULE(ofctl);

/* --strict: Use strict matching for flow mod commands?  Additionally governs
 * use of nx_pull_match() instead of nx_pull_match_loose() in parse-nx-match.
 */
static bool strict;

/* --readd: If true, on replace-flows, re-add even flows that have not changed
 * (to reset flow counters). */
static bool readd;

/* -F, --flow-format: Allowed protocols.  By default, any protocol is
 * allowed. */
static enum ofputil_protocol allowed_protocols = OFPUTIL_P_ANY;

/* -P, --packet-in-format: Packet IN format to use in monitor and snoop
 * commands.  Either one of NXPIF_* to force a particular packet_in format, or
 * -1 to let ovs-ofctl choose the default. */
static int preferred_packet_in_format = -1;

/* -m, --more: Additional verbosity for ofp-print functions. */
static int verbosity;

/* --timestamp: Print a timestamp before each received packet on "monitor" and
 * "snoop" command? */
static bool timestamp;

/* --unixctl-path: Path to use for unixctl server, for "monitor" and "snoop"
     commands. */
static char *unixctl_path;

/* --sort, --rsort: Sort order. */
enum sort_order { SORT_ASC, SORT_DESC };
struct sort_criterion {
    const struct mf_field *field; /* NULL means to sort by priority. */
    enum sort_order order;
};
static struct sort_criterion *criteria;
static size_t n_criteria, allocated_criteria;

static const struct ovs_cmdl_command *get_all_commands(void);

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);

static bool recv_flow_stats_reply(struct vconn *, ovs_be32 send_xid,
                                  struct ofpbuf **replyp,
                                  struct ofputil_flow_stats *,
                                  struct ofpbuf *ofpacts);
int
main(int argc, char *argv[])
{
    struct ovs_cmdl_context ctx = { .argc = 0, };
    set_program_name(argv[0]);
    service_start(&argc, &argv);
    parse_options(argc, argv);
    fatal_ignore_sigpipe();
    ctx.argc = argc - optind;
    ctx.argv = argv + optind;
    ovs_cmdl_run_command(&ctx, get_all_commands());
    return 0;
}

static void
add_sort_criterion(enum sort_order order, const char *field)
{
    struct sort_criterion *sc;

    if (n_criteria >= allocated_criteria) {
        criteria = x2nrealloc(criteria, &allocated_criteria, sizeof *criteria);
    }

    sc = &criteria[n_criteria++];
    if (!field || !strcasecmp(field, "priority")) {
        sc->field = NULL;
    } else {
        sc->field = mf_from_name(field);
        if (!sc->field) {
            ovs_fatal(0, "%s: unknown field name", field);
        }
    }
    sc->order = order;
}

static void
parse_options(int argc, char *argv[])
{
    enum {
        OPT_STRICT = UCHAR_MAX + 1,
        OPT_READD,
        OPT_TIMESTAMP,
        OPT_SORT,
        OPT_RSORT,
        OPT_UNIXCTL,
        DAEMON_OPTION_ENUMS,
        OFP_VERSION_OPTION_ENUMS,
        VLOG_OPTION_ENUMS
    };
    static const struct option long_options[] = {
        {"timeout", required_argument, NULL, 't'},
        {"strict", no_argument, NULL, OPT_STRICT},
        {"readd", no_argument, NULL, OPT_READD},
        {"flow-format", required_argument, NULL, 'F'},
        {"packet-in-format", required_argument, NULL, 'P'},
        {"more", no_argument, NULL, 'm'},
        {"timestamp", no_argument, NULL, OPT_TIMESTAMP},
        {"sort", optional_argument, NULL, OPT_SORT},
        {"rsort", optional_argument, NULL, OPT_RSORT},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        {"help", no_argument, NULL, 'h'},
        {"option", no_argument, NULL, 'o'},
        DAEMON_LONG_OPTIONS,
        OFP_VERSION_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = ovs_cmdl_long_options_to_short_options(long_options);
    uint32_t versions;
    enum ofputil_protocol version_protocols;

    /* For now, ovs-ofctl only enables OpenFlow 1.0 by default.  This is
     * because ovs-ofctl implements command such as "add-flow" as raw OpenFlow
     * requests, but those requests have subtly different semantics in
     * different OpenFlow versions.  For example:
     *
     *     - In OpenFlow 1.0, a "mod-flow" operation that does not find any
     *       existing flow to modify adds a new flow.
     *
     *     - In OpenFlow 1.1, a "mod-flow" operation that does not find any
     *       existing flow to modify adds a new flow, but only if the mod-flow
     *       did not match on the flow cookie.
     *
     *     - In OpenFlow 1.2 and a later, a "mod-flow" operation never adds a
     *       new flow.
     */
    set_allowed_ofp_versions("OpenFlow10");

    for (;;) {
        unsigned long int timeout;
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 't':
            timeout = strtoul(optarg, NULL, 10);
            if (timeout <= 0) {
                ovs_fatal(0, "value %s on -t or --timeout is not at least 1",
                          optarg);
            } else {
                time_alarm(timeout);
            }
            break;

        case 'F':
            allowed_protocols = ofputil_protocols_from_string(optarg);
            if (!allowed_protocols) {
                ovs_fatal(0, "%s: invalid flow format(s)", optarg);
            }
            break;

        case 'P':
            preferred_packet_in_format =
                ofputil_packet_in_format_from_string(optarg);
            if (preferred_packet_in_format < 0) {
                ovs_fatal(0, "unknown packet-in format `%s'", optarg);
            }
            break;

        case 'm':
            verbosity++;
            break;

        case 'h':
            usage();

        case 'o':
            ovs_cmdl_print_options(long_options);
            exit(EXIT_SUCCESS);

        case OPT_STRICT:
            strict = true;
            break;

        case OPT_READD:
            readd = true;
            break;

        case OPT_TIMESTAMP:
            timestamp = true;
            break;

        case OPT_SORT:
            add_sort_criterion(SORT_ASC, optarg);
            break;

        case OPT_RSORT:
            add_sort_criterion(SORT_DESC, optarg);
            break;

        case OPT_UNIXCTL:
            unixctl_path = optarg;
            break;

        DAEMON_OPTION_HANDLERS
        OFP_VERSION_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }

    if (n_criteria) {
        /* Always do a final sort pass based on priority. */
        add_sort_criterion(SORT_DESC, "priority");
    }

    free(short_options);

    versions = get_allowed_ofp_versions();
    version_protocols = ofputil_protocols_from_version_bitmap(versions);
    if (!(allowed_protocols & version_protocols)) {
        char *protocols = ofputil_protocols_to_string(allowed_protocols);
        struct ds version_s = DS_EMPTY_INITIALIZER;

        ofputil_format_version_bitmap_names(&version_s, versions);
        ovs_fatal(0, "None of the enabled OpenFlow versions (%s) supports "
                  "any of the enabled flow formats (%s).  (Use -O to enable "
                  "additional OpenFlow versions or -F to enable additional "
                  "flow formats.)", ds_cstr(&version_s), protocols);
    }
    allowed_protocols &= version_protocols;
    mask_allowed_ofp_versions(ofputil_protocols_to_version_bitmap(
                                  allowed_protocols));
}

static void
usage(void)
{
    printf("%s: OpenFlow switch management utility\n"
           "usage: %s [OPTIONS] COMMAND [ARG...]\n"
           "\nFor OpenFlow switches:\n"
           "  show SWITCH                 show OpenFlow information\n"
           "  dump-desc SWITCH            print switch description\n"
           "  dump-tables SWITCH          print table stats\n"
           "  dump-table-features SWITCH  print table features\n"
           "  mod-port SWITCH IFACE ACT   modify port behavior\n"
           "  mod-table SWITCH MOD        modify flow table behavior\n"
           "  get-frags SWITCH            print fragment handling behavior\n"
           "  set-frags SWITCH FRAG_MODE  set fragment handling behavior\n"
           "  dump-ports SWITCH [PORT]    print port statistics\n"
           "  dump-ports-desc SWITCH [PORT]  print port descriptions\n"
           "  dump-flows SWITCH           print all flow entries\n"
           "  dump-flows SWITCH FLOW      print matching FLOWs\n"
           "  dump-aggregate SWITCH       print aggregate flow statistics\n"
           "  dump-aggregate SWITCH FLOW  print aggregate stats for FLOWs\n"
           "  queue-stats SWITCH [PORT [QUEUE]]  dump queue stats\n"
           "  add-flow SWITCH FLOW        add flow described by FLOW\n"
           "  add-flows SWITCH FILE       add flows from FILE\n"
           "  mod-flows SWITCH FLOW       modify actions of matching FLOWs\n"
           "  del-flows SWITCH [FLOW]     delete matching FLOWs\n"
           "  replace-flows SWITCH FILE   replace flows with those in FILE\n"
           "  diff-flows SOURCE1 SOURCE2  compare flows from two sources\n"
           "  packet-out SWITCH IN_PORT ACTIONS PACKET...\n"
           "                              execute ACTIONS on PACKET\n"
           "  monitor SWITCH [MISSLEN] [invalid_ttl] [watch:[...]]\n"
           "                              print packets received from SWITCH\n"
           "  snoop SWITCH                snoop on SWITCH and its controller\n"
           "  add-group SWITCH GROUP      add group described by GROUP\n"
           "  add-groups SWITCH FILE      add group from FILE\n"
           "  mod-group SWITCH GROUP      modify specific group\n"
           "  del-groups SWITCH [GROUP]   delete matching GROUPs\n"
           "  insert-buckets SWITCH [GROUP] add buckets to GROUP\n"
           "  remove-buckets SWITCH [GROUP] remove buckets from GROUP\n"
           "  dump-group-features SWITCH  print group features\n"
           "  dump-groups SWITCH [GROUP]  print group description\n"
           "  dump-group-stats SWITCH [GROUP]  print group statistics\n"
           "  queue-get-config SWITCH PORT  print queue information for port\n"
           "  add-meter SWITCH METER      add meter described by METER\n"
           "  mod-meter SWITCH METER      modify specific METER\n"
           "  del-meter SWITCH METER      delete METER\n"
           "  del-meters SWITCH           delete all meters\n"
           "  dump-meter SWITCH METER     print METER configuration\n"
           "  dump-meters SWITCH          print all meter configuration\n"
           "  meter-stats SWITCH [METER]  print meter statistics\n"
           "  meter-features SWITCH       print meter features\n"
           "\nFor OpenFlow switches and controllers:\n"
           "  probe TARGET                probe whether TARGET is up\n"
           "  ping TARGET [N]             latency of N-byte echos\n"
           "  benchmark TARGET N COUNT    bandwidth of COUNT N-byte echos\n"
           "SWITCH or TARGET is an active OpenFlow connection method.\n"
           "\nOther commands:\n"
           "  ofp-parse FILE              print messages read from FILE\n"
           "  ofp-parse-pcap PCAP         print OpenFlow read from PCAP\n",
           program_name, program_name);
    vconn_usage(true, false, false);
    daemon_usage();
    ofp_version_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  --strict                    use strict match for flow commands\n"
           "  --readd                     replace flows that haven't changed\n"
           "  -F, --flow-format=FORMAT    force particular flow format\n"
           "  -P, --packet-in-format=FRMT force particular packet in format\n"
           "  -m, --more                  be more verbose printing OpenFlow\n"
           "  --timestamp                 (monitor, snoop) print timestamps\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  --sort[=field]              sort in ascending order\n"
           "  --rsort[=field]             sort in descending order\n"
           "  --unixctl=SOCKET            set control socket name\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
}

static void
ofctl_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
           const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
}

static void run(int retval, const char *message, ...)
    OVS_PRINTF_FORMAT(2, 3);

static void
run(int retval, const char *message, ...)
{
    if (retval) {
        va_list args;

        va_start(args, message);
        ovs_fatal_valist(retval, message, args);
    }
}

/* Generic commands. */

static int
open_vconn_socket(const char *name, struct vconn **vconnp)
{
    char *vconn_name = xasprintf("unix:%s", name);
    int error;

    error = vconn_open(vconn_name, get_allowed_ofp_versions(), DSCP_DEFAULT,
                       vconnp);
    if (error && error != ENOENT) {
        ovs_fatal(0, "%s: failed to open socket (%s)", name,
                  ovs_strerror(error));
    }
    free(vconn_name);

    return error;
}

enum open_target { MGMT, SNOOP };

static enum ofputil_protocol
open_vconn__(const char *name, enum open_target target,
             struct vconn **vconnp)
{
    const char *suffix = target == MGMT ? "mgmt" : "snoop";
    char *datapath_name, *datapath_type, *socket_name;
    enum ofputil_protocol protocol;
    char *bridge_path;
    int ofp_version;
    int error;

    bridge_path = xasprintf("%s/%s.%s", ovs_rundir(), name, suffix);

    ofproto_parse_name(name, &datapath_name, &datapath_type);
    socket_name = xasprintf("%s/%s.%s", ovs_rundir(), datapath_name, suffix);
    free(datapath_name);
    free(datapath_type);

    if (strchr(name, ':')) {
        run(vconn_open(name, get_allowed_ofp_versions(), DSCP_DEFAULT, vconnp),
            "connecting to %s", name);
    } else if (!open_vconn_socket(name, vconnp)) {
        /* Fall Through. */
    } else if (!open_vconn_socket(bridge_path, vconnp)) {
        /* Fall Through. */
    } else if (!open_vconn_socket(socket_name, vconnp)) {
        /* Fall Through. */
    } else {
        ovs_fatal(0, "%s is not a bridge or a socket", name);
    }

    if (target == SNOOP) {
        vconn_set_recv_any_version(*vconnp);
    }

    free(bridge_path);
    free(socket_name);

    VLOG_DBG("connecting to %s", vconn_get_name(*vconnp));
    error = vconn_connect_block(*vconnp);
    if (error) {
        ovs_fatal(0, "%s: failed to connect to socket (%s)", name,
                  ovs_strerror(error));
    }

    ofp_version = vconn_get_version(*vconnp);
    protocol = ofputil_protocol_from_ofp_version(ofp_version);
    if (!protocol) {
        ovs_fatal(0, "%s: unsupported OpenFlow version 0x%02x",
                  name, ofp_version);
    }
    return protocol;
}

static enum ofputil_protocol
open_vconn(const char *name, struct vconn **vconnp)
{
    return open_vconn__(name, MGMT, vconnp);
}

static void
send_openflow_buffer(struct vconn *vconn, struct ofpbuf *buffer)
{
    ofpmsg_update_length(buffer);
    run(vconn_send_block(vconn, buffer), "failed to send packet to switch");
}

static void
dump_transaction(struct vconn *vconn, struct ofpbuf *request)
{
    struct ofpbuf *reply;

    ofpmsg_update_length(request);
    run(vconn_transact(vconn, request, &reply), "talking to %s",
        vconn_get_name(vconn));
    ofp_print(stdout, reply->data, reply->size, verbosity + 1);
    ofpbuf_delete(reply);
}

static void
dump_trivial_transaction(const char *vconn_name, enum ofpraw raw)
{
    struct ofpbuf *request;
    struct vconn *vconn;

    open_vconn(vconn_name, &vconn);
    request = ofpraw_alloc(raw, vconn_get_version(vconn), 0);
    dump_transaction(vconn, request);
    vconn_close(vconn);
}

static void
dump_stats_transaction(struct vconn *vconn, struct ofpbuf *request)
{
    const struct ofp_header *request_oh = request->data;
    ovs_be32 send_xid = request_oh->xid;
    enum ofpraw request_raw;
    enum ofpraw reply_raw;
    bool done = false;

    ofpraw_decode_partial(&request_raw, request->data, request->size);
    reply_raw = ofpraw_stats_request_to_reply(request_raw,
                                              request_oh->version);

    send_openflow_buffer(vconn, request);
    while (!done) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            enum ofpraw raw;

            ofp_print(stdout, reply->data, reply->size, verbosity + 1);

            ofpraw_decode(&raw, reply->data);
            if (ofptype_from_ofpraw(raw) == OFPTYPE_ERROR) {
                done = true;
            } else if (raw == reply_raw) {
                done = !ofpmp_more(reply->data);
            } else {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(reply->data, reply->size,
                                        verbosity + 1));
            }
        } else {
            VLOG_DBG("received reply with xid %08"PRIx32" "
                     "!= expected %08"PRIx32, recv_xid, send_xid);
        }
        ofpbuf_delete(reply);
    }
}

static void
dump_trivial_stats_transaction(const char *vconn_name, enum ofpraw raw)
{
    struct ofpbuf *request;
    struct vconn *vconn;

    open_vconn(vconn_name, &vconn);
    request = ofpraw_alloc(raw, vconn_get_version(vconn), 0);
    dump_stats_transaction(vconn, request);
    vconn_close(vconn);
}

/* Sends all of the 'requests', which should be requests that only have replies
 * if an error occurs, and waits for them to succeed or fail.  If an error does
 * occur, prints it and exits with an error.
 *
 * Destroys all of the 'requests'. */
static void
transact_multiple_noreply(struct vconn *vconn, struct ovs_list *requests)
{
    struct ofpbuf *request, *reply;

    LIST_FOR_EACH (request, list_node, requests) {
        ofpmsg_update_length(request);
    }

    run(vconn_transact_multiple_noreply(vconn, requests, &reply),
        "talking to %s", vconn_get_name(vconn));
    if (reply) {
        ofp_print(stderr, reply->data, reply->size, verbosity + 2);
        exit(1);
    }
    ofpbuf_delete(reply);
}

/* Sends 'request', which should be a request that only has a reply if an error
 * occurs, and waits for it to succeed or fail.  If an error does occur, prints
 * it and exits with an error.
 *
 * Destroys 'request'. */
static void
transact_noreply(struct vconn *vconn, struct ofpbuf *request)
{
    struct ovs_list requests;

    list_init(&requests);
    list_push_back(&requests, &request->list_node);
    transact_multiple_noreply(vconn, &requests);
}

static void
fetch_switch_config(struct vconn *vconn, struct ofp_switch_config *config_)
{
    struct ofp_switch_config *config;
    struct ofpbuf *request;
    struct ofpbuf *reply;
    enum ofptype type;

    request = ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST,
                           vconn_get_version(vconn), 0);
    run(vconn_transact(vconn, request, &reply),
        "talking to %s", vconn_get_name(vconn));

    if (ofptype_pull(&type, reply) || type != OFPTYPE_GET_CONFIG_REPLY) {
        ovs_fatal(0, "%s: bad reply to config request", vconn_get_name(vconn));
    }

    config = ofpbuf_pull(reply, sizeof *config);
    *config_ = *config;

    ofpbuf_delete(reply);
}

static void
set_switch_config(struct vconn *vconn, const struct ofp_switch_config *config)
{
    struct ofpbuf *request;

    request = ofpraw_alloc(OFPRAW_OFPT_SET_CONFIG, vconn_get_version(vconn), 0);
    ofpbuf_put(request, config, sizeof *config);

    transact_noreply(vconn, request);
}

static void
ofctl_show(struct ovs_cmdl_context *ctx)
{
    const char *vconn_name = ctx->argv[1];
    enum ofp_version version;
    struct vconn *vconn;
    struct ofpbuf *request;
    struct ofpbuf *reply;
    bool has_ports;

    open_vconn(vconn_name, &vconn);
    version = vconn_get_version(vconn);
    request = ofpraw_alloc(OFPRAW_OFPT_FEATURES_REQUEST, version, 0);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);

    has_ports = ofputil_switch_features_has_ports(reply);
    ofp_print(stdout, reply->data, reply->size, verbosity + 1);
    ofpbuf_delete(reply);

    if (!has_ports) {
        request = ofputil_encode_port_desc_stats_request(version, OFPP_ANY);
        dump_stats_transaction(vconn, request);
    }
    dump_trivial_transaction(vconn_name, OFPRAW_OFPT_GET_CONFIG_REQUEST);
    vconn_close(vconn);
}

static void
ofctl_dump_desc(struct ovs_cmdl_context *ctx)
{
    dump_trivial_stats_transaction(ctx->argv[1], OFPRAW_OFPST_DESC_REQUEST);
}

static void
ofctl_dump_tables(struct ovs_cmdl_context *ctx)
{
    dump_trivial_stats_transaction(ctx->argv[1], OFPRAW_OFPST_TABLE_REQUEST);
}

static void
ofctl_dump_table_features(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;

    open_vconn(ctx->argv[1], &vconn);
    request = ofputil_encode_table_features_request(vconn_get_version(vconn));
    if (request) {
        dump_stats_transaction(vconn, request);
    }

    vconn_close(vconn);
}

static bool fetch_port_by_stats(struct vconn *,
                                const char *port_name, ofp_port_t port_no,
                                struct ofputil_phy_port *);

/* Uses OFPT_FEATURES_REQUEST to attempt to fetch information about the port
 * named 'port_name' or numbered 'port_no' into '*pp'.  Returns true if
 * successful, false on failure.
 *
 * This is only appropriate for OpenFlow 1.0, 1.1, and 1.2, which include a
 * list of ports in OFPT_FEATURES_REPLY. */
static bool
fetch_port_by_features(struct vconn *vconn,
                       const char *port_name, ofp_port_t port_no,
                       struct ofputil_phy_port *pp)
{
    struct ofputil_switch_features features;
    const struct ofp_header *oh;
    struct ofpbuf *request, *reply;
    enum ofperr error;
    enum ofptype type;
    struct ofpbuf b;
    bool found = false;

    /* Fetch the switch's ofp_switch_features. */
    request = ofpraw_alloc(OFPRAW_OFPT_FEATURES_REQUEST,
                           vconn_get_version(vconn), 0);
    run(vconn_transact(vconn, request, &reply),
        "talking to %s", vconn_get_name(vconn));

    oh = reply->data;
    if (ofptype_decode(&type, reply->data)
        || type != OFPTYPE_FEATURES_REPLY) {
        ovs_fatal(0, "%s: received bad features reply", vconn_get_name(vconn));
    }
    if (!ofputil_switch_features_has_ports(reply)) {
        /* The switch features reply does not contain a complete list of ports.
         * Probably, there are more ports than will fit into a single 64 kB
         * OpenFlow message.  Use OFPST_PORT_DESC to get a complete list of
         * ports. */
        ofpbuf_delete(reply);
        return fetch_port_by_stats(vconn, port_name, port_no, pp);
    }

    error = ofputil_decode_switch_features(oh, &features, &b);
    if (error) {
        ovs_fatal(0, "%s: failed to decode features reply (%s)",
                  vconn_get_name(vconn), ofperr_to_string(error));
    }

    while (!ofputil_pull_phy_port(oh->version, &b, pp)) {
        if (port_no != OFPP_NONE
            ? port_no == pp->port_no
            : !strcmp(pp->name, port_name)) {
            found = true;
            break;
        }
    }
    ofpbuf_delete(reply);
    return found;
}

/* Uses a OFPST_PORT_DESC request to attempt to fetch information about the
 * port named 'port_name' or numbered 'port_no' into '*pp'.  Returns true if
 * successful, false on failure.
 *
 * This is most appropriate for OpenFlow 1.3 and later.  Open vSwitch 1.7 and
 * later also implements OFPST_PORT_DESC, as an extension, for OpenFlow 1.0,
 * 1.1, and 1.2, so this can be used as a fallback in those versions when there
 * are too many ports than fit in an OFPT_FEATURES_REPLY. */
static bool
fetch_port_by_stats(struct vconn *vconn,
                    const char *port_name, ofp_port_t port_no,
                    struct ofputil_phy_port *pp)
{
    struct ofpbuf *request;
    ovs_be32 send_xid;
    bool done = false;
    bool found = false;

    request = ofputil_encode_port_desc_stats_request(vconn_get_version(vconn),
                                                     port_no);
    send_xid = ((struct ofp_header *) request->data)->xid;

    send_openflow_buffer(vconn, request);
    while (!done) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            struct ofp_header *oh = reply->data;
            enum ofptype type;
            struct ofpbuf b;
            uint16_t flags;

            ofpbuf_use_const(&b, oh, ntohs(oh->length));
            if (ofptype_pull(&type, &b)
                || type != OFPTYPE_PORT_DESC_STATS_REPLY) {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(reply->data, reply->size,
                                        verbosity + 1));
            }

            flags = ofpmp_flags(oh);
            done = !(flags & OFPSF_REPLY_MORE);

            if (found) {
                /* We've already found the port, but we need to drain
                 * the queue of any other replies for this request. */
                continue;
            }

            while (!ofputil_pull_phy_port(oh->version, &b, pp)) {
                if (port_no != OFPP_NONE ? port_no == pp->port_no
                                         : !strcmp(pp->name, port_name)) {
                    found = true;
                    break;
                }
            }
        } else {
            VLOG_DBG("received reply with xid %08"PRIx32" "
                     "!= expected %08"PRIx32, recv_xid, send_xid);
        }
        ofpbuf_delete(reply);
    }

    return found;
}

static bool
str_to_ofp(const char *s, ofp_port_t *ofp_port)
{
    bool ret;
    uint32_t port_;

    ret = str_to_uint(s, 10, &port_);
    *ofp_port = u16_to_ofp(port_);
    return ret;
}

/* Opens a connection to 'vconn_name', fetches the port structure for
 * 'port_name' (which may be a port name or number), and copies it into
 * '*pp'. */
static void
fetch_ofputil_phy_port(const char *vconn_name, const char *port_name,
                       struct ofputil_phy_port *pp)
{
    struct vconn *vconn;
    ofp_port_t port_no;
    bool found;

    /* Try to interpret the argument as a port number. */
    if (!str_to_ofp(port_name, &port_no)) {
        port_no = OFPP_NONE;
    }

    /* OpenFlow 1.0, 1.1, and 1.2 put the list of ports in the
     * OFPT_FEATURES_REPLY message.  OpenFlow 1.3 and later versions put it
     * into the OFPST_PORT_DESC reply.  Try it the correct way. */
    open_vconn(vconn_name, &vconn);
    found = (vconn_get_version(vconn) < OFP13_VERSION
             ? fetch_port_by_features(vconn, port_name, port_no, pp)
             : fetch_port_by_stats(vconn, port_name, port_no, pp));
    vconn_close(vconn);

    if (!found) {
        ovs_fatal(0, "%s: couldn't find port `%s'", vconn_name, port_name);
    }
}

/* Returns the port number corresponding to 'port_name' (which may be a port
 * name or number) within the switch 'vconn_name'. */
static ofp_port_t
str_to_port_no(const char *vconn_name, const char *port_name)
{
    ofp_port_t port_no;

    if (ofputil_port_from_string(port_name, &port_no)) {
        return port_no;
    } else {
        struct ofputil_phy_port pp;

        fetch_ofputil_phy_port(vconn_name, port_name, &pp);
        return pp.port_no;
    }
}

static bool
try_set_protocol(struct vconn *vconn, enum ofputil_protocol want,
                 enum ofputil_protocol *cur)
{
    for (;;) {
        struct ofpbuf *request, *reply;
        enum ofputil_protocol next;

        request = ofputil_encode_set_protocol(*cur, want, &next);
        if (!request) {
            return *cur == want;
        }

        run(vconn_transact_noreply(vconn, request, &reply),
            "talking to %s", vconn_get_name(vconn));
        if (reply) {
            char *s = ofp_to_string(reply->data, reply->size, 2);
            VLOG_DBG("%s: failed to set protocol, switch replied: %s",
                     vconn_get_name(vconn), s);
            free(s);
            ofpbuf_delete(reply);
            return false;
        }

        *cur = next;
    }
}

static enum ofputil_protocol
set_protocol_for_flow_dump(struct vconn *vconn,
                           enum ofputil_protocol cur_protocol,
                           enum ofputil_protocol usable_protocols)
{
    char *usable_s;
    int i;

    for (i = 0; i < ofputil_n_flow_dump_protocols; i++) {
        enum ofputil_protocol f = ofputil_flow_dump_protocols[i];
        if (f & usable_protocols & allowed_protocols
            && try_set_protocol(vconn, f, &cur_protocol)) {
            return f;
        }
    }

    usable_s = ofputil_protocols_to_string(usable_protocols);
    if (usable_protocols & allowed_protocols) {
        ovs_fatal(0, "switch does not support any of the usable flow "
                  "formats (%s)", usable_s);
    } else {
        char *allowed_s = ofputil_protocols_to_string(allowed_protocols);
        ovs_fatal(0, "none of the usable flow formats (%s) is among the "
                  "allowed flow formats (%s)", usable_s, allowed_s);
    }
}

static struct vconn *
prepare_dump_flows(int argc, char *argv[], bool aggregate,
                   struct ofpbuf **requestp)
{
    enum ofputil_protocol usable_protocols, protocol;
    struct ofputil_flow_stats_request fsr;
    struct vconn *vconn;
    char *error;

    error = parse_ofp_flow_stats_request_str(&fsr, aggregate,
                                             argc > 2 ? argv[2] : "",
                                             &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    protocol = open_vconn(argv[1], &vconn);
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);
    *requestp = ofputil_encode_flow_stats_request(&fsr, protocol);
    return vconn;
}

static void
ofctl_dump_flows__(int argc, char *argv[], bool aggregate)
{
    struct ofpbuf *request;
    struct vconn *vconn;

    vconn = prepare_dump_flows(argc, argv, aggregate, &request);
    dump_stats_transaction(vconn, request);
    vconn_close(vconn);
}

static int
compare_flows(const void *afs_, const void *bfs_)
{
    const struct ofputil_flow_stats *afs = afs_;
    const struct ofputil_flow_stats *bfs = bfs_;
    const struct match *a = &afs->match;
    const struct match *b = &bfs->match;
    const struct sort_criterion *sc;

    for (sc = criteria; sc < &criteria[n_criteria]; sc++) {
        const struct mf_field *f = sc->field;
        int ret;

        if (!f) {
            int a_pri = afs->priority;
            int b_pri = bfs->priority;
            ret = a_pri < b_pri ? -1 : a_pri > b_pri;
        } else {
            bool ina, inb;

            ina = mf_are_prereqs_ok(f, &a->flow) && !mf_is_all_wild(f, &a->wc);
            inb = mf_are_prereqs_ok(f, &b->flow) && !mf_is_all_wild(f, &b->wc);
            if (ina != inb) {
                /* Skip the test for sc->order, so that missing fields always
                 * sort to the end whether we're sorting in ascending or
                 * descending order. */
                return ina ? -1 : 1;
            } else {
                union mf_value aval, bval;

                mf_get_value(f, &a->flow, &aval);
                mf_get_value(f, &b->flow, &bval);
                ret = memcmp(&aval, &bval, f->n_bytes);
            }
        }

        if (ret) {
            return sc->order == SORT_ASC ? ret : -ret;
        }
    }

    return 0;
}

static void
ofctl_dump_flows(struct ovs_cmdl_context *ctx)
{
    if (!n_criteria) {
        ofctl_dump_flows__(ctx->argc, ctx->argv, false);
        return;
    } else {
        struct ofputil_flow_stats *fses;
        size_t n_fses, allocated_fses;
        struct ofpbuf *request;
        struct ofpbuf ofpacts;
        struct ofpbuf *reply;
        struct vconn *vconn;
        ovs_be32 send_xid;
        struct ds s;
        size_t i;

        vconn = prepare_dump_flows(ctx->argc, ctx->argv, false, &request);
        send_xid = ((struct ofp_header *) request->data)->xid;
        send_openflow_buffer(vconn, request);

        fses = NULL;
        n_fses = allocated_fses = 0;
        reply = NULL;
        ofpbuf_init(&ofpacts, 0);
        for (;;) {
            struct ofputil_flow_stats *fs;

            if (n_fses >= allocated_fses) {
                fses = x2nrealloc(fses, &allocated_fses, sizeof *fses);
            }

            fs = &fses[n_fses];
            if (!recv_flow_stats_reply(vconn, send_xid, &reply, fs,
                                       &ofpacts)) {
                break;
            }
            fs->ofpacts = xmemdup(fs->ofpacts, fs->ofpacts_len);
            n_fses++;
        }
        ofpbuf_uninit(&ofpacts);

        qsort(fses, n_fses, sizeof *fses, compare_flows);

        ds_init(&s);
        for (i = 0; i < n_fses; i++) {
            ds_clear(&s);
            ofp_print_flow_stats(&s, &fses[i]);
            puts(ds_cstr(&s));
        }
        ds_destroy(&s);

        for (i = 0; i < n_fses; i++) {
            free(CONST_CAST(struct ofpact *, fses[i].ofpacts));
        }
        free(fses);

        vconn_close(vconn);
    }
}

static void
ofctl_dump_aggregate(struct ovs_cmdl_context *ctx)
{
    ofctl_dump_flows__(ctx->argc, ctx->argv, true);
}

static void
ofctl_queue_stats(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;
    struct ofputil_queue_stats_request oqs;

    open_vconn(ctx->argv[1], &vconn);

    if (ctx->argc > 2 && ctx->argv[2][0] && strcasecmp(ctx->argv[2], "all")) {
        oqs.port_no = str_to_port_no(ctx->argv[1], ctx->argv[2]);
    } else {
        oqs.port_no = OFPP_ANY;
    }
    if (ctx->argc > 3 && ctx->argv[3][0] && strcasecmp(ctx->argv[3], "all")) {
        oqs.queue_id = atoi(ctx->argv[3]);
    } else {
        oqs.queue_id = OFPQ_ALL;
    }

    request = ofputil_encode_queue_stats_request(vconn_get_version(vconn), &oqs);
    dump_stats_transaction(vconn, request);
    vconn_close(vconn);
}

static void
ofctl_queue_get_config(struct ovs_cmdl_context *ctx)
{
    const char *vconn_name = ctx->argv[1];
    const char *port_name = ctx->argv[2];
    enum ofputil_protocol protocol;
    enum ofp_version version;
    struct ofpbuf *request;
    struct vconn *vconn;
    ofp_port_t port;

    port = str_to_port_no(vconn_name, port_name);

    protocol = open_vconn(vconn_name, &vconn);
    version = ofputil_protocol_to_ofp_version(protocol);
    request = ofputil_encode_queue_get_config_request(version, port);
    dump_transaction(vconn, request);
    vconn_close(vconn);
}

static enum ofputil_protocol
open_vconn_for_flow_mod(const char *remote, struct vconn **vconnp,
                        enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol cur_protocol;
    char *usable_s;
    int i;

    if (!(usable_protocols & allowed_protocols)) {
        char *allowed_s = ofputil_protocols_to_string(allowed_protocols);
        usable_s = ofputil_protocols_to_string(usable_protocols);
        ovs_fatal(0, "none of the usable flow formats (%s) is among the "
                  "allowed flow formats (%s)", usable_s, allowed_s);
    }

    /* If the initial flow format is allowed and usable, keep it. */
    cur_protocol = open_vconn(remote, vconnp);
    if (usable_protocols & allowed_protocols & cur_protocol) {
        return cur_protocol;
    }

    /* Otherwise try each flow format in turn. */
    for (i = 0; i < sizeof(enum ofputil_protocol) * CHAR_BIT; i++) {
        enum ofputil_protocol f = 1 << i;

        if (f != cur_protocol
            && f & usable_protocols & allowed_protocols
            && try_set_protocol(*vconnp, f, &cur_protocol)) {
            return f;
        }
    }

    usable_s = ofputil_protocols_to_string(usable_protocols);
    ovs_fatal(0, "switch does not support any of the usable flow "
              "formats (%s)", usable_s);
}

static void
ofctl_flow_mod__(const char *remote, struct ofputil_flow_mod *fms,
                 size_t n_fms, enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol protocol;
    struct vconn *vconn;
    size_t i;

    protocol = open_vconn_for_flow_mod(remote, &vconn, usable_protocols);

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];

        transact_noreply(vconn, ofputil_encode_flow_mod(fm, protocol));
        free(CONST_CAST(struct ofpact *, fm->ofpacts));
    }
    vconn_close(vconn);
}

static void
ofctl_flow_mod_file(int argc OVS_UNUSED, char *argv[], uint16_t command)
{
    enum ofputil_protocol usable_protocols;
    struct ofputil_flow_mod *fms = NULL;
    size_t n_fms = 0;
    char *error;

    error = parse_ofp_flow_mod_file(argv[2], command, &fms, &n_fms,
                                    &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
    ofctl_flow_mod__(argv[1], fms, n_fms, usable_protocols);
    free(fms);
}

static void
ofctl_flow_mod(int argc, char *argv[], uint16_t command)
{
    if (argc > 2 && !strcmp(argv[2], "-")) {
        ofctl_flow_mod_file(argc, argv, command);
    } else {
        struct ofputil_flow_mod fm;
        char *error;
        enum ofputil_protocol usable_protocols;

        error = parse_ofp_flow_mod_str(&fm, argc > 2 ? argv[2] : "", command,
                                       &usable_protocols);
        if (error) {
            ovs_fatal(0, "%s", error);
        }
        ofctl_flow_mod__(argv[1], &fm, 1, usable_protocols);
    }
}

static void
ofctl_add_flow(struct ovs_cmdl_context *ctx)
{
    ofctl_flow_mod(ctx->argc, ctx->argv, OFPFC_ADD);
}

static void
ofctl_add_flows(struct ovs_cmdl_context *ctx)
{
    ofctl_flow_mod_file(ctx->argc, ctx->argv, OFPFC_ADD);
}

static void
ofctl_mod_flows(struct ovs_cmdl_context *ctx)
{
    ofctl_flow_mod(ctx->argc, ctx->argv, strict ? OFPFC_MODIFY_STRICT : OFPFC_MODIFY);
}

static void
ofctl_del_flows(struct ovs_cmdl_context *ctx)
{
    ofctl_flow_mod(ctx->argc, ctx->argv, strict ? OFPFC_DELETE_STRICT : OFPFC_DELETE);
}

static void
set_packet_in_format(struct vconn *vconn,
                     enum nx_packet_in_format packet_in_format)
{
    struct ofpbuf *spif;

    spif = ofputil_make_set_packet_in_format(vconn_get_version(vconn),
                                             packet_in_format);
    transact_noreply(vconn, spif);
    VLOG_DBG("%s: using user-specified packet in format %s",
             vconn_get_name(vconn),
             ofputil_packet_in_format_to_string(packet_in_format));
}

static int
monitor_set_invalid_ttl_to_controller(struct vconn *vconn)
{
    struct ofp_switch_config config;
    enum ofp_config_flags flags;

    fetch_switch_config(vconn, &config);
    flags = ntohs(config.flags);
    if (!(flags & OFPC_INVALID_TTL_TO_CONTROLLER)) {
        /* Set the invalid ttl config. */
        flags |= OFPC_INVALID_TTL_TO_CONTROLLER;

        config.flags = htons(flags);
        set_switch_config(vconn, &config);

        /* Then retrieve the configuration to see if it really took.  OpenFlow
         * doesn't define error reporting for bad modes, so this is all we can
         * do. */
        fetch_switch_config(vconn, &config);
        flags = ntohs(config.flags);
        if (!(flags & OFPC_INVALID_TTL_TO_CONTROLLER)) {
            ovs_fatal(0, "setting invalid_ttl_to_controller failed (this "
                      "switch probably doesn't support mode)");
            return -EOPNOTSUPP;
        }
    }
    return 0;
}

/* Converts hex digits in 'hex' to an OpenFlow message in '*msgp'.  The
 * caller must free '*msgp'.  On success, returns NULL.  On failure, returns
 * an error message and stores NULL in '*msgp'. */
static const char *
openflow_from_hex(const char *hex, struct ofpbuf **msgp)
{
    struct ofp_header *oh;
    struct ofpbuf *msg;

    msg = ofpbuf_new(strlen(hex) / 2);
    *msgp = NULL;

    if (ofpbuf_put_hex(msg, hex, NULL)[0] != '\0') {
        ofpbuf_delete(msg);
        return "Trailing garbage in hex data";
    }

    if (msg->size < sizeof(struct ofp_header)) {
        ofpbuf_delete(msg);
        return "Message too short for OpenFlow";
    }

    oh = msg->data;
    if (msg->size != ntohs(oh->length)) {
        ofpbuf_delete(msg);
        return "Message size does not match length in OpenFlow header";
    }

    *msgp = msg;
    return NULL;
}

static void
ofctl_send(struct unixctl_conn *conn, int argc,
           const char *argv[], void *vconn_)
{
    struct vconn *vconn = vconn_;
    struct ds reply;
    bool ok;
    int i;

    ok = true;
    ds_init(&reply);
    for (i = 1; i < argc; i++) {
        const char *error_msg;
        struct ofpbuf *msg;
        int error;

        error_msg = openflow_from_hex(argv[i], &msg);
        if (error_msg) {
            ds_put_format(&reply, "%s\n", error_msg);
            ok = false;
            continue;
        }

        fprintf(stderr, "send: ");
        ofp_print(stderr, msg->data, msg->size, verbosity);

        error = vconn_send_block(vconn, msg);
        if (error) {
            ofpbuf_delete(msg);
            ds_put_format(&reply, "%s\n", ovs_strerror(error));
            ok = false;
        } else {
            ds_put_cstr(&reply, "sent\n");
        }
    }

    if (ok) {
        unixctl_command_reply(conn, ds_cstr(&reply));
    } else {
        unixctl_command_reply_error(conn, ds_cstr(&reply));
    }
    ds_destroy(&reply);
}

struct barrier_aux {
    struct vconn *vconn;        /* OpenFlow connection for sending barrier. */
    struct unixctl_conn *conn;  /* Connection waiting for barrier response. */
};

static void
ofctl_barrier(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *aux_)
{
    struct barrier_aux *aux = aux_;
    struct ofpbuf *msg;
    int error;

    if (aux->conn) {
        unixctl_command_reply_error(conn, "already waiting for barrier reply");
        return;
    }

    msg = ofputil_encode_barrier_request(vconn_get_version(aux->vconn));
    error = vconn_send_block(aux->vconn, msg);
    if (error) {
        ofpbuf_delete(msg);
        unixctl_command_reply_error(conn, ovs_strerror(error));
    } else {
        aux->conn = conn;
    }
}

static void
ofctl_set_output_file(struct unixctl_conn *conn, int argc OVS_UNUSED,
                      const char *argv[], void *aux OVS_UNUSED)
{
    int fd;

    fd = open(argv[1], O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (fd < 0) {
        unixctl_command_reply_error(conn, ovs_strerror(errno));
        return;
    }

    fflush(stderr);
    dup2(fd, STDERR_FILENO);
    close(fd);
    unixctl_command_reply(conn, NULL);
}

static void
ofctl_block(struct unixctl_conn *conn, int argc OVS_UNUSED,
            const char *argv[] OVS_UNUSED, void *blocked_)
{
    bool *blocked = blocked_;

    if (!*blocked) {
        *blocked = true;
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply(conn, "already blocking");
    }
}

static void
ofctl_unblock(struct unixctl_conn *conn, int argc OVS_UNUSED,
              const char *argv[] OVS_UNUSED, void *blocked_)
{
    bool *blocked = blocked_;

    if (*blocked) {
        *blocked = false;
        unixctl_command_reply(conn, NULL);
    } else {
        unixctl_command_reply(conn, "already unblocked");
    }
}

/* Prints to stdout all of the messages received on 'vconn'.
 *
 * Iff 'reply_to_echo_requests' is true, sends a reply to any echo request
 * received on 'vconn'. */
static void
monitor_vconn(struct vconn *vconn, bool reply_to_echo_requests)
{
    struct barrier_aux barrier_aux = { vconn, NULL };
    struct unixctl_server *server;
    bool exiting = false;
    bool blocked = false;
    int error;

    daemon_save_fd(STDERR_FILENO);
    daemonize_start();
    error = unixctl_server_create(unixctl_path, &server);
    if (error) {
        ovs_fatal(error, "failed to create unixctl server");
    }
    unixctl_command_register("exit", "", 0, 0, ofctl_exit, &exiting);
    unixctl_command_register("ofctl/send", "OFMSG...", 1, INT_MAX,
                             ofctl_send, vconn);
    unixctl_command_register("ofctl/barrier", "", 0, 0,
                             ofctl_barrier, &barrier_aux);
    unixctl_command_register("ofctl/set-output-file", "FILE", 1, 1,
                             ofctl_set_output_file, NULL);

    unixctl_command_register("ofctl/block", "", 0, 0, ofctl_block, &blocked);
    unixctl_command_register("ofctl/unblock", "", 0, 0, ofctl_unblock,
                             &blocked);

    daemonize_complete();

    for (;;) {
        struct ofpbuf *b;
        int retval;

        unixctl_server_run(server);

        while (!blocked) {
            enum ofptype type;

            retval = vconn_recv(vconn, &b);
            if (retval == EAGAIN) {
                break;
            }
            run(retval, "vconn_recv");

            if (timestamp) {
                char *s = xastrftime_msec("%Y-%m-%d %H:%M:%S.###: ",
                                          time_wall_msec(), true);
                fputs(s, stderr);
                free(s);
            }

            ofptype_decode(&type, b->data);
            ofp_print(stderr, b->data, b->size, verbosity + 2);
            fflush(stderr);

            switch ((int) type) {
            case OFPTYPE_BARRIER_REPLY:
                if (barrier_aux.conn) {
                    unixctl_command_reply(barrier_aux.conn, NULL);
                    barrier_aux.conn = NULL;
                }
                break;

            case OFPTYPE_ECHO_REQUEST:
                if (reply_to_echo_requests) {
                    struct ofpbuf *reply;

                    reply = make_echo_reply(b->data);
                    retval = vconn_send_block(vconn, reply);
                    if (retval) {
                        ovs_fatal(retval, "failed to send echo reply");
                    }
                }
                break;
            }
            ofpbuf_delete(b);
        }

        if (exiting) {
            break;
        }

        vconn_run(vconn);
        vconn_run_wait(vconn);
        if (!blocked) {
            vconn_recv_wait(vconn);
        }
        unixctl_server_wait(server);
        poll_block();
    }
    vconn_close(vconn);
    unixctl_server_destroy(server);
}

static void
ofctl_monitor(struct ovs_cmdl_context *ctx)
{
    struct vconn *vconn;
    int i;
    enum ofputil_protocol usable_protocols;

    open_vconn(ctx->argv[1], &vconn);
    for (i = 2; i < ctx->argc; i++) {
        const char *arg = ctx->argv[i];

        if (isdigit((unsigned char) *arg)) {
            struct ofp_switch_config config;

            fetch_switch_config(vconn, &config);
            config.miss_send_len = htons(atoi(arg));
            set_switch_config(vconn, &config);
        } else if (!strcmp(arg, "invalid_ttl")) {
            monitor_set_invalid_ttl_to_controller(vconn);
        } else if (!strncmp(arg, "watch:", 6)) {
            struct ofputil_flow_monitor_request fmr;
            struct ofpbuf *msg;
            char *error;

            error = parse_flow_monitor_request(&fmr, arg + 6,
                                               &usable_protocols);
            if (error) {
                ovs_fatal(0, "%s", error);
            }

            msg = ofpbuf_new(0);
            ofputil_append_flow_monitor_request(&fmr, msg);
            dump_stats_transaction(vconn, msg);
            fflush(stdout);
        } else {
            ovs_fatal(0, "%s: unsupported \"monitor\" argument", arg);
        }
    }

    if (preferred_packet_in_format >= 0) {
        set_packet_in_format(vconn, preferred_packet_in_format);
    } else {
        enum ofp_version version = vconn_get_version(vconn);

        switch (version) {
        case OFP10_VERSION: {
            struct ofpbuf *spif, *reply;

            spif = ofputil_make_set_packet_in_format(vconn_get_version(vconn),
                                                     NXPIF_NXM);
            run(vconn_transact_noreply(vconn, spif, &reply),
                "talking to %s", vconn_get_name(vconn));
            if (reply) {
                char *s = ofp_to_string(reply->data, reply->size, 2);
                VLOG_DBG("%s: failed to set packet in format to nxm, controller"
                        " replied: %s. Falling back to the switch default.",
                        vconn_get_name(vconn), s);
                free(s);
                ofpbuf_delete(reply);
            }
            break;
        }
        case OFP11_VERSION:
        case OFP12_VERSION:
        case OFP13_VERSION:
        case OFP14_VERSION:
        case OFP15_VERSION:
            break;
        default:
            OVS_NOT_REACHED();
        }
    }

    monitor_vconn(vconn, true);
}

static void
ofctl_snoop(struct ovs_cmdl_context *ctx)
{
    struct vconn *vconn;

    open_vconn__(ctx->argv[1], SNOOP, &vconn);
    monitor_vconn(vconn, false);
}

static void
ofctl_dump_ports(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;
    ofp_port_t port;

    open_vconn(ctx->argv[1], &vconn);
    port = ctx->argc > 2 ? str_to_port_no(ctx->argv[1], ctx->argv[2]) : OFPP_ANY;
    request = ofputil_encode_dump_ports_request(vconn_get_version(vconn), port);
    dump_stats_transaction(vconn, request);
    vconn_close(vconn);
}

static void
ofctl_dump_ports_desc(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;
    ofp_port_t port;

    open_vconn(ctx->argv[1], &vconn);
    port = ctx->argc > 2 ? str_to_port_no(ctx->argv[1], ctx->argv[2]) : OFPP_ANY;
    request = ofputil_encode_port_desc_stats_request(vconn_get_version(vconn),
                                                     port);
    dump_stats_transaction(vconn, request);
    vconn_close(vconn);
}

static void
ofctl_probe(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;
    struct ofpbuf *reply;

    open_vconn(ctx->argv[1], &vconn);
    request = make_echo_request(vconn_get_version(vconn));
    run(vconn_transact(vconn, request, &reply), "talking to %s", ctx->argv[1]);
    if (reply->size != sizeof(struct ofp_header)) {
        ovs_fatal(0, "reply does not match request");
    }
    ofpbuf_delete(reply);
    vconn_close(vconn);
}

static void
ofctl_packet_out(struct ovs_cmdl_context *ctx)
{
    enum ofputil_protocol protocol;
    struct ofputil_packet_out po;
    struct ofpbuf ofpacts;
    struct vconn *vconn;
    char *error;
    int i;
    enum ofputil_protocol usable_protocols; /* XXX: Use in proto selection */

    ofpbuf_init(&ofpacts, 64);
    error = ofpacts_parse_actions(ctx->argv[3], &ofpacts, &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    po.buffer_id = UINT32_MAX;
    po.in_port = str_to_port_no(ctx->argv[1], ctx->argv[2]);
    po.ofpacts = ofpacts.data;
    po.ofpacts_len = ofpacts.size;

    protocol = open_vconn(ctx->argv[1], &vconn);
    for (i = 4; i < ctx->argc; i++) {
        struct dp_packet *packet;
        struct ofpbuf *opo;
        const char *error_msg;

        error_msg = eth_from_hex(ctx->argv[i], &packet);
        if (error_msg) {
            ovs_fatal(0, "%s", error_msg);
        }

        po.packet = dp_packet_data(packet);
        po.packet_len = dp_packet_size(packet);
        opo = ofputil_encode_packet_out(&po, protocol);
        transact_noreply(vconn, opo);
        dp_packet_delete(packet);
    }
    vconn_close(vconn);
    ofpbuf_uninit(&ofpacts);
}

static void
ofctl_mod_port(struct ovs_cmdl_context *ctx)
{
    struct ofp_config_flag {
        const char *name;             /* The flag's name. */
        enum ofputil_port_config bit; /* Bit to turn on or off. */
        bool on;                      /* Value to set the bit to. */
    };
    static const struct ofp_config_flag flags[] = {
        { "up",          OFPUTIL_PC_PORT_DOWN,    false },
        { "down",        OFPUTIL_PC_PORT_DOWN,    true  },
        { "stp",         OFPUTIL_PC_NO_STP,       false },
        { "receive",     OFPUTIL_PC_NO_RECV,      false },
        { "receive-stp", OFPUTIL_PC_NO_RECV_STP,  false },
        { "flood",       OFPUTIL_PC_NO_FLOOD,     false },
        { "forward",     OFPUTIL_PC_NO_FWD,       false },
        { "packet-in",   OFPUTIL_PC_NO_PACKET_IN, false },
    };

    const struct ofp_config_flag *flag;
    enum ofputil_protocol protocol;
    struct ofputil_port_mod pm;
    struct ofputil_phy_port pp;
    struct vconn *vconn;
    const char *command;
    bool not;

    fetch_ofputil_phy_port(ctx->argv[1], ctx->argv[2], &pp);

    pm.port_no = pp.port_no;
    memcpy(pm.hw_addr, pp.hw_addr, ETH_ADDR_LEN);
    pm.config = 0;
    pm.mask = 0;
    pm.advertise = 0;

    if (!strncasecmp(ctx->argv[3], "no-", 3)) {
        command = ctx->argv[3] + 3;
        not = true;
    } else if (!strncasecmp(ctx->argv[3], "no", 2)) {
        command = ctx->argv[3] + 2;
        not = true;
    } else {
        command = ctx->argv[3];
        not = false;
    }
    for (flag = flags; flag < &flags[ARRAY_SIZE(flags)]; flag++) {
        if (!strcasecmp(command, flag->name)) {
            pm.mask = flag->bit;
            pm.config = flag->on ^ not ? flag->bit : 0;
            goto found;
        }
    }
    ovs_fatal(0, "unknown mod-port command '%s'", ctx->argv[3]);

found:
    protocol = open_vconn(ctx->argv[1], &vconn);
    transact_noreply(vconn, ofputil_encode_port_mod(&pm, protocol));
    vconn_close(vconn);
}

static void
ofctl_mod_table(struct ovs_cmdl_context *ctx)
{
    enum ofputil_protocol protocol, usable_protocols;
    struct ofputil_table_mod tm;
    struct vconn *vconn;
    char *error;
    int i;

    error = parse_ofp_table_mod(&tm, ctx->argv[2], ctx->argv[3], &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    protocol = open_vconn(ctx->argv[1], &vconn);
    if (!(protocol & usable_protocols)) {
        for (i = 0; i < sizeof(enum ofputil_protocol) * CHAR_BIT; i++) {
            enum ofputil_protocol f = 1 << i;
            if (f != protocol
                && f & usable_protocols
                && try_set_protocol(vconn, f, &protocol)) {
                protocol = f;
                break;
            }
        }
    }

    if (!(protocol & usable_protocols)) {
        char *usable_s = ofputil_protocols_to_string(usable_protocols);
        ovs_fatal(0, "Switch does not support table mod message(%s)", usable_s);
    }

    transact_noreply(vconn, ofputil_encode_table_mod(&tm, protocol));
    vconn_close(vconn);
}

static void
ofctl_get_frags(struct ovs_cmdl_context *ctx)
{
    struct ofp_switch_config config;
    struct vconn *vconn;

    open_vconn(ctx->argv[1], &vconn);
    fetch_switch_config(vconn, &config);
    puts(ofputil_frag_handling_to_string(ntohs(config.flags)));
    vconn_close(vconn);
}

static void
ofctl_set_frags(struct ovs_cmdl_context *ctx)
{
    struct ofp_switch_config config;
    enum ofp_config_flags mode;
    struct vconn *vconn;
    ovs_be16 flags;

    if (!ofputil_frag_handling_from_string(ctx->argv[2], &mode)) {
        ovs_fatal(0, "%s: unknown fragment handling mode", ctx->argv[2]);
    }

    open_vconn(ctx->argv[1], &vconn);
    fetch_switch_config(vconn, &config);
    flags = htons(mode) | (config.flags & htons(~OFPC_FRAG_MASK));
    if (flags != config.flags) {
        /* Set the configuration. */
        config.flags = flags;
        set_switch_config(vconn, &config);

        /* Then retrieve the configuration to see if it really took.  OpenFlow
         * doesn't define error reporting for bad modes, so this is all we can
         * do. */
        fetch_switch_config(vconn, &config);
        if (flags != config.flags) {
            ovs_fatal(0, "%s: setting fragment handling mode failed (this "
                      "switch probably doesn't support mode \"%s\")",
                      ctx->argv[1], ofputil_frag_handling_to_string(mode));
        }
    }
    vconn_close(vconn);
}

static void
ofctl_ofp_parse(struct ovs_cmdl_context *ctx)
{
    const char *filename = ctx->argv[1];
    struct ofpbuf b;
    FILE *file;

    file = !strcmp(filename, "-") ? stdin : fopen(filename, "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", filename);
    }

    ofpbuf_init(&b, 65536);
    for (;;) {
        struct ofp_header *oh;
        size_t length, tail_len;
        void *tail;
        size_t n;

        ofpbuf_clear(&b);
        oh = ofpbuf_put_uninit(&b, sizeof *oh);
        n = fread(oh, 1, sizeof *oh, file);
        if (n == 0) {
            break;
        } else if (n < sizeof *oh) {
            ovs_fatal(0, "%s: unexpected end of file mid-message", filename);
        }

        length = ntohs(oh->length);
        if (length < sizeof *oh) {
            ovs_fatal(0, "%s: %"PRIuSIZE"-byte message is too short for OpenFlow",
                      filename, length);
        }

        tail_len = length - sizeof *oh;
        tail = ofpbuf_put_uninit(&b, tail_len);
        n = fread(tail, 1, tail_len, file);
        if (n < tail_len) {
            ovs_fatal(0, "%s: unexpected end of file mid-message", filename);
        }

        ofp_print(stdout, b.data, b.size, verbosity + 2);
    }
    ofpbuf_uninit(&b);

    if (file != stdin) {
        fclose(file);
    }
}

static bool
is_openflow_port(ovs_be16 port_, char *ports[])
{
    uint16_t port = ntohs(port_);
    if (ports[0]) {
        int i;

        for (i = 0; ports[i]; i++) {
            if (port == atoi(ports[i])) {
                return true;
            }
        }
        return false;
    } else {
        return port == OFP_PORT || port == OFP_OLD_PORT;
    }
}

static void
ofctl_ofp_parse_pcap(struct ovs_cmdl_context *ctx)
{
    struct tcp_reader *reader;
    FILE *file;
    int error;
    bool first;

    file = ovs_pcap_open(ctx->argv[1], "rb");
    if (!file) {
        ovs_fatal(errno, "%s: open failed", ctx->argv[1]);
    }

    reader = tcp_reader_open();
    first = true;
    for (;;) {
        struct dp_packet *packet;
        long long int when;
        struct flow flow;

        error = ovs_pcap_read(file, &packet, &when);
        if (error) {
            break;
        }
        packet->md = PKT_METADATA_INITIALIZER(ODPP_NONE);
        flow_extract(packet, &flow);
        if (flow.dl_type == htons(ETH_TYPE_IP)
            && flow.nw_proto == IPPROTO_TCP
            && (is_openflow_port(flow.tp_src, ctx->argv + 2) ||
                is_openflow_port(flow.tp_dst, ctx->argv + 2))) {
            struct dp_packet *payload = tcp_reader_run(reader, &flow, packet);
            if (payload) {
                while (dp_packet_size(payload) >= sizeof(struct ofp_header)) {
                    const struct ofp_header *oh;
                    void *data = dp_packet_data(payload);
                    int length;

                    /* Align OpenFlow on 8-byte boundary for safe access. */
                    dp_packet_shift(payload, -((intptr_t) data & 7));

                    oh = dp_packet_data(payload);
                    length = ntohs(oh->length);
                    if (dp_packet_size(payload) < length) {
                        break;
                    }

                    if (!first) {
                        putchar('\n');
                    }
                    first = false;

                    if (timestamp) {
                        char *s = xastrftime_msec("%H:%M:%S.### ", when, true);
                        fputs(s, stdout);
                        free(s);
                    }

                    printf(IP_FMT".%"PRIu16" > "IP_FMT".%"PRIu16":\n",
                           IP_ARGS(flow.nw_src), ntohs(flow.tp_src),
                           IP_ARGS(flow.nw_dst), ntohs(flow.tp_dst));
                    ofp_print(stdout, dp_packet_data(payload), length, verbosity + 1);
                    dp_packet_pull(payload, length);
                }
            }
        }
        dp_packet_delete(packet);
    }
    tcp_reader_close(reader);
}

static void
ofctl_ping(struct ovs_cmdl_context *ctx)
{
    size_t max_payload = 65535 - sizeof(struct ofp_header);
    unsigned int payload;
    struct vconn *vconn;
    int i;

    payload = ctx->argc > 2 ? atoi(ctx->argv[2]) : 64;
    if (payload > max_payload) {
        ovs_fatal(0, "payload must be between 0 and %"PRIuSIZE" bytes", max_payload);
    }

    open_vconn(ctx->argv[1], &vconn);
    for (i = 0; i < 10; i++) {
        struct timeval start, end;
        struct ofpbuf *request, *reply;
        const struct ofp_header *rpy_hdr;
        enum ofptype type;

        request = ofpraw_alloc(OFPRAW_OFPT_ECHO_REQUEST,
                               vconn_get_version(vconn), payload);
        random_bytes(ofpbuf_put_uninit(request, payload), payload);

        xgettimeofday(&start);
        run(vconn_transact(vconn, ofpbuf_clone(request), &reply), "transact");
        xgettimeofday(&end);

        rpy_hdr = reply->data;
        if (ofptype_pull(&type, reply)
            || type != OFPTYPE_ECHO_REPLY
            || reply->size != payload
            || memcmp(request->msg, reply->msg, payload)) {
            printf("Reply does not match request.  Request:\n");
            ofp_print(stdout, request, request->size, verbosity + 2);
            printf("Reply:\n");
            ofp_print(stdout, reply, reply->size, verbosity + 2);
        }
        printf("%"PRIu32" bytes from %s: xid=%08"PRIx32" time=%.1f ms\n",
               reply->size, ctx->argv[1], ntohl(rpy_hdr->xid),
                   (1000*(double)(end.tv_sec - start.tv_sec))
                   + (.001*(end.tv_usec - start.tv_usec)));
        ofpbuf_delete(request);
        ofpbuf_delete(reply);
    }
    vconn_close(vconn);
}

static void
ofctl_benchmark(struct ovs_cmdl_context *ctx)
{
    size_t max_payload = 65535 - sizeof(struct ofp_header);
    struct timeval start, end;
    unsigned int payload_size, message_size;
    struct vconn *vconn;
    double duration;
    int count;
    int i;

    payload_size = atoi(ctx->argv[2]);
    if (payload_size > max_payload) {
        ovs_fatal(0, "payload must be between 0 and %"PRIuSIZE" bytes", max_payload);
    }
    message_size = sizeof(struct ofp_header) + payload_size;

    count = atoi(ctx->argv[3]);

    printf("Sending %d packets * %u bytes (with header) = %u bytes total\n",
           count, message_size, count * message_size);

    open_vconn(ctx->argv[1], &vconn);
    xgettimeofday(&start);
    for (i = 0; i < count; i++) {
        struct ofpbuf *request, *reply;

        request = ofpraw_alloc(OFPRAW_OFPT_ECHO_REQUEST,
                               vconn_get_version(vconn), payload_size);
        ofpbuf_put_zeros(request, payload_size);
        run(vconn_transact(vconn, request, &reply), "transact");
        ofpbuf_delete(reply);
    }
    xgettimeofday(&end);
    vconn_close(vconn);

    duration = ((1000*(double)(end.tv_sec - start.tv_sec))
                + (.001*(end.tv_usec - start.tv_usec)));
    printf("Finished in %.1f ms (%.0f packets/s) (%.0f bytes/s)\n",
           duration, count / (duration / 1000.0),
           count * message_size / (duration / 1000.0));
}

static void
ofctl_group_mod__(const char *remote, struct ofputil_group_mod *gms,
                  size_t n_gms, enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol protocol;
    struct ofputil_group_mod *gm;
    enum ofp_version version;
    struct ofpbuf *request;

    struct vconn *vconn;
    size_t i;

    protocol = open_vconn_for_flow_mod(remote, &vconn, usable_protocols);
    version = ofputil_protocol_to_ofp_version(protocol);

    for (i = 0; i < n_gms; i++) {
        gm = &gms[i];
        request = ofputil_encode_group_mod(version, gm);
        if (request) {
            transact_noreply(vconn, request);
        }
    }

    vconn_close(vconn);

}


static void
ofctl_group_mod_file(int argc OVS_UNUSED, char *argv[], uint16_t command)
{
    struct ofputil_group_mod *gms = NULL;
    enum ofputil_protocol usable_protocols;
    size_t n_gms = 0;
    char *error;
    int i;

    error = parse_ofp_group_mod_file(argv[2], command, &gms, &n_gms,
                                     &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
    ofctl_group_mod__(argv[1], gms, n_gms, usable_protocols);
    for (i = 0; i < n_gms; i++) {
        ofputil_bucket_list_destroy(&gms[i].buckets);
    }
    free(gms);
}

static void
ofctl_group_mod(int argc, char *argv[], uint16_t command)
{
    if (argc > 2 && !strcmp(argv[2], "-")) {
        ofctl_group_mod_file(argc, argv, command);
    } else {
        enum ofputil_protocol usable_protocols;
        struct ofputil_group_mod gm;
        char *error;

        error = parse_ofp_group_mod_str(&gm, command, argc > 2 ? argv[2] : "",
                                        &usable_protocols);
        if (error) {
            ovs_fatal(0, "%s", error);
        }
        ofctl_group_mod__(argv[1], &gm, 1, usable_protocols);
        ofputil_bucket_list_destroy(&gm.buckets);
    }
}

static void
ofctl_add_group(struct ovs_cmdl_context *ctx)
{
    ofctl_group_mod(ctx->argc, ctx->argv, OFPGC11_ADD);
}

static void
ofctl_add_groups(struct ovs_cmdl_context *ctx)
{
    ofctl_group_mod_file(ctx->argc, ctx->argv, OFPGC11_ADD);
}

static void
ofctl_mod_group(struct ovs_cmdl_context *ctx)
{
    ofctl_group_mod(ctx->argc, ctx->argv, OFPGC11_MODIFY);
}

static void
ofctl_del_groups(struct ovs_cmdl_context *ctx)
{
    ofctl_group_mod(ctx->argc, ctx->argv, OFPGC11_DELETE);
}

static void
ofctl_insert_bucket(struct ovs_cmdl_context *ctx)
{
    ofctl_group_mod(ctx->argc, ctx->argv, OFPGC15_INSERT_BUCKET);
}

static void
ofctl_remove_bucket(struct ovs_cmdl_context *ctx)
{
    ofctl_group_mod(ctx->argc, ctx->argv, OFPGC15_REMOVE_BUCKET);
}

static void
ofctl_dump_group_stats(struct ovs_cmdl_context *ctx)
{
    enum ofputil_protocol usable_protocols;
    struct ofputil_group_mod gm;
    struct ofpbuf *request;
    struct vconn *vconn;
    uint32_t group_id;
    char *error;

    memset(&gm, 0, sizeof gm);

    error = parse_ofp_group_mod_str(&gm, OFPGC11_DELETE,
                                    ctx->argc > 2 ? ctx->argv[2] : "",
                                    &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    group_id = gm.group_id;

    open_vconn(ctx->argv[1], &vconn);
    request = ofputil_encode_group_stats_request(vconn_get_version(vconn),
                                                 group_id);
    if (request) {
        dump_stats_transaction(vconn, request);
    }

    vconn_close(vconn);
}

static void
ofctl_dump_group_desc(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;
    uint32_t group_id;

    open_vconn(ctx->argv[1], &vconn);

    if (ctx->argc < 3 || !ofputil_group_from_string(ctx->argv[2], &group_id)) {
        group_id = OFPG11_ALL;
    }

    request = ofputil_encode_group_desc_request(vconn_get_version(vconn),
                                                group_id);
    if (request) {
        dump_stats_transaction(vconn, request);
    }

    vconn_close(vconn);
}

static void
ofctl_dump_group_features(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;

    open_vconn(ctx->argv[1], &vconn);
    request = ofputil_encode_group_features_request(vconn_get_version(vconn));
    if (request) {
        dump_stats_transaction(vconn, request);
    }

    vconn_close(vconn);
}

static void
ofctl_help(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    usage();
}

static void
ofctl_list_commands(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ovs_cmdl_print_commands(get_all_commands());
}

/* replace-flows and diff-flows commands. */

/* A flow table entry, possibly with two different versions. */
struct fte {
    struct cls_rule rule;       /* Within a "struct classifier". */
    struct fte_version *versions[2];
};

/* One version of a Flow Table Entry. */
struct fte_version {
    ovs_be64 cookie;
    uint16_t idle_timeout;
    uint16_t hard_timeout;
    uint16_t importance;
    uint16_t flags;
    struct ofpact *ofpacts;
    size_t ofpacts_len;
};

/* Frees 'version' and the data that it owns. */
static void
fte_version_free(struct fte_version *version)
{
    if (version) {
        free(CONST_CAST(struct ofpact *, version->ofpacts));
        free(version);
    }
}

/* Returns true if 'a' and 'b' are the same, false if they differ.
 *
 * Ignores differences in 'flags' because there's no way to retrieve flags from
 * an OpenFlow switch.  We have to assume that they are the same. */
static bool
fte_version_equals(const struct fte_version *a, const struct fte_version *b)
{
    return (a->cookie == b->cookie
            && a->idle_timeout == b->idle_timeout
            && a->hard_timeout == b->hard_timeout
            && a->importance == b->importance
            && ofpacts_equal(a->ofpacts, a->ofpacts_len,
                             b->ofpacts, b->ofpacts_len));
}

/* Clears 's', then if 's' has a version 'index', formats 'fte' and version
 * 'index' into 's', followed by a new-line. */
static void
fte_version_format(const struct fte *fte, int index, struct ds *s)
{
    const struct fte_version *version = fte->versions[index];

    ds_clear(s);
    if (!version) {
        return;
    }

    cls_rule_format(&fte->rule, s);
    if (version->cookie != htonll(0)) {
        ds_put_format(s, " cookie=0x%"PRIx64, ntohll(version->cookie));
    }
    if (version->idle_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, " idle_timeout=%"PRIu16, version->idle_timeout);
    }
    if (version->hard_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, " hard_timeout=%"PRIu16, version->hard_timeout);
    }
    if (version->importance != 0) {
        ds_put_format(s, " importance=%"PRIu16, version->importance);
    }

    ds_put_cstr(s, " actions=");
    ofpacts_format(version->ofpacts, version->ofpacts_len, s);

    ds_put_char(s, '\n');
}

static struct fte *
fte_from_cls_rule(const struct cls_rule *cls_rule)
{
    return cls_rule ? CONTAINER_OF(cls_rule, struct fte, rule) : NULL;
}

/* Frees 'fte' and its versions. */
static void
fte_free(struct fte *fte)
{
    if (fte) {
        fte_version_free(fte->versions[0]);
        fte_version_free(fte->versions[1]);
        cls_rule_destroy(&fte->rule);
        free(fte);
    }
}

/* Frees all of the FTEs within 'cls'. */
static void
fte_free_all(struct classifier *cls)
{
    struct fte *fte;

    classifier_defer(cls);
    CLS_FOR_EACH (fte, rule, cls) {
        classifier_remove(cls, &fte->rule);
        ovsrcu_postpone(fte_free, fte);
    }
    classifier_destroy(cls);
}

/* Searches 'cls' for an FTE matching 'rule', inserting a new one if
 * necessary.  Sets 'version' as the version of that rule with the given
 * 'index', replacing any existing version, if any.
 *
 * Takes ownership of 'version'. */
static void
fte_insert(struct classifier *cls, const struct match *match,
           int priority, struct fte_version *version, int index)
{
    struct fte *old, *fte;

    fte = xzalloc(sizeof *fte);
    cls_rule_init(&fte->rule, match, priority);
    fte->versions[index] = version;

    old = fte_from_cls_rule(classifier_replace(cls, &fte->rule, NULL, 0));
    if (old) {
        fte->versions[!index] = old->versions[!index];
        old->versions[!index] = NULL;

        ovsrcu_postpone(fte_free, old);
    }
    cls_rule_make_visible(&fte->rule);
}

/* Reads the flows in 'filename' as flow table entries in 'cls' for the version
 * with the specified 'index'.  Returns the flow formats able to represent the
 * flows that were read. */
static enum ofputil_protocol
read_flows_from_file(const char *filename, struct classifier *cls, int index)
{
    enum ofputil_protocol usable_protocols;
    int line_number;
    struct ds s;
    FILE *file;

    file = !strcmp(filename, "-") ? stdin : fopen(filename, "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", filename);
    }

    ds_init(&s);
    usable_protocols = OFPUTIL_P_ANY;
    line_number = 0;
    classifier_defer(cls);
    while (!ds_get_preprocessed_line(&s, file, &line_number)) {
        struct fte_version *version;
        struct ofputil_flow_mod fm;
        char *error;
        enum ofputil_protocol usable;

        error = parse_ofp_str(&fm, OFPFC_ADD, ds_cstr(&s), &usable);
        if (error) {
            ovs_fatal(0, "%s:%d: %s", filename, line_number, error);
        }
        usable_protocols &= usable;

        version = xmalloc(sizeof *version);
        version->cookie = fm.new_cookie;
        version->idle_timeout = fm.idle_timeout;
        version->hard_timeout = fm.hard_timeout;
        version->importance = fm.importance;
        version->flags = fm.flags & (OFPUTIL_FF_SEND_FLOW_REM
                                     | OFPUTIL_FF_EMERG);
        version->ofpacts = fm.ofpacts;
        version->ofpacts_len = fm.ofpacts_len;

        fte_insert(cls, &fm.match, fm.priority, version, index);
    }
    classifier_publish(cls);
    ds_destroy(&s);

    if (file != stdin) {
        fclose(file);
    }

    return usable_protocols;
}

static bool
recv_flow_stats_reply(struct vconn *vconn, ovs_be32 send_xid,
                      struct ofpbuf **replyp,
                      struct ofputil_flow_stats *fs, struct ofpbuf *ofpacts)
{
    struct ofpbuf *reply = *replyp;

    for (;;) {
        int retval;
        bool more;

        /* Get a flow stats reply message, if we don't already have one. */
        if (!reply) {
            enum ofptype type;
            enum ofperr error;

            do {
                run(vconn_recv_block(vconn, &reply),
                    "OpenFlow packet receive failed");
            } while (((struct ofp_header *) reply->data)->xid != send_xid);

            error = ofptype_decode(&type, reply->data);
            if (error || type != OFPTYPE_FLOW_STATS_REPLY) {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(reply->data, reply->size,
                                        verbosity + 1));
            }
        }

        /* Pull an individual flow stats reply out of the message. */
        retval = ofputil_decode_flow_stats_reply(fs, reply, false, ofpacts);
        switch (retval) {
        case 0:
            *replyp = reply;
            return true;

        case EOF:
            more = ofpmp_more(reply->header);
            ofpbuf_delete(reply);
            reply = NULL;
            if (!more) {
                *replyp = NULL;
                return false;
            }
            break;

        default:
            ovs_fatal(0, "parse error in reply (%s)",
                      ofperr_to_string(retval));
        }
    }
}

/* Reads the OpenFlow flow table from 'vconn', which has currently active flow
 * format 'protocol', and adds them as flow table entries in 'cls' for the
 * version with the specified 'index'. */
static void
read_flows_from_switch(struct vconn *vconn,
                       enum ofputil_protocol protocol,
                       struct classifier *cls, int index)
{
    struct ofputil_flow_stats_request fsr;
    struct ofputil_flow_stats fs;
    struct ofpbuf *request;
    struct ofpbuf ofpacts;
    struct ofpbuf *reply;
    ovs_be32 send_xid;

    fsr.aggregate = false;
    match_init_catchall(&fsr.match);
    fsr.out_port = OFPP_ANY;
    fsr.table_id = 0xff;
    fsr.cookie = fsr.cookie_mask = htonll(0);
    request = ofputil_encode_flow_stats_request(&fsr, protocol);
    send_xid = ((struct ofp_header *) request->data)->xid;
    send_openflow_buffer(vconn, request);

    reply = NULL;
    ofpbuf_init(&ofpacts, 0);
    classifier_defer(cls);
    while (recv_flow_stats_reply(vconn, send_xid, &reply, &fs, &ofpacts)) {
        struct fte_version *version;

        version = xmalloc(sizeof *version);
        version->cookie = fs.cookie;
        version->idle_timeout = fs.idle_timeout;
        version->hard_timeout = fs.hard_timeout;
        version->importance = fs.importance;
        version->flags = 0;
        version->ofpacts_len = fs.ofpacts_len;
        version->ofpacts = xmemdup(fs.ofpacts, fs.ofpacts_len);

        fte_insert(cls, &fs.match, fs.priority, version, index);
    }
    classifier_publish(cls);
    ofpbuf_uninit(&ofpacts);
}

static void
fte_make_flow_mod(const struct fte *fte, int index, uint16_t command,
                  enum ofputil_protocol protocol, struct ovs_list *packets)
{
    const struct fte_version *version = fte->versions[index];
    struct ofputil_flow_mod fm;
    struct ofpbuf *ofm;

    minimatch_expand(&fte->rule.match, &fm.match);
    fm.priority = fte->rule.priority;
    fm.cookie = htonll(0);
    fm.cookie_mask = htonll(0);
    fm.new_cookie = version->cookie;
    fm.modify_cookie = true;
    fm.table_id = 0xff;
    fm.command = command;
    fm.idle_timeout = version->idle_timeout;
    fm.hard_timeout = version->hard_timeout;
    fm.importance = version->importance;
    fm.buffer_id = UINT32_MAX;
    fm.out_port = OFPP_ANY;
    fm.flags = version->flags;
    if (command == OFPFC_ADD || command == OFPFC_MODIFY ||
        command == OFPFC_MODIFY_STRICT) {
        fm.ofpacts = version->ofpacts;
        fm.ofpacts_len = version->ofpacts_len;
    } else {
        fm.ofpacts = NULL;
        fm.ofpacts_len = 0;
    }
    fm.delete_reason = OFPRR_DELETE;

    ofm = ofputil_encode_flow_mod(&fm, protocol);
    list_push_back(packets, &ofm->list_node);
}

static void
ofctl_replace_flows(struct ovs_cmdl_context *ctx)
{
    enum { FILE_IDX = 0, SWITCH_IDX = 1 };
    enum ofputil_protocol usable_protocols, protocol;
    struct classifier cls;
    struct ovs_list requests;
    struct vconn *vconn;
    struct fte *fte;

    classifier_init(&cls, NULL);
    usable_protocols = read_flows_from_file(ctx->argv[2], &cls, FILE_IDX);

    protocol = open_vconn(ctx->argv[1], &vconn);
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);

    read_flows_from_switch(vconn, protocol, &cls, SWITCH_IDX);

    list_init(&requests);

    /* Delete flows that exist on the switch but not in the file. */
    CLS_FOR_EACH (fte, rule, &cls) {
        struct fte_version *file_ver = fte->versions[FILE_IDX];
        struct fte_version *sw_ver = fte->versions[SWITCH_IDX];

        if (sw_ver && !file_ver) {
            fte_make_flow_mod(fte, SWITCH_IDX, OFPFC_DELETE_STRICT,
                              protocol, &requests);
        }
    }

    /* Add flows that exist in the file but not on the switch.
     * Update flows that exist in both places but differ. */
    CLS_FOR_EACH (fte, rule, &cls) {
        struct fte_version *file_ver = fte->versions[FILE_IDX];
        struct fte_version *sw_ver = fte->versions[SWITCH_IDX];

        if (file_ver
            && (readd || !sw_ver || !fte_version_equals(sw_ver, file_ver))) {
            fte_make_flow_mod(fte, FILE_IDX, OFPFC_ADD, protocol, &requests);
        }
    }
    transact_multiple_noreply(vconn, &requests);
    vconn_close(vconn);

    fte_free_all(&cls);
}

static void
read_flows_from_source(const char *source, struct classifier *cls, int index)
{
    struct stat s;

    if (source[0] == '/' || source[0] == '.'
        || (!strchr(source, ':') && !stat(source, &s))) {
        read_flows_from_file(source, cls, index);
    } else {
        enum ofputil_protocol protocol;
        struct vconn *vconn;

        protocol = open_vconn(source, &vconn);
        protocol = set_protocol_for_flow_dump(vconn, protocol, OFPUTIL_P_ANY);
        read_flows_from_switch(vconn, protocol, cls, index);
        vconn_close(vconn);
    }
}

static void
ofctl_diff_flows(struct ovs_cmdl_context *ctx)
{
    bool differences = false;
    struct classifier cls;
    struct ds a_s, b_s;
    struct fte *fte;

    classifier_init(&cls, NULL);
    read_flows_from_source(ctx->argv[1], &cls, 0);
    read_flows_from_source(ctx->argv[2], &cls, 1);

    ds_init(&a_s);
    ds_init(&b_s);

    CLS_FOR_EACH (fte, rule, &cls) {
        struct fte_version *a = fte->versions[0];
        struct fte_version *b = fte->versions[1];

        if (!a || !b || !fte_version_equals(a, b)) {
            fte_version_format(fte, 0, &a_s);
            fte_version_format(fte, 1, &b_s);
            if (strcmp(ds_cstr(&a_s), ds_cstr(&b_s))) {
                if (a_s.length) {
                    printf("-%s", ds_cstr(&a_s));
                }
                if (b_s.length) {
                    printf("+%s", ds_cstr(&b_s));
                }
                differences = true;
            }
        }
    }

    ds_destroy(&a_s);
    ds_destroy(&b_s);

    fte_free_all(&cls);

    if (differences) {
        exit(2);
    }
}

static void
ofctl_meter_mod__(const char *bridge, const char *str, int command)
{
    struct ofputil_meter_mod mm;
    struct vconn *vconn;
    enum ofputil_protocol protocol;
    enum ofputil_protocol usable_protocols;
    enum ofp_version version;

    if (str) {
        char *error;
        error = parse_ofp_meter_mod_str(&mm, str, command, &usable_protocols);
        if (error) {
            ovs_fatal(0, "%s", error);
        }
    } else {
        usable_protocols = OFPUTIL_P_OF13_UP;
        mm.command = command;
        mm.meter.meter_id = OFPM13_ALL;
    }

    protocol = open_vconn_for_flow_mod(bridge, &vconn, usable_protocols);
    version = ofputil_protocol_to_ofp_version(protocol);
    transact_noreply(vconn, ofputil_encode_meter_mod(version, &mm));
    vconn_close(vconn);
}

static void
ofctl_meter_request__(const char *bridge, const char *str,
                      enum ofputil_meter_request_type type)
{
    struct ofputil_meter_mod mm;
    struct vconn *vconn;
    enum ofputil_protocol usable_protocols;
    enum ofputil_protocol protocol;
    enum ofp_version version;

    if (str) {
        char *error;
        error = parse_ofp_meter_mod_str(&mm, str, -1, &usable_protocols);
        if (error) {
            ovs_fatal(0, "%s", error);
        }
    } else {
        usable_protocols = OFPUTIL_P_OF13_UP;
        mm.meter.meter_id = OFPM13_ALL;
    }

    protocol = open_vconn_for_flow_mod(bridge, &vconn, usable_protocols);
    version = ofputil_protocol_to_ofp_version(protocol);
    transact_noreply(vconn, ofputil_encode_meter_request(version,
                                                         type,
                                                         mm.meter.meter_id));
    vconn_close(vconn);
}


static void
ofctl_add_meter(struct ovs_cmdl_context *ctx)
{
    ofctl_meter_mod__(ctx->argv[1], ctx->argv[2], OFPMC13_ADD);
}

static void
ofctl_mod_meter(struct ovs_cmdl_context *ctx)
{
    ofctl_meter_mod__(ctx->argv[1], ctx->argv[2], OFPMC13_MODIFY);
}

static void
ofctl_del_meters(struct ovs_cmdl_context *ctx)
{
    ofctl_meter_mod__(ctx->argv[1], ctx->argc > 2 ? ctx->argv[2] : NULL, OFPMC13_DELETE);
}

static void
ofctl_dump_meters(struct ovs_cmdl_context *ctx)
{
    ofctl_meter_request__(ctx->argv[1], ctx->argc > 2 ? ctx->argv[2] : NULL,
                          OFPUTIL_METER_CONFIG);
}

static void
ofctl_meter_stats(struct ovs_cmdl_context *ctx)
{
    ofctl_meter_request__(ctx->argv[1], ctx->argc > 2 ? ctx->argv[2] : NULL,
                          OFPUTIL_METER_STATS);
}

static void
ofctl_meter_features(struct ovs_cmdl_context *ctx)
{
    ofctl_meter_request__(ctx->argv[1], NULL, OFPUTIL_METER_FEATURES);
}


/* Undocumented commands for unit testing. */

static void
ofctl_parse_flows__(struct ofputil_flow_mod *fms, size_t n_fms,
                    enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol protocol = 0;
    char *usable_s;
    size_t i;

    usable_s = ofputil_protocols_to_string(usable_protocols);
    printf("usable protocols: %s\n", usable_s);
    free(usable_s);

    if (!(usable_protocols & allowed_protocols)) {
        ovs_fatal(0, "no usable protocol");
    }
    for (i = 0; i < sizeof(enum ofputil_protocol) * CHAR_BIT; i++) {
        protocol = 1 << i;
        if (protocol & usable_protocols & allowed_protocols) {
            break;
        }
    }
    ovs_assert(is_pow2(protocol));

    printf("chosen protocol: %s\n", ofputil_protocol_to_string(protocol));

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];
        struct ofpbuf *msg;

        msg = ofputil_encode_flow_mod(fm, protocol);
        ofp_print(stdout, msg->data, msg->size, verbosity);
        ofpbuf_delete(msg);

        free(CONST_CAST(struct ofpact *, fm->ofpacts));
    }
}

/* "parse-flow FLOW": parses the argument as a flow (like add-flow) and prints
 * it back to stdout.  */
static void
ofctl_parse_flow(struct ovs_cmdl_context *ctx)
{
    enum ofputil_protocol usable_protocols;
    struct ofputil_flow_mod fm;
    char *error;

    error = parse_ofp_flow_mod_str(&fm, ctx->argv[1], OFPFC_ADD, &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
    ofctl_parse_flows__(&fm, 1, usable_protocols);
}

/* "parse-flows FILENAME": reads the named file as a sequence of flows (like
 * add-flows) and prints each of the flows back to stdout.  */
static void
ofctl_parse_flows(struct ovs_cmdl_context *ctx)
{
    enum ofputil_protocol usable_protocols;
    struct ofputil_flow_mod *fms = NULL;
    size_t n_fms = 0;
    char *error;

    error = parse_ofp_flow_mod_file(ctx->argv[1], OFPFC_ADD, &fms, &n_fms,
                                    &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
    ofctl_parse_flows__(fms, n_fms, usable_protocols);
    free(fms);
}

static void
ofctl_parse_nxm__(bool oxm, enum ofp_version version)
{
    struct ds in;

    ds_init(&in);
    while (!ds_get_test_line(&in, stdin)) {
        struct ofpbuf nx_match;
        struct match match;
        ovs_be64 cookie, cookie_mask;
        enum ofperr error;
        int match_len;

        /* Convert string to nx_match. */
        ofpbuf_init(&nx_match, 0);
        if (oxm) {
            match_len = oxm_match_from_string(ds_cstr(&in), &nx_match);
        } else {
            match_len = nx_match_from_string(ds_cstr(&in), &nx_match);
        }

        /* Convert nx_match to match. */
        if (strict) {
            if (oxm) {
                error = oxm_pull_match(&nx_match, &match);
            } else {
                error = nx_pull_match(&nx_match, match_len, &match,
                                      &cookie, &cookie_mask);
            }
        } else {
            if (oxm) {
                error = oxm_pull_match_loose(&nx_match, &match);
            } else {
                error = nx_pull_match_loose(&nx_match, match_len, &match,
                                            &cookie, &cookie_mask);
            }
        }


        if (!error) {
            char *out;

            /* Convert match back to nx_match. */
            ofpbuf_uninit(&nx_match);
            ofpbuf_init(&nx_match, 0);
            if (oxm) {
                match_len = oxm_put_match(&nx_match, &match, version);
                out = oxm_match_to_string(&nx_match, match_len);
            } else {
                match_len = nx_put_match(&nx_match, &match,
                                         cookie, cookie_mask);
                out = nx_match_to_string(nx_match.data, match_len);
            }

            puts(out);
            free(out);

            if (verbosity > 0) {
                ovs_hex_dump(stdout, nx_match.data, nx_match.size, 0, false);
            }
        } else {
            printf("nx_pull_match() returned error %s\n",
                   ofperr_get_name(error));
        }

        ofpbuf_uninit(&nx_match);
    }
    ds_destroy(&in);
}

/* "parse-nxm": reads a series of NXM nx_match specifications as strings from
 * stdin, does some internal fussing with them, and then prints them back as
 * strings on stdout. */
static void
ofctl_parse_nxm(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    ofctl_parse_nxm__(false, 0);
}

/* "parse-oxm VERSION": reads a series of OXM nx_match specifications as
 * strings from stdin, does some internal fussing with them, and then prints
 * them back as strings on stdout.  VERSION must specify an OpenFlow version,
 * e.g. "OpenFlow12". */
static void
ofctl_parse_oxm(struct ovs_cmdl_context *ctx)
{
    enum ofp_version version = ofputil_version_from_string(ctx->argv[1]);
    if (version < OFP12_VERSION) {
        ovs_fatal(0, "%s: not a valid version for OXM", ctx->argv[1]);
    }

    ofctl_parse_nxm__(true, version);
}

static void
print_differences(const char *prefix,
                  const void *a_, size_t a_len,
                  const void *b_, size_t b_len)
{
    const uint8_t *a = a_;
    const uint8_t *b = b_;
    size_t i;

    for (i = 0; i < MIN(a_len, b_len); i++) {
        if (a[i] != b[i]) {
            printf("%s%2"PRIuSIZE": %02"PRIx8" -> %02"PRIx8"\n",
                   prefix, i, a[i], b[i]);
        }
    }
    for (i = a_len; i < b_len; i++) {
        printf("%s%2"PRIuSIZE": (none) -> %02"PRIx8"\n", prefix, i, b[i]);
    }
    for (i = b_len; i < a_len; i++) {
        printf("%s%2"PRIuSIZE": %02"PRIx8" -> (none)\n", prefix, i, a[i]);
    }
}

static void
ofctl_parse_actions__(const char *version_s, bool instructions)
{
    enum ofp_version version;
    struct ds in;

    version = ofputil_version_from_string(version_s);
    if (!version) {
        ovs_fatal(0, "%s: not a valid OpenFlow version", version_s);
    }

    ds_init(&in);
    while (!ds_get_preprocessed_line(&in, stdin, NULL)) {
        struct ofpbuf of_out;
        struct ofpbuf of_in;
        struct ofpbuf ofpacts;
        const char *table_id;
        char *actions;
        enum ofperr error;
        size_t size;
        struct ds s;

        /* Parse table_id separated with the follow-up actions by ",", if
         * any. */
        actions = ds_cstr(&in);
        table_id = NULL;
        if (strstr(actions, ",")) {
            table_id = strsep(&actions, ",");
        }

        /* Parse hex bytes. */
        ofpbuf_init(&of_in, 0);
        if (ofpbuf_put_hex(&of_in, actions, NULL)[0] != '\0') {
            ovs_fatal(0, "Trailing garbage in hex data");
        }

        /* Convert to ofpacts. */
        ofpbuf_init(&ofpacts, 0);
        size = of_in.size;
        error = (instructions
                 ? ofpacts_pull_openflow_instructions
                 : ofpacts_pull_openflow_actions)(
                     &of_in, of_in.size, version, &ofpacts);
        if (!error && instructions) {
            /* Verify actions, enforce consistency. */
            enum ofputil_protocol protocol;
            struct flow flow;

            memset(&flow, 0, sizeof flow);
            protocol = ofputil_protocols_from_ofp_version(version);
            error = ofpacts_check_consistency(ofpacts.data, ofpacts.size,
                                              &flow, OFPP_MAX,
                                              table_id ? atoi(table_id) : 0,
                                              255, protocol);
        }
        if (error) {
            printf("bad %s %s: %s\n\n",
                   version_s, instructions ? "instructions" : "actions",
                   ofperr_get_name(error));
            ofpbuf_uninit(&ofpacts);
            ofpbuf_uninit(&of_in);
            continue;
        }
        ofpbuf_push_uninit(&of_in, size);

        /* Print cls_rule. */
        ds_init(&s);
        ds_put_cstr(&s, "actions=");
        ofpacts_format(ofpacts.data, ofpacts.size, &s);
        puts(ds_cstr(&s));
        ds_destroy(&s);

        /* Convert back to ofp10 actions and print differences from input. */
        ofpbuf_init(&of_out, 0);
        if (instructions) {
           ofpacts_put_openflow_instructions(ofpacts.data, ofpacts.size,
                                             &of_out, version);
        } else {
           ofpacts_put_openflow_actions(ofpacts.data, ofpacts.size,
                                         &of_out, version);
        }

        print_differences("", of_in.data, of_in.size,
                          of_out.data, of_out.size);
        putchar('\n');

        ofpbuf_uninit(&ofpacts);
        ofpbuf_uninit(&of_in);
        ofpbuf_uninit(&of_out);
    }
    ds_destroy(&in);
}

/* "parse-actions VERSION": reads a series of action specifications for the
 * given OpenFlow VERSION as hex bytes from stdin, converts them to ofpacts,
 * prints them as strings on stdout, and then converts them back to hex bytes
 * and prints any differences from the input. */
static void
ofctl_parse_actions(struct ovs_cmdl_context *ctx)
{
    ofctl_parse_actions__(ctx->argv[1], false);
}

/* "parse-actions VERSION": reads a series of instruction specifications for
 * the given OpenFlow VERSION as hex bytes from stdin, converts them to
 * ofpacts, prints them as strings on stdout, and then converts them back to
 * hex bytes and prints any differences from the input. */
static void
ofctl_parse_instructions(struct ovs_cmdl_context *ctx)
{
    ofctl_parse_actions__(ctx->argv[1], true);
}

/* "parse-ofp10-match": reads a series of ofp10_match specifications as hex
 * bytes from stdin, converts them to cls_rules, prints them as strings on
 * stdout, and then converts them back to hex bytes and prints any differences
 * from the input.
 *
 * The input hex bytes may contain "x"s to represent "don't-cares", bytes whose
 * values are ignored in the input and will be set to zero when OVS converts
 * them back to hex bytes.  ovs-ofctl actually sets "x"s to random bits when
 * it does the conversion to hex, to ensure that in fact they are ignored. */
static void
ofctl_parse_ofp10_match(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct ds expout;
    struct ds in;

    ds_init(&in);
    ds_init(&expout);
    while (!ds_get_preprocessed_line(&in, stdin, NULL)) {
        struct ofpbuf match_in, match_expout;
        struct ofp10_match match_out;
        struct ofp10_match match_normal;
        struct match match;
        char *p;

        /* Parse hex bytes to use for expected output. */
        ds_clear(&expout);
        ds_put_cstr(&expout, ds_cstr(&in));
        for (p = ds_cstr(&expout); *p; p++) {
            if (*p == 'x') {
                *p = '0';
            }
        }
        ofpbuf_init(&match_expout, 0);
        if (ofpbuf_put_hex(&match_expout, ds_cstr(&expout), NULL)[0] != '\0') {
            ovs_fatal(0, "Trailing garbage in hex data");
        }
        if (match_expout.size != sizeof(struct ofp10_match)) {
            ovs_fatal(0, "Input is %"PRIu32" bytes, expected %"PRIuSIZE,
                      match_expout.size, sizeof(struct ofp10_match));
        }

        /* Parse hex bytes for input. */
        for (p = ds_cstr(&in); *p; p++) {
            if (*p == 'x') {
                *p = "0123456789abcdef"[random_uint32() & 0xf];
            }
        }
        ofpbuf_init(&match_in, 0);
        if (ofpbuf_put_hex(&match_in, ds_cstr(&in), NULL)[0] != '\0') {
            ovs_fatal(0, "Trailing garbage in hex data");
        }
        if (match_in.size != sizeof(struct ofp10_match)) {
            ovs_fatal(0, "Input is %"PRIu32" bytes, expected %"PRIuSIZE,
                      match_in.size, sizeof(struct ofp10_match));
        }

        /* Convert to cls_rule and print. */
        ofputil_match_from_ofp10_match(match_in.data, &match);
        match_print(&match);

        /* Convert back to ofp10_match and print differences from input. */
        ofputil_match_to_ofp10_match(&match, &match_out);
        print_differences("", match_expout.data, match_expout.size,
                          &match_out, sizeof match_out);

        /* Normalize, then convert and compare again. */
        ofputil_normalize_match(&match);
        ofputil_match_to_ofp10_match(&match, &match_normal);
        print_differences("normal: ", &match_out, sizeof match_out,
                          &match_normal, sizeof match_normal);
        putchar('\n');

        ofpbuf_uninit(&match_in);
        ofpbuf_uninit(&match_expout);
    }
    ds_destroy(&in);
    ds_destroy(&expout);
}

/* "parse-ofp11-match": reads a series of ofp11_match specifications as hex
 * bytes from stdin, converts them to "struct match"es, prints them as strings
 * on stdout, and then converts them back to hex bytes and prints any
 * differences from the input. */
static void
ofctl_parse_ofp11_match(struct ovs_cmdl_context *ctx OVS_UNUSED)
{
    struct ds in;

    ds_init(&in);
    while (!ds_get_preprocessed_line(&in, stdin, NULL)) {
        struct ofpbuf match_in;
        struct ofp11_match match_out;
        struct match match;
        enum ofperr error;

        /* Parse hex bytes. */
        ofpbuf_init(&match_in, 0);
        if (ofpbuf_put_hex(&match_in, ds_cstr(&in), NULL)[0] != '\0') {
            ovs_fatal(0, "Trailing garbage in hex data");
        }
        if (match_in.size != sizeof(struct ofp11_match)) {
            ovs_fatal(0, "Input is %"PRIu32" bytes, expected %"PRIuSIZE,
                      match_in.size, sizeof(struct ofp11_match));
        }

        /* Convert to match. */
        error = ofputil_match_from_ofp11_match(match_in.data, &match);
        if (error) {
            printf("bad ofp11_match: %s\n\n", ofperr_get_name(error));
            ofpbuf_uninit(&match_in);
            continue;
        }

        /* Print match. */
        match_print(&match);

        /* Convert back to ofp11_match and print differences from input. */
        ofputil_match_to_ofp11_match(&match, &match_out);

        print_differences("", match_in.data, match_in.size,
                          &match_out, sizeof match_out);
        putchar('\n');

        ofpbuf_uninit(&match_in);
    }
    ds_destroy(&in);
}

/* "parse-pcap PCAP": read packets from PCAP and print their flows. */
static void
ofctl_parse_pcap(struct ovs_cmdl_context *ctx)
{
    FILE *pcap;

    pcap = ovs_pcap_open(ctx->argv[1], "rb");
    if (!pcap) {
        ovs_fatal(errno, "%s: open failed", ctx->argv[1]);
    }

    for (;;) {
        struct dp_packet *packet;
        struct flow flow;
        int error;

        error = ovs_pcap_read(pcap, &packet, NULL);
        if (error == EOF) {
            break;
        } else if (error) {
            ovs_fatal(error, "%s: read failed", ctx->argv[1]);
        }

        packet->md = PKT_METADATA_INITIALIZER(ODPP_NONE);
        flow_extract(packet, &flow);
        flow_print(stdout, &flow);
        putchar('\n');
        dp_packet_delete(packet);
    }
}

/* "check-vlan VLAN_TCI VLAN_TCI_MASK": converts the specified vlan_tci and
 * mask values to and from various formats and prints the results. */
static void
ofctl_check_vlan(struct ovs_cmdl_context *ctx)
{
    struct match match;

    char *string_s;
    struct ofputil_flow_mod fm;

    struct ofpbuf nxm;
    struct match nxm_match;
    int nxm_match_len;
    char *nxm_s;

    struct ofp10_match of10_raw;
    struct match of10_match;

    struct ofp11_match of11_raw;
    struct match of11_match;

    enum ofperr error;
    char *error_s;

    enum ofputil_protocol usable_protocols; /* Unused for now. */

    match_init_catchall(&match);
    match.flow.vlan_tci = htons(strtoul(ctx->argv[1], NULL, 16));
    match.wc.masks.vlan_tci = htons(strtoul(ctx->argv[2], NULL, 16));

    /* Convert to and from string. */
    string_s = match_to_string(&match, OFP_DEFAULT_PRIORITY);
    printf("%s -> ", string_s);
    fflush(stdout);
    error_s = parse_ofp_str(&fm, -1, string_s, &usable_protocols);
    if (error_s) {
        ovs_fatal(0, "%s", error_s);
    }
    printf("%04"PRIx16"/%04"PRIx16"\n",
           ntohs(fm.match.flow.vlan_tci),
           ntohs(fm.match.wc.masks.vlan_tci));
    free(string_s);

    /* Convert to and from NXM. */
    ofpbuf_init(&nxm, 0);
    nxm_match_len = nx_put_match(&nxm, &match, htonll(0), htonll(0));
    nxm_s = nx_match_to_string(nxm.data, nxm_match_len);
    error = nx_pull_match(&nxm, nxm_match_len, &nxm_match, NULL, NULL);
    printf("NXM: %s -> ", nxm_s);
    if (error) {
        printf("%s\n", ofperr_to_string(error));
    } else {
        printf("%04"PRIx16"/%04"PRIx16"\n",
               ntohs(nxm_match.flow.vlan_tci),
               ntohs(nxm_match.wc.masks.vlan_tci));
    }
    free(nxm_s);
    ofpbuf_uninit(&nxm);

    /* Convert to and from OXM. */
    ofpbuf_init(&nxm, 0);
    nxm_match_len = oxm_put_match(&nxm, &match, OFP12_VERSION);
    nxm_s = oxm_match_to_string(&nxm, nxm_match_len);
    error = oxm_pull_match(&nxm, &nxm_match);
    printf("OXM: %s -> ", nxm_s);
    if (error) {
        printf("%s\n", ofperr_to_string(error));
    } else {
        uint16_t vid = ntohs(nxm_match.flow.vlan_tci) &
            (VLAN_VID_MASK | VLAN_CFI);
        uint16_t mask = ntohs(nxm_match.wc.masks.vlan_tci) &
            (VLAN_VID_MASK | VLAN_CFI);

        printf("%04"PRIx16"/%04"PRIx16",", vid, mask);
        if (vid && vlan_tci_to_pcp(nxm_match.wc.masks.vlan_tci)) {
            printf("%02"PRIx8"\n", vlan_tci_to_pcp(nxm_match.flow.vlan_tci));
        } else {
            printf("--\n");
        }
    }
    free(nxm_s);
    ofpbuf_uninit(&nxm);

    /* Convert to and from OpenFlow 1.0. */
    ofputil_match_to_ofp10_match(&match, &of10_raw);
    ofputil_match_from_ofp10_match(&of10_raw, &of10_match);
    printf("OF1.0: %04"PRIx16"/%d,%02"PRIx8"/%d -> %04"PRIx16"/%04"PRIx16"\n",
           ntohs(of10_raw.dl_vlan),
           (of10_raw.wildcards & htonl(OFPFW10_DL_VLAN)) != 0,
           of10_raw.dl_vlan_pcp,
           (of10_raw.wildcards & htonl(OFPFW10_DL_VLAN_PCP)) != 0,
           ntohs(of10_match.flow.vlan_tci),
           ntohs(of10_match.wc.masks.vlan_tci));

    /* Convert to and from OpenFlow 1.1. */
    ofputil_match_to_ofp11_match(&match, &of11_raw);
    ofputil_match_from_ofp11_match(&of11_raw, &of11_match);
    printf("OF1.1: %04"PRIx16"/%d,%02"PRIx8"/%d -> %04"PRIx16"/%04"PRIx16"\n",
           ntohs(of11_raw.dl_vlan),
           (of11_raw.wildcards & htonl(OFPFW11_DL_VLAN)) != 0,
           of11_raw.dl_vlan_pcp,
           (of11_raw.wildcards & htonl(OFPFW11_DL_VLAN_PCP)) != 0,
           ntohs(of11_match.flow.vlan_tci),
           ntohs(of11_match.wc.masks.vlan_tci));
}

/* "print-error ENUM": Prints the type and code of ENUM for every OpenFlow
 * version. */
static void
ofctl_print_error(struct ovs_cmdl_context *ctx)
{
    enum ofperr error;
    int version;

    error = ofperr_from_name(ctx->argv[1]);
    if (!error) {
        ovs_fatal(0, "unknown error \"%s\"", ctx->argv[1]);
    }

    for (version = 0; version <= UINT8_MAX; version++) {
        const char *name = ofperr_domain_get_name(version);
        if (name) {
            int vendor = ofperr_get_vendor(error, version);
            int type = ofperr_get_type(error, version);
            int code = ofperr_get_code(error, version);

            if (vendor != -1 || type != -1 || code != -1) {
                printf("%s: vendor %#x, type %d, code %d\n",
                       name, vendor, type, code);
            }
        }
    }
}

/* "encode-error-reply ENUM REQUEST": Encodes an error reply to REQUEST for the
 * error named ENUM and prints the error reply in hex. */
static void
ofctl_encode_error_reply(struct ovs_cmdl_context *ctx)
{
    const struct ofp_header *oh;
    struct ofpbuf request, *reply;
    enum ofperr error;

    error = ofperr_from_name(ctx->argv[1]);
    if (!error) {
        ovs_fatal(0, "unknown error \"%s\"", ctx->argv[1]);
    }

    ofpbuf_init(&request, 0);
    if (ofpbuf_put_hex(&request, ctx->argv[2], NULL)[0] != '\0') {
        ovs_fatal(0, "Trailing garbage in hex data");
    }
    if (request.size < sizeof(struct ofp_header)) {
        ovs_fatal(0, "Request too short");
    }

    oh = request.data;
    if (request.size != ntohs(oh->length)) {
        ovs_fatal(0, "Request size inconsistent");
    }

    reply = ofperr_encode_reply(error, request.data);
    ofpbuf_uninit(&request);

    ovs_hex_dump(stdout, reply->data, reply->size, 0, false);
    ofpbuf_delete(reply);
}

/* "ofp-print HEXSTRING [VERBOSITY]": Converts the hex digits in HEXSTRING into
 * binary data, interpreting them as an OpenFlow message, and prints the
 * OpenFlow message on stdout, at VERBOSITY (level 2 by default).
 *
 * Alternative usage: "ofp-print [VERBOSITY] - < HEXSTRING_FILE", where
 * HEXSTRING_FILE contains the HEXSTRING. */
static void
ofctl_ofp_print(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf packet;
    char *buffer;
    int verbosity = 2;
    struct ds line;

    ds_init(&line);

    if (!strcmp(ctx->argv[ctx->argc-1], "-")) {
        if (ds_get_line(&line, stdin)) {
           VLOG_FATAL("Failed to read stdin");
        }

        buffer = line.string;
        verbosity = ctx->argc > 2 ? atoi(ctx->argv[1]) : verbosity;
    } else if (ctx->argc > 2) {
        buffer = ctx->argv[1];
        verbosity = atoi(ctx->argv[2]);
    } else {
        buffer = ctx->argv[1];
    }

    ofpbuf_init(&packet, strlen(buffer) / 2);
    if (ofpbuf_put_hex(&packet, buffer, NULL)[0] != '\0') {
        ovs_fatal(0, "trailing garbage following hex bytes");
    }
    ofp_print(stdout, packet.data, packet.size, verbosity);
    ofpbuf_uninit(&packet);
    ds_destroy(&line);
}

/* "encode-hello BITMAP...": Encodes each BITMAP as an OpenFlow hello message
 * and dumps each message in hex.  */
static void
ofctl_encode_hello(struct ovs_cmdl_context *ctx)
{
    uint32_t bitmap = strtol(ctx->argv[1], NULL, 0);
    struct ofpbuf *hello;

    hello = ofputil_encode_hello(bitmap);
    ovs_hex_dump(stdout, hello->data, hello->size, 0, false);
    ofp_print(stdout, hello->data, hello->size, verbosity);
    ofpbuf_delete(hello);
}

static const struct ovs_cmdl_command all_commands[] = {
    { "show", "switch",
      1, 1, ofctl_show },
    { "monitor", "switch [misslen] [invalid_ttl] [watch:[...]]",
      1, 3, ofctl_monitor },
    { "snoop", "switch",
      1, 1, ofctl_snoop },
    { "dump-desc", "switch",
      1, 1, ofctl_dump_desc },
    { "dump-tables", "switch",
      1, 1, ofctl_dump_tables },
    { "dump-table-features", "switch",
      1, 1, ofctl_dump_table_features },
    { "dump-flows", "switch",
      1, 2, ofctl_dump_flows },
    { "dump-aggregate", "switch",
      1, 2, ofctl_dump_aggregate },
    { "queue-stats", "switch [port [queue]]",
      1, 3, ofctl_queue_stats },
    { "queue-get-config", "switch port",
      2, 2, ofctl_queue_get_config },
    { "add-flow", "switch flow",
      2, 2, ofctl_add_flow },
    { "add-flows", "switch file",
      2, 2, ofctl_add_flows },
    { "mod-flows", "switch flow",
      2, 2, ofctl_mod_flows },
    { "del-flows", "switch [flow]",
      1, 2, ofctl_del_flows },
    { "replace-flows", "switch file",
      2, 2, ofctl_replace_flows },
    { "diff-flows", "source1 source2",
      2, 2, ofctl_diff_flows },
    { "add-meter", "switch meter",
      2, 2, ofctl_add_meter },
    { "mod-meter", "switch meter",
      2, 2, ofctl_mod_meter },
    { "del-meter", "switch meter",
      2, 2, ofctl_del_meters },
    { "del-meters", "switch",
      1, 1, ofctl_del_meters },
    { "dump-meter", "switch meter",
      2, 2, ofctl_dump_meters },
    { "dump-meters", "switch",
      1, 1, ofctl_dump_meters },
    { "meter-stats", "switch [meter]",
      1, 2, ofctl_meter_stats },
    { "meter-features", "switch",
      1, 1, ofctl_meter_features },
    { "packet-out", "switch in_port actions packet...",
      4, INT_MAX, ofctl_packet_out },
    { "dump-ports", "switch [port]",
      1, 2, ofctl_dump_ports },
    { "dump-ports-desc", "switch [port]",
      1, 2, ofctl_dump_ports_desc },
    { "mod-port", "switch iface act",
      3, 3, ofctl_mod_port },
    { "mod-table", "switch mod",
      3, 3, ofctl_mod_table },
    { "get-frags", "switch",
      1, 1, ofctl_get_frags },
    { "set-frags", "switch frag_mode",
      2, 2, ofctl_set_frags },
    { "probe", "target",
      1, 1, ofctl_probe },
    { "ping", "target [n]",
      1, 2, ofctl_ping },
    { "benchmark", "target n count",
      3, 3, ofctl_benchmark },

    { "ofp-parse", "file",
      1, 1, ofctl_ofp_parse },
    { "ofp-parse-pcap", "pcap",
      1, INT_MAX, ofctl_ofp_parse_pcap },

    { "add-group", "switch group",
      1, 2, ofctl_add_group },
    { "add-groups", "switch file",
      1, 2, ofctl_add_groups },
    { "mod-group", "switch group",
      1, 2, ofctl_mod_group },
    { "del-groups", "switch [group]",
      1, 2, ofctl_del_groups },
    { "insert-buckets", "switch [group]",
      1, 2, ofctl_insert_bucket },
    { "remove-buckets", "switch [group]",
      1, 2, ofctl_remove_bucket },
    { "dump-groups", "switch [group]",
      1, 2, ofctl_dump_group_desc },
    { "dump-group-stats", "switch [group]",
      1, 2, ofctl_dump_group_stats },
    { "dump-group-features", "switch",
      1, 1, ofctl_dump_group_features },
    { "help", NULL, 0, INT_MAX, ofctl_help },
    { "list-commands", NULL, 0, INT_MAX, ofctl_list_commands },

    /* Undocumented commands for testing. */
    { "parse-flow", NULL, 1, 1, ofctl_parse_flow },
    { "parse-flows", NULL, 1, 1, ofctl_parse_flows },
    { "parse-nx-match", NULL, 0, 0, ofctl_parse_nxm },
    { "parse-nxm", NULL, 0, 0, ofctl_parse_nxm },
    { "parse-oxm", NULL, 1, 1, ofctl_parse_oxm },
    { "parse-actions", NULL, 1, 1, ofctl_parse_actions },
    { "parse-instructions", NULL, 1, 1, ofctl_parse_instructions },
    { "parse-ofp10-match", NULL, 0, 0, ofctl_parse_ofp10_match },
    { "parse-ofp11-match", NULL, 0, 0, ofctl_parse_ofp11_match },
    { "parse-pcap", NULL, 1, 1, ofctl_parse_pcap },
    { "check-vlan", NULL, 2, 2, ofctl_check_vlan },
    { "print-error", NULL, 1, 1, ofctl_print_error },
    { "encode-error-reply", NULL, 2, 2, ofctl_encode_error_reply },
    { "ofp-print", NULL, 1, 2, ofctl_ofp_print },
    { "encode-hello", NULL, 1, 1, ofctl_encode_hello },

    { NULL, NULL, 0, 0, NULL },
};

static const struct ovs_cmdl_command *get_all_commands(void)
{
    return all_commands;
}
