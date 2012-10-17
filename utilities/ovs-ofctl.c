/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "byte-order.h"
#include "classifier.h"
#include "command-line.h"
#include "daemon.h"
#include "compiler.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-msgs.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "random.h"
#include "stream-ssl.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"
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

/* --sort, --rsort: Sort order. */
enum sort_order { SORT_ASC, SORT_DESC };
struct sort_criterion {
    const struct mf_field *field; /* NULL means to sort by priority. */
    enum sort_order order;
};
static struct sort_criterion *criteria;
static size_t n_criteria, allocated_criteria;

static const struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

static bool recv_flow_stats_reply(struct vconn *, ovs_be32 send_xid,
                                  struct ofpbuf **replyp,
                                  struct ofputil_flow_stats *,
                                  struct ofpbuf *ofpacts);
int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);
    parse_options(argc, argv);
    signal(SIGPIPE, SIG_IGN);
    run_command(argc - optind, argv + optind, all_commands);
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
        DAEMON_OPTION_ENUMS,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"timeout", required_argument, NULL, 't'},
        {"strict", no_argument, NULL, OPT_STRICT},
        {"readd", no_argument, NULL, OPT_READD},
        {"flow-format", required_argument, NULL, 'F'},
        {"packet-in-format", required_argument, NULL, 'P'},
        {"more", no_argument, NULL, 'm'},
        {"timestamp", no_argument, NULL, OPT_TIMESTAMP},
        {"sort", optional_argument, NULL, OPT_SORT},
        {"rsort", optional_argument, NULL, OPT_RSORT},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

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

        case 'V':
            ovs_print_version(OFP10_VERSION, OFP10_VERSION);
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

        DAEMON_OPTION_HANDLERS
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
           "  mod-port SWITCH IFACE ACT   modify port behavior\n"
           "  get-frags SWITCH            print fragment handling behavior\n"
           "  set-frags SWITCH FRAG_MODE  set fragment handling behavior\n"
           "  dump-ports SWITCH [PORT]    print port statistics\n"
           "  dump-ports-desc SWITCH      print port descriptions\n"
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
           "\nFor OpenFlow switches and controllers:\n"
           "  probe TARGET                probe whether TARGET is up\n"
           "  ping TARGET [N]             latency of N-byte echos\n"
           "  benchmark TARGET N COUNT    bandwidth of COUNT N-byte echos\n"
           "where SWITCH or TARGET is an active OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, false, false);
    daemon_usage();
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
    PRINTF_FORMAT(2, 3);

static void run(int retval, const char *message, ...)
{
    if (retval) {
        va_list args;

        va_start(args, message);
        ovs_fatal_valist(retval, message, args);
    }
}

/* Generic commands. */

static void
open_vconn_socket(const char *name, struct vconn **vconnp)
{
    char *vconn_name = xasprintf("unix:%s", name);
    VLOG_DBG("connecting to %s", vconn_name);
    run(vconn_open_block(vconn_name, OFP10_VERSION, vconnp),
        "connecting to %s", vconn_name);
    free(vconn_name);
}

static enum ofputil_protocol
open_vconn__(const char *name, const char *default_suffix,
             struct vconn **vconnp)
{
    char *datapath_name, *datapath_type, *socket_name;
    enum ofputil_protocol protocol;
    char *bridge_path;
    int ofp_version;
    struct stat s;

    bridge_path = xasprintf("%s/%s.%s", ovs_rundir(), name, default_suffix);

    ofproto_parse_name(name, &datapath_name, &datapath_type);
    socket_name = xasprintf("%s/%s.%s",
                            ovs_rundir(), datapath_name, default_suffix);
    free(datapath_name);
    free(datapath_type);

    if (strchr(name, ':')) {
        run(vconn_open_block(name, OFP10_VERSION, vconnp),
            "connecting to %s", name);
    } else if (!stat(name, &s) && S_ISSOCK(s.st_mode)) {
        open_vconn_socket(name, vconnp);
    } else if (!stat(bridge_path, &s) && S_ISSOCK(s.st_mode)) {
        open_vconn_socket(bridge_path, vconnp);
    } else if (!stat(socket_name, &s)) {
        if (!S_ISSOCK(s.st_mode)) {
            ovs_fatal(0, "cannot connect to %s: %s is not a socket",
                      name, socket_name);
        }
        open_vconn_socket(socket_name, vconnp);
    } else {
        ovs_fatal(0, "%s is not a bridge or a socket", name);
    }

    free(bridge_path);
    free(socket_name);

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
    return open_vconn__(name, "mgmt", vconnp);
}

static void
send_openflow_buffer(struct vconn *vconn, struct ofpbuf *buffer)
{
    ofpmsg_update_length(buffer);
    run(vconn_send_block(vconn, buffer), "failed to send packet to switch");
}

static void
dump_transaction(const char *vconn_name, struct ofpbuf *request)
{
    struct vconn *vconn;
    struct ofpbuf *reply;

    ofpmsg_update_length(request);
    open_vconn(vconn_name, &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);
    ofp_print(stdout, reply->data, reply->size, verbosity + 1);
    ofpbuf_delete(reply);
    vconn_close(vconn);
}

static void
dump_trivial_transaction(const char *vconn_name, enum ofpraw raw)
{
    struct ofpbuf *request;
    request = ofpraw_alloc(raw, OFP10_VERSION, 0);
    dump_transaction(vconn_name, request);
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

/* Sends 'request', which should be a request that only has a reply if an error
 * occurs, and waits for it to succeed or fail.  If an error does occur, prints
 * it and exits with an error.
 *
 * Destroys all of the 'requests'. */
static void
transact_multiple_noreply(struct vconn *vconn, struct list *requests)
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
    struct list requests;

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

    request = ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST, OFP10_VERSION, 0);
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

    request = ofpraw_alloc(OFPRAW_OFPT_SET_CONFIG, OFP10_VERSION, 0);
    ofpbuf_put(request, config, sizeof *config);

    transact_noreply(vconn, request);
}

static void
ofctl_show(int argc OVS_UNUSED, char *argv[])
{
    const char *vconn_name = argv[1];
    struct vconn *vconn;
    struct ofpbuf *request;
    struct ofpbuf *reply;
    bool trunc;

    request = ofpraw_alloc(OFPRAW_OFPT_FEATURES_REQUEST, OFP10_VERSION, 0);
    open_vconn(vconn_name, &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);

    trunc = ofputil_switch_features_ports_trunc(reply);
    ofp_print(stdout, reply->data, reply->size, verbosity + 1);

    ofpbuf_delete(reply);
    vconn_close(vconn);

    if (trunc) {
        /* The Features Reply may not contain all the ports, so send a
         * Port Description stats request, which doesn't have size
         * constraints. */
        dump_trivial_stats_transaction(vconn_name,
                                       OFPRAW_OFPST_PORT_DESC_REQUEST);
    }
    dump_trivial_transaction(vconn_name, OFPRAW_OFPT_GET_CONFIG_REQUEST);
}

static void
ofctl_dump_desc(int argc OVS_UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPRAW_OFPST_DESC_REQUEST);
}

static void
ofctl_dump_tables(int argc OVS_UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPRAW_OFPST_TABLE_REQUEST);
}

static bool
fetch_port_by_features(const char *vconn_name,
                       const char *port_name, unsigned int port_no,
                       struct ofputil_phy_port *pp, bool *trunc)
{
    struct ofputil_switch_features features;
    const struct ofp_header *oh;
    struct ofpbuf *request, *reply;
    struct vconn *vconn;
    enum ofperr error;
    enum ofptype type;
    struct ofpbuf b;
    bool found = false;

    /* Fetch the switch's ofp_switch_features. */
    request = ofpraw_alloc(OFPRAW_OFPT_FEATURES_REQUEST, OFP10_VERSION, 0);
    open_vconn(vconn_name, &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);
    vconn_close(vconn);

    oh = reply->data;
    if (ofptype_decode(&type, reply->data)
        || type != OFPTYPE_FEATURES_REPLY) {
        ovs_fatal(0, "%s: received bad features reply", vconn_name);
    }

    *trunc = false;
    if (ofputil_switch_features_ports_trunc(reply)) {
        *trunc = true;
        goto exit;
    }

    error = ofputil_decode_switch_features(oh, &features, &b);
    if (error) {
        ovs_fatal(0, "%s: failed to decode features reply (%s)",
                  vconn_name, ofperr_to_string(error));
    }

    while (!ofputil_pull_phy_port(oh->version, &b, pp)) {
        if (port_no != UINT_MAX
            ? port_no == pp->port_no
            : !strcmp(pp->name, port_name)) {
            found = true;
            goto exit;
        }
    }

exit:
    ofpbuf_delete(reply);
    return found;
}

static bool
fetch_port_by_stats(const char *vconn_name,
                    const char *port_name, unsigned int port_no,
                    struct ofputil_phy_port *pp)
{
    struct ofpbuf *request;
    struct vconn *vconn;
    ovs_be32 send_xid;
    bool done = false;
    bool found = false;

    request = ofpraw_alloc(OFPRAW_OFPST_PORT_DESC_REQUEST, OFP10_VERSION, 0);
    send_xid = ((struct ofp_header *) request->data)->xid;

    open_vconn(vconn_name, &vconn);
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
                if (port_no != UINT_MAX ? port_no == pp->port_no
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
    vconn_close(vconn);

    return found;
}


/* Opens a connection to 'vconn_name', fetches the port structure for
 * 'port_name' (which may be a port name or number), and copies it into
 * '*pp'. */
static void
fetch_ofputil_phy_port(const char *vconn_name, const char *port_name,
                       struct ofputil_phy_port *pp)
{
    unsigned int port_no;
    bool found;
    bool trunc;

    /* Try to interpret the argument as a port number. */
    if (!str_to_uint(port_name, 10, &port_no)) {
        port_no = UINT_MAX;
    }

    /* Try to find the port based on the Features Reply.  If it looks
     * like the results may be truncated, then use the Port Description
     * stats message introduced in OVS 1.7. */
    found = fetch_port_by_features(vconn_name, port_name, port_no, pp,
                                   &trunc);
    if (trunc) {
        found = fetch_port_by_stats(vconn_name, port_name, port_no, pp);
    }

    if (!found) {
        ovs_fatal(0, "%s: couldn't find port `%s'", vconn_name, port_name);
    }
}

/* Returns the port number corresponding to 'port_name' (which may be a port
 * name or number) within the switch 'vconn_name'. */
static uint16_t
str_to_port_no(const char *vconn_name, const char *port_name)
{
    uint16_t port_no;

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
            return true;
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

    parse_ofp_flow_stats_request_str(&fsr, aggregate, argc > 2 ? argv[2] : "");
    usable_protocols = ofputil_flow_stats_request_usable_protocols(&fsr);

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
            unsigned int a_pri = afs->priority;
            unsigned int b_pri = bfs->priority;
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
ofctl_dump_flows(int argc, char *argv[])
{
    if (!n_criteria) {
        return ofctl_dump_flows__(argc, argv, false);
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

        vconn = prepare_dump_flows(argc, argv, false, &request);
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
            free(fses[i].ofpacts);
        }
        free(fses);

        vconn_close(vconn);
    }
}

static void
ofctl_dump_aggregate(int argc, char *argv[])
{
    return ofctl_dump_flows__(argc, argv, true);
}

static void
ofctl_queue_stats(int argc, char *argv[])
{
    struct ofpbuf *request;
    struct vconn *vconn;
    struct ofputil_queue_stats_request oqs;

    open_vconn(argv[1], &vconn);

    if (argc > 2 && argv[2][0] && strcasecmp(argv[2], "all")) {
        oqs.port_no = str_to_port_no(argv[1], argv[2]);
    } else {
        oqs.port_no = OFPP_ALL;
    }
    if (argc > 3 && argv[3][0] && strcasecmp(argv[3], "all")) {
        oqs.queue_id = atoi(argv[3]);
    } else {
        oqs.queue_id = OFPQ_ALL;
    }

    request = ofputil_encode_queue_stats_request(vconn_get_version(vconn), &oqs);
    dump_stats_transaction(vconn, request);
    vconn_close(vconn);
}

static enum ofputil_protocol
open_vconn_for_flow_mod(const char *remote,
                        const struct ofputil_flow_mod *fms, size_t n_fms,
                        struct vconn **vconnp)
{
    enum ofputil_protocol usable_protocols;
    enum ofputil_protocol cur_protocol;
    char *usable_s;
    int i;

    /* Figure out what flow formats will work. */
    usable_protocols = ofputil_flow_mod_usable_protocols(fms, n_fms);
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
                 size_t n_fms)
{
    enum ofputil_protocol protocol;
    struct vconn *vconn;
    size_t i;

    protocol = open_vconn_for_flow_mod(remote, fms, n_fms, &vconn);

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];

        transact_noreply(vconn, ofputil_encode_flow_mod(fm, protocol));
        free(fm->ofpacts);
    }
    vconn_close(vconn);
}

static void
ofctl_flow_mod_file(int argc OVS_UNUSED, char *argv[], uint16_t command)
{
    struct ofputil_flow_mod *fms = NULL;
    size_t n_fms = 0;

    parse_ofp_flow_mod_file(argv[2], command, &fms, &n_fms);
    ofctl_flow_mod__(argv[1], fms, n_fms);
    free(fms);
}

static void
ofctl_flow_mod(int argc, char *argv[], uint16_t command)
{
    if (argc > 2 && !strcmp(argv[2], "-")) {
        ofctl_flow_mod_file(argc, argv, command);
    } else {
        struct ofputil_flow_mod fm;
        parse_ofp_flow_mod_str(&fm, argc > 2 ? argv[2] : "", command, false);
        ofctl_flow_mod__(argv[1], &fm, 1);
    }
}

static void
ofctl_add_flow(int argc, char *argv[])
{
    ofctl_flow_mod(argc, argv, OFPFC_ADD);
}

static void
ofctl_add_flows(int argc, char *argv[])
{
    ofctl_flow_mod_file(argc, argv, OFPFC_ADD);
}

static void
ofctl_mod_flows(int argc, char *argv[])
{
    ofctl_flow_mod(argc, argv, strict ? OFPFC_MODIFY_STRICT : OFPFC_MODIFY);
}

static void
ofctl_del_flows(int argc, char *argv[])
{
    ofctl_flow_mod(argc, argv, strict ? OFPFC_DELETE_STRICT : OFPFC_DELETE);
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
            ds_put_format(&reply, "%s\n", strerror(error));
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
        unixctl_command_reply_error(conn, strerror(error));
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
        unixctl_command_reply_error(conn, strerror(errno));
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

static void
monitor_vconn(struct vconn *vconn)
{
    struct barrier_aux barrier_aux = { vconn, NULL };
    struct unixctl_server *server;
    bool exiting = false;
    bool blocked = false;
    int error;

    daemon_save_fd(STDERR_FILENO);
    daemonize_start();
    error = unixctl_server_create(NULL, &server);
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
                time_t now = time_wall();
                char s[32];

                strftime(s, sizeof s, "%Y-%m-%d %H:%M:%S: ", gmtime(&now));
                fputs(s, stderr);
            }

            ofptype_decode(&type, b->data);
            ofp_print(stderr, b->data, b->size, verbosity + 2);
            ofpbuf_delete(b);

            if (barrier_aux.conn && type == OFPTYPE_BARRIER_REPLY) {
                unixctl_command_reply(barrier_aux.conn, NULL);
                barrier_aux.conn = NULL;
            }
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
ofctl_monitor(int argc, char *argv[])
{
    struct vconn *vconn;
    int i;

    open_vconn(argv[1], &vconn);
    for (i = 2; i < argc; i++) {
        const char *arg = argv[i];

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

            parse_flow_monitor_request(&fmr, arg + 6);

            msg = ofpbuf_new(0);
            ofputil_append_flow_monitor_request(&fmr, msg);
            dump_stats_transaction(vconn, msg);
        } else {
            ovs_fatal(0, "%s: unsupported \"monitor\" argument", arg);
        }
    }

    if (preferred_packet_in_format >= 0) {
        set_packet_in_format(vconn, preferred_packet_in_format);
    } else {
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
    }

    monitor_vconn(vconn);
}

static void
ofctl_snoop(int argc OVS_UNUSED, char *argv[])
{
    struct vconn *vconn;

    open_vconn__(argv[1], "snoop", &vconn);
    monitor_vconn(vconn);
}

static void
ofctl_dump_ports(int argc, char *argv[])
{
    struct ofpbuf *request;
    struct vconn *vconn;
    uint16_t port;

    open_vconn(argv[1], &vconn);
    port = argc > 2 ? str_to_port_no(argv[1], argv[2]) : OFPP_NONE;
    request = ofputil_encode_dump_ports_request(vconn_get_version(vconn), port);
    dump_stats_transaction(vconn, request);
    vconn_close(vconn);
}

static void
ofctl_dump_ports_desc(int argc OVS_UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPRAW_OFPST_PORT_DESC_REQUEST);
}

static void
ofctl_probe(int argc OVS_UNUSED, char *argv[])
{
    struct ofpbuf *request;
    struct vconn *vconn;
    struct ofpbuf *reply;

    open_vconn(argv[1], &vconn);
    request = make_echo_request(vconn_get_version(vconn));
    run(vconn_transact(vconn, request, &reply), "talking to %s", argv[1]);
    if (reply->size != sizeof(struct ofp_header)) {
        ovs_fatal(0, "reply does not match request");
    }
    ofpbuf_delete(reply);
    vconn_close(vconn);
}

static void
ofctl_packet_out(int argc, char *argv[])
{
    enum ofputil_protocol protocol;
    struct ofputil_packet_out po;
    struct ofpbuf ofpacts;
    struct vconn *vconn;
    int i;

    ofpbuf_init(&ofpacts, 64);
    parse_ofpacts(argv[3], &ofpacts);

    po.buffer_id = UINT32_MAX;
    po.in_port = str_to_port_no(argv[1], argv[2]);
    po.ofpacts = ofpacts.data;
    po.ofpacts_len = ofpacts.size;

    protocol = open_vconn(argv[1], &vconn);
    for (i = 4; i < argc; i++) {
        struct ofpbuf *packet, *opo;
        const char *error_msg;

        error_msg = eth_from_hex(argv[i], &packet);
        if (error_msg) {
            ovs_fatal(0, "%s", error_msg);
        }

        po.packet = packet->data;
        po.packet_len = packet->size;
        opo = ofputil_encode_packet_out(&po, protocol);
        transact_noreply(vconn, opo);
        ofpbuf_delete(packet);
    }
    vconn_close(vconn);
    ofpbuf_uninit(&ofpacts);
}

static void
ofctl_mod_port(int argc OVS_UNUSED, char *argv[])
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

    fetch_ofputil_phy_port(argv[1], argv[2], &pp);

    pm.port_no = pp.port_no;
    memcpy(pm.hw_addr, pp.hw_addr, ETH_ADDR_LEN);
    pm.config = 0;
    pm.mask = 0;
    pm.advertise = 0;

    if (!strncasecmp(argv[3], "no-", 3)) {
        command = argv[3] + 3;
        not = true;
    } else if (!strncasecmp(argv[3], "no", 2)) {
        command = argv[3] + 2;
        not = true;
    } else {
        command = argv[3];
        not = false;
    }
    for (flag = flags; flag < &flags[ARRAY_SIZE(flags)]; flag++) {
        if (!strcasecmp(command, flag->name)) {
            pm.mask = flag->bit;
            pm.config = flag->on ^ not ? flag->bit : 0;
            goto found;
        }
    }
    ovs_fatal(0, "unknown mod-port command '%s'", argv[3]);

found:
    protocol = open_vconn(argv[1], &vconn);
    transact_noreply(vconn, ofputil_encode_port_mod(&pm, protocol));
    vconn_close(vconn);
}

static void
ofctl_get_frags(int argc OVS_UNUSED, char *argv[])
{
    struct ofp_switch_config config;
    struct vconn *vconn;

    open_vconn(argv[1], &vconn);
    fetch_switch_config(vconn, &config);
    puts(ofputil_frag_handling_to_string(ntohs(config.flags)));
    vconn_close(vconn);
}

static void
ofctl_set_frags(int argc OVS_UNUSED, char *argv[])
{
    struct ofp_switch_config config;
    enum ofp_config_flags mode;
    struct vconn *vconn;
    ovs_be16 flags;

    if (!ofputil_frag_handling_from_string(argv[2], &mode)) {
        ovs_fatal(0, "%s: unknown fragment handling mode", argv[2]);
    }

    open_vconn(argv[1], &vconn);
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
                      argv[1], ofputil_frag_handling_to_string(mode));
        }
    }
    vconn_close(vconn);
}

static void
ofctl_ping(int argc, char *argv[])
{
    size_t max_payload = 65535 - sizeof(struct ofp_header);
    unsigned int payload;
    struct vconn *vconn;
    int i;

    payload = argc > 2 ? atoi(argv[2]) : 64;
    if (payload > max_payload) {
        ovs_fatal(0, "payload must be between 0 and %zu bytes", max_payload);
    }

    open_vconn(argv[1], &vconn);
    for (i = 0; i < 10; i++) {
        struct timeval start, end;
        struct ofpbuf *request, *reply;
        const struct ofp_header *rpy_hdr;
        enum ofptype type;

        request = ofpraw_alloc(OFPRAW_OFPT_ECHO_REQUEST, OFP10_VERSION,
                               payload);
        random_bytes(ofpbuf_put_uninit(request, payload), payload);

        xgettimeofday(&start);
        run(vconn_transact(vconn, ofpbuf_clone(request), &reply), "transact");
        xgettimeofday(&end);

        rpy_hdr = reply->data;
        if (ofptype_pull(&type, reply)
            || type != OFPTYPE_ECHO_REPLY
            || reply->size != payload
            || memcmp(request->l3, reply->l3, payload)) {
            printf("Reply does not match request.  Request:\n");
            ofp_print(stdout, request, request->size, verbosity + 2);
            printf("Reply:\n");
            ofp_print(stdout, reply, reply->size, verbosity + 2);
        }
        printf("%zu bytes from %s: xid=%08"PRIx32" time=%.1f ms\n",
               reply->size, argv[1], ntohl(rpy_hdr->xid),
                   (1000*(double)(end.tv_sec - start.tv_sec))
                   + (.001*(end.tv_usec - start.tv_usec)));
        ofpbuf_delete(request);
        ofpbuf_delete(reply);
    }
    vconn_close(vconn);
}

static void
ofctl_benchmark(int argc OVS_UNUSED, char *argv[])
{
    size_t max_payload = 65535 - sizeof(struct ofp_header);
    struct timeval start, end;
    unsigned int payload_size, message_size;
    struct vconn *vconn;
    double duration;
    int count;
    int i;

    payload_size = atoi(argv[2]);
    if (payload_size > max_payload) {
        ovs_fatal(0, "payload must be between 0 and %zu bytes", max_payload);
    }
    message_size = sizeof(struct ofp_header) + payload_size;

    count = atoi(argv[3]);

    printf("Sending %d packets * %u bytes (with header) = %u bytes total\n",
           count, message_size, count * message_size);

    open_vconn(argv[1], &vconn);
    xgettimeofday(&start);
    for (i = 0; i < count; i++) {
        struct ofpbuf *request, *reply;

        request = ofpraw_alloc(OFPRAW_OFPT_ECHO_REQUEST, OFP10_VERSION,
                               payload_size);
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
ofctl_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    usage();
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
    uint16_t flags;
    struct ofpact *ofpacts;
    size_t ofpacts_len;
};

/* Frees 'version' and the data that it owns. */
static void
fte_version_free(struct fte_version *version)
{
    if (version) {
        free(version->ofpacts);
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

    ds_put_char(s, ' ');
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
    struct cls_cursor cursor;
    struct fte *fte, *next;

    cls_cursor_init(&cursor, cls, NULL);
    CLS_CURSOR_FOR_EACH_SAFE (fte, next, rule, &cursor) {
        classifier_remove(cls, &fte->rule);
        fte_free(fte);
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
           unsigned int priority, struct fte_version *version, int index)
{
    struct fte *old, *fte;

    fte = xzalloc(sizeof *fte);
    cls_rule_init(&fte->rule, match, priority);
    fte->versions[index] = version;

    old = fte_from_cls_rule(classifier_replace(cls, &fte->rule));
    if (old) {
        fte_version_free(old->versions[index]);
        fte->versions[!index] = old->versions[!index];
        cls_rule_destroy(&old->rule);
        free(old);
    }
}

/* Reads the flows in 'filename' as flow table entries in 'cls' for the version
 * with the specified 'index'.  Returns the flow formats able to represent the
 * flows that were read. */
static enum ofputil_protocol
read_flows_from_file(const char *filename, struct classifier *cls, int index)
{
    enum ofputil_protocol usable_protocols;
    struct ds s;
    FILE *file;

    file = !strcmp(filename, "-") ? stdin : fopen(filename, "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", filename);
    }

    ds_init(&s);
    usable_protocols = OFPUTIL_P_ANY;
    while (!ds_get_preprocessed_line(&s, file)) {
        struct fte_version *version;
        struct ofputil_flow_mod fm;

        parse_ofp_str(&fm, OFPFC_ADD, ds_cstr(&s), true);

        version = xmalloc(sizeof *version);
        version->cookie = fm.new_cookie;
        version->idle_timeout = fm.idle_timeout;
        version->hard_timeout = fm.hard_timeout;
        version->flags = fm.flags & (OFPFF_SEND_FLOW_REM | OFPFF10_EMERG);
        version->ofpacts = fm.ofpacts;
        version->ofpacts_len = fm.ofpacts_len;

        usable_protocols &= ofputil_usable_protocols(&fm.match);

        fte_insert(cls, &fm.match, fm.priority, version, index);
    }
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
            more = ofpmp_more(reply->l2);
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
    fsr.out_port = OFPP_NONE;
    fsr.table_id = 0xff;
    fsr.cookie = fsr.cookie_mask = htonll(0);
    request = ofputil_encode_flow_stats_request(&fsr, protocol);
    send_xid = ((struct ofp_header *) request->data)->xid;
    send_openflow_buffer(vconn, request);

    reply = NULL;
    ofpbuf_init(&ofpacts, 0);
    while (recv_flow_stats_reply(vconn, send_xid, &reply, &fs, &ofpacts)) {
        struct fte_version *version;

        version = xmalloc(sizeof *version);
        version->cookie = fs.cookie;
        version->idle_timeout = fs.idle_timeout;
        version->hard_timeout = fs.hard_timeout;
        version->flags = 0;
        version->ofpacts_len = fs.ofpacts_len;
        version->ofpacts = xmemdup(fs.ofpacts, fs.ofpacts_len);

        fte_insert(cls, &fs.match, fs.priority, version, index);
    }
    ofpbuf_uninit(&ofpacts);
}

static void
fte_make_flow_mod(const struct fte *fte, int index, uint16_t command,
                  enum ofputil_protocol protocol, struct list *packets)
{
    const struct fte_version *version = fte->versions[index];
    struct ofputil_flow_mod fm;
    struct ofpbuf *ofm;

    minimatch_expand(&fte->rule.match, &fm.match);
    fm.priority = fte->rule.priority;
    fm.cookie = htonll(0);
    fm.cookie_mask = htonll(0);
    fm.new_cookie = version->cookie;
    fm.table_id = 0xff;
    fm.command = command;
    fm.idle_timeout = version->idle_timeout;
    fm.hard_timeout = version->hard_timeout;
    fm.buffer_id = UINT32_MAX;
    fm.out_port = OFPP_NONE;
    fm.flags = version->flags;
    if (command == OFPFC_ADD || command == OFPFC_MODIFY ||
        command == OFPFC_MODIFY_STRICT) {
        fm.ofpacts = version->ofpacts;
        fm.ofpacts_len = version->ofpacts_len;
    } else {
        fm.ofpacts = NULL;
        fm.ofpacts_len = 0;
    }

    ofm = ofputil_encode_flow_mod(&fm, protocol);
    list_push_back(packets, &ofm->list_node);
}

static void
ofctl_replace_flows(int argc OVS_UNUSED, char *argv[])
{
    enum { FILE_IDX = 0, SWITCH_IDX = 1 };
    enum ofputil_protocol usable_protocols, protocol;
    struct cls_cursor cursor;
    struct classifier cls;
    struct list requests;
    struct vconn *vconn;
    struct fte *fte;

    classifier_init(&cls);
    usable_protocols = read_flows_from_file(argv[2], &cls, FILE_IDX);

    protocol = open_vconn(argv[1], &vconn);
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);

    read_flows_from_switch(vconn, protocol, &cls, SWITCH_IDX);

    list_init(&requests);

    /* Delete flows that exist on the switch but not in the file. */
    cls_cursor_init(&cursor, &cls, NULL);
    CLS_CURSOR_FOR_EACH (fte, rule, &cursor) {
        struct fte_version *file_ver = fte->versions[FILE_IDX];
        struct fte_version *sw_ver = fte->versions[SWITCH_IDX];

        if (sw_ver && !file_ver) {
            fte_make_flow_mod(fte, SWITCH_IDX, OFPFC_DELETE_STRICT,
                              protocol, &requests);
        }
    }

    /* Add flows that exist in the file but not on the switch.
     * Update flows that exist in both places but differ. */
    cls_cursor_init(&cursor, &cls, NULL);
    CLS_CURSOR_FOR_EACH (fte, rule, &cursor) {
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
ofctl_diff_flows(int argc OVS_UNUSED, char *argv[])
{
    bool differences = false;
    struct cls_cursor cursor;
    struct classifier cls;
    struct ds a_s, b_s;
    struct fte *fte;

    classifier_init(&cls);
    read_flows_from_source(argv[1], &cls, 0);
    read_flows_from_source(argv[2], &cls, 1);

    ds_init(&a_s);
    ds_init(&b_s);

    cls_cursor_init(&cursor, &cls, NULL);
    CLS_CURSOR_FOR_EACH (fte, rule, &cursor) {
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

/* Undocumented commands for unit testing. */

static void
ofctl_parse_flows__(struct ofputil_flow_mod *fms, size_t n_fms)
{
    enum ofputil_protocol usable_protocols;
    enum ofputil_protocol protocol = 0;
    char *usable_s;
    size_t i;

    usable_protocols = ofputil_flow_mod_usable_protocols(fms, n_fms);
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
    assert(IS_POW2(protocol));

    printf("chosen protocol: %s\n", ofputil_protocol_to_string(protocol));

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];
        struct ofpbuf *msg;

        msg = ofputil_encode_flow_mod(fm, protocol);
        ofp_print(stdout, msg->data, msg->size, verbosity);
        ofpbuf_delete(msg);

        free(fm->ofpacts);
    }
}

/* "parse-flow FLOW": parses the argument as a flow (like add-flow) and prints
 * it back to stdout.  */
static void
ofctl_parse_flow(int argc OVS_UNUSED, char *argv[])
{
    struct ofputil_flow_mod fm;

    parse_ofp_flow_mod_str(&fm, argv[1], OFPFC_ADD, false);
    ofctl_parse_flows__(&fm, 1);
}

/* "parse-flows FILENAME": reads the named file as a sequence of flows (like
 * add-flows) and prints each of the flows back to stdout.  */
static void
ofctl_parse_flows(int argc OVS_UNUSED, char *argv[])
{
    struct ofputil_flow_mod *fms = NULL;
    size_t n_fms = 0;

    parse_ofp_flow_mod_file(argv[1], OFPFC_ADD, &fms, &n_fms);
    ofctl_parse_flows__(fms, n_fms);
    free(fms);
}

static void
ofctl_parse_nxm__(bool oxm)
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
                match_len = oxm_put_match(&nx_match, &match);
                out = oxm_match_to_string(nx_match.data, match_len);
            } else {
                match_len = nx_put_match(&nx_match, &match,
                                         cookie, cookie_mask);
                out = nx_match_to_string(nx_match.data, match_len);
            }

            puts(out);
            free(out);
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
ofctl_parse_nxm(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    return ofctl_parse_nxm__(false);
}

/* "parse-oxm": reads a series of OXM nx_match specifications as strings from
 * stdin, does some internal fussing with them, and then prints them back as
 * strings on stdout. */
static void
ofctl_parse_oxm(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    return ofctl_parse_nxm__(true);
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
            printf("%s%2zu: %02"PRIx8" -> %02"PRIx8"\n",
                   prefix, i, a[i], b[i]);
        }
    }
    for (i = a_len; i < b_len; i++) {
        printf("%s%2zu: (none) -> %02"PRIx8"\n", prefix, i, b[i]);
    }
    for (i = b_len; i < a_len; i++) {
        printf("%s%2zu: %02"PRIx8" -> (none)\n", prefix, i, a[i]);
    }
}

/* "parse-ofp10-actions": reads a series of OpenFlow 1.0 action specifications
 * as hex bytes from stdin, converts them to ofpacts, prints them as strings
 * on stdout, and then converts them back to hex bytes and prints any
 * differences from the input. */
static void
ofctl_parse_ofp10_actions(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds in;

    ds_init(&in);
    while (!ds_get_preprocessed_line(&in, stdin)) {
        struct ofpbuf of10_out;
        struct ofpbuf of10_in;
        struct ofpbuf ofpacts;
        enum ofperr error;
        size_t size;
        struct ds s;

        /* Parse hex bytes. */
        ofpbuf_init(&of10_in, 0);
        if (ofpbuf_put_hex(&of10_in, ds_cstr(&in), NULL)[0] != '\0') {
            ovs_fatal(0, "Trailing garbage in hex data");
        }

        /* Convert to ofpacts. */
        ofpbuf_init(&ofpacts, 0);
        size = of10_in.size;
        error = ofpacts_pull_openflow10(&of10_in, of10_in.size, &ofpacts);
        if (error) {
            printf("bad OF1.1 actions: %s\n\n", ofperr_get_name(error));
            ofpbuf_uninit(&ofpacts);
            ofpbuf_uninit(&of10_in);
            continue;
        }
        ofpbuf_push_uninit(&of10_in, size);

        /* Print cls_rule. */
        ds_init(&s);
        ofpacts_format(ofpacts.data, ofpacts.size, &s);
        puts(ds_cstr(&s));
        ds_destroy(&s);

        /* Convert back to ofp10 actions and print differences from input. */
        ofpbuf_init(&of10_out, 0);
        ofpacts_put_openflow10(ofpacts.data, ofpacts.size, &of10_out);

        print_differences("", of10_in.data, of10_in.size,
                          of10_out.data, of10_out.size);
        putchar('\n');

        ofpbuf_uninit(&ofpacts);
        ofpbuf_uninit(&of10_in);
        ofpbuf_uninit(&of10_out);
    }
    ds_destroy(&in);
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
ofctl_parse_ofp10_match(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds expout;
    struct ds in;

    ds_init(&in);
    ds_init(&expout);
    while (!ds_get_preprocessed_line(&in, stdin)) {
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
            ovs_fatal(0, "Input is %zu bytes, expected %zu",
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
            ovs_fatal(0, "Input is %zu bytes, expected %zu",
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
ofctl_parse_ofp11_match(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds in;

    ds_init(&in);
    while (!ds_get_preprocessed_line(&in, stdin)) {
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
            ovs_fatal(0, "Input is %zu bytes, expected %zu",
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

/* "parse-ofp11-actions": reads a series of OpenFlow 1.1 action specifications
 * as hex bytes from stdin, converts them to ofpacts, prints them as strings
 * on stdout, and then converts them back to hex bytes and prints any
 * differences from the input. */
static void
ofctl_parse_ofp11_actions(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds in;

    ds_init(&in);
    while (!ds_get_preprocessed_line(&in, stdin)) {
        struct ofpbuf of11_out;
        struct ofpbuf of11_in;
        struct ofpbuf ofpacts;
        enum ofperr error;
        size_t size;
        struct ds s;

        /* Parse hex bytes. */
        ofpbuf_init(&of11_in, 0);
        if (ofpbuf_put_hex(&of11_in, ds_cstr(&in), NULL)[0] != '\0') {
            ovs_fatal(0, "Trailing garbage in hex data");
        }

        /* Convert to ofpacts. */
        ofpbuf_init(&ofpacts, 0);
        size = of11_in.size;
        error = ofpacts_pull_openflow11_actions(&of11_in, of11_in.size,
                                                &ofpacts);
        if (error) {
            printf("bad OF1.1 actions: %s\n\n", ofperr_get_name(error));
            ofpbuf_uninit(&ofpacts);
            ofpbuf_uninit(&of11_in);
            continue;
        }
        ofpbuf_push_uninit(&of11_in, size);

        /* Print cls_rule. */
        ds_init(&s);
        ofpacts_format(ofpacts.data, ofpacts.size, &s);
        puts(ds_cstr(&s));
        ds_destroy(&s);

        /* Convert back to ofp11 actions and print differences from input. */
        ofpbuf_init(&of11_out, 0);
        ofpacts_put_openflow11_actions(ofpacts.data, ofpacts.size, &of11_out);

        print_differences("", of11_in.data, of11_in.size,
                          of11_out.data, of11_out.size);
        putchar('\n');

        ofpbuf_uninit(&ofpacts);
        ofpbuf_uninit(&of11_in);
        ofpbuf_uninit(&of11_out);
    }
    ds_destroy(&in);
}

/* "parse-ofp11-instructions": reads a series of OpenFlow 1.1 instruction
 * specifications as hex bytes from stdin, converts them to ofpacts, prints
 * them as strings on stdout, and then converts them back to hex bytes and
 * prints any differences from the input. */
static void
ofctl_parse_ofp11_instructions(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds in;

    ds_init(&in);
    while (!ds_get_preprocessed_line(&in, stdin)) {
        struct ofpbuf of11_out;
        struct ofpbuf of11_in;
        struct ofpbuf ofpacts;
        enum ofperr error;
        size_t size;
        struct ds s;

        /* Parse hex bytes. */
        ofpbuf_init(&of11_in, 0);
        if (ofpbuf_put_hex(&of11_in, ds_cstr(&in), NULL)[0] != '\0') {
            ovs_fatal(0, "Trailing garbage in hex data");
        }

        /* Convert to ofpacts. */
        ofpbuf_init(&ofpacts, 0);
        size = of11_in.size;
        error = ofpacts_pull_openflow11_instructions(&of11_in, of11_in.size,
                                                     &ofpacts);
        if (error) {
            printf("bad OF1.1 instructions: %s\n\n", ofperr_get_name(error));
            ofpbuf_uninit(&ofpacts);
            ofpbuf_uninit(&of11_in);
            continue;
        }
        ofpbuf_push_uninit(&of11_in, size);

        /* Print cls_rule. */
        ds_init(&s);
        ofpacts_format(ofpacts.data, ofpacts.size, &s);
        puts(ds_cstr(&s));
        ds_destroy(&s);

        /* Convert back to ofp11 instructions and print differences from
         * input. */
        ofpbuf_init(&of11_out, 0);
        ofpacts_put_openflow11_instructions(ofpacts.data, ofpacts.size,
                                            &of11_out);

        print_differences("", of11_in.data, of11_in.size,
                          of11_out.data, of11_out.size);
        putchar('\n');

        ofpbuf_uninit(&ofpacts);
        ofpbuf_uninit(&of11_in);
        ofpbuf_uninit(&of11_out);
    }
    ds_destroy(&in);
}

/* "check-vlan VLAN_TCI VLAN_TCI_MASK": converts the specified vlan_tci and
 * mask values to and from various formats and prints the results. */
static void
ofctl_check_vlan(int argc OVS_UNUSED, char *argv[])
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

    match_init_catchall(&match);
    match.flow.vlan_tci = htons(strtoul(argv[1], NULL, 16));
    match.wc.masks.vlan_tci = htons(strtoul(argv[2], NULL, 16));

    /* Convert to and from string. */
    string_s = match_to_string(&match, OFP_DEFAULT_PRIORITY);
    printf("%s -> ", string_s);
    fflush(stdout);
    parse_ofp_str(&fm, -1, string_s, false);
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
    nxm_match_len = oxm_put_match(&nxm, &match);
    nxm_s = oxm_match_to_string(nxm.data, nxm_match_len);
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
ofctl_print_error(int argc OVS_UNUSED, char *argv[])
{
    enum ofperr error;
    int version;

    error = ofperr_from_name(argv[1]);
    if (!error) {
        ovs_fatal(0, "unknown error \"%s\"", argv[1]);
    }

    for (version = 0; version <= UINT8_MAX; version++) {
        const char *name = ofperr_domain_get_name(version);
        if (!name) {
            continue;
        }
        printf("%s: %d,%d\n",
               ofperr_domain_get_name(version),
               ofperr_get_type(error, version),
               ofperr_get_code(error, version));
    }
}

/* "ofp-print HEXSTRING [VERBOSITY]": Converts the hex digits in HEXSTRING into
 * binary data, interpreting them as an OpenFlow message, and prints the
 * OpenFlow message on stdout, at VERBOSITY (level 2 by default).  */
static void
ofctl_ofp_print(int argc, char *argv[])
{
    struct ofpbuf packet;

    ofpbuf_init(&packet, strlen(argv[1]) / 2);
    if (ofpbuf_put_hex(&packet, argv[1], NULL)[0] != '\0') {
        ovs_fatal(0, "trailing garbage following hex bytes");
    }
    ofp_print(stdout, packet.data, packet.size, argc > 2 ? atoi(argv[2]) : 2);
    ofpbuf_uninit(&packet);
}

static const struct command all_commands[] = {
    { "show", 1, 1, ofctl_show },
    { "monitor", 1, 3, ofctl_monitor },
    { "snoop", 1, 1, ofctl_snoop },
    { "dump-desc", 1, 1, ofctl_dump_desc },
    { "dump-tables", 1, 1, ofctl_dump_tables },
    { "dump-flows", 1, 2, ofctl_dump_flows },
    { "dump-aggregate", 1, 2, ofctl_dump_aggregate },
    { "queue-stats", 1, 3, ofctl_queue_stats },
    { "add-flow", 2, 2, ofctl_add_flow },
    { "add-flows", 2, 2, ofctl_add_flows },
    { "mod-flows", 2, 2, ofctl_mod_flows },
    { "del-flows", 1, 2, ofctl_del_flows },
    { "replace-flows", 2, 2, ofctl_replace_flows },
    { "diff-flows", 2, 2, ofctl_diff_flows },
    { "packet-out", 4, INT_MAX, ofctl_packet_out },
    { "dump-ports", 1, 2, ofctl_dump_ports },
    { "dump-ports-desc", 1, 1, ofctl_dump_ports_desc },
    { "mod-port", 3, 3, ofctl_mod_port },
    { "get-frags", 1, 1, ofctl_get_frags },
    { "set-frags", 2, 2, ofctl_set_frags },
    { "probe", 1, 1, ofctl_probe },
    { "ping", 1, 2, ofctl_ping },
    { "benchmark", 3, 3, ofctl_benchmark },
    { "help", 0, INT_MAX, ofctl_help },

    /* Undocumented commands for testing. */
    { "parse-flow", 1, 1, ofctl_parse_flow },
    { "parse-flows", 1, 1, ofctl_parse_flows },
    { "parse-nx-match", 0, 0, ofctl_parse_nxm },
    { "parse-nxm", 0, 0, ofctl_parse_nxm },
    { "parse-oxm", 0, 0, ofctl_parse_oxm },
    { "parse-ofp10-actions", 0, 0, ofctl_parse_ofp10_actions },
    { "parse-ofp10-match", 0, 0, ofctl_parse_ofp10_match },
    { "parse-ofp11-match", 0, 0, ofctl_parse_ofp11_match },
    { "parse-ofp11-actions", 0, 0, ofctl_parse_ofp11_actions },
    { "parse-ofp11-instructions", 0, 0, ofctl_parse_ofp11_instructions },
    { "check-vlan", 2, 2, ofctl_check_vlan },
    { "print-error", 1, 1, ofctl_print_error },
    { "ofp-print", 1, 2, ofctl_ofp_print },

    { NULL, 0, 0, NULL },
};
