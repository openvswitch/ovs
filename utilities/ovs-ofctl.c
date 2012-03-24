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
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-errors.h"
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

static const struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

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
parse_options(int argc, char *argv[])
{
    enum {
        OPT_STRICT = UCHAR_MAX + 1,
        OPT_READD,
        OPT_TIMESTAMP,
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

        DAEMON_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

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
           "  monitor SWITCH [MISSLEN] [invalid_ttl]\n"
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

static void *
alloc_stats_request(size_t rq_len, uint16_t type, struct ofpbuf **bufferp)
{
    struct ofp_stats_msg *rq;

    rq = make_openflow(rq_len, OFPT10_STATS_REQUEST, bufferp);
    rq->type = htons(type);
    rq->flags = htons(0);
    return rq;
}

static void
send_openflow_buffer(struct vconn *vconn, struct ofpbuf *buffer)
{
    update_openflow_length(buffer);
    run(vconn_send_block(vconn, buffer), "failed to send packet to switch");
}

static void
dump_transaction(const char *vconn_name, struct ofpbuf *request)
{
    struct vconn *vconn;
    struct ofpbuf *reply;

    update_openflow_length(request);
    open_vconn(vconn_name, &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);
    ofp_print(stdout, reply->data, reply->size, verbosity + 1);
    ofpbuf_delete(reply);
    vconn_close(vconn);
}

static void
dump_trivial_transaction(const char *vconn_name, uint8_t request_type)
{
    struct ofpbuf *request;
    make_openflow(sizeof(struct ofp_header), request_type, &request);
    dump_transaction(vconn_name, request);
}

static void
dump_stats_transaction(const char *vconn_name, struct ofpbuf *request)
{
    ovs_be32 send_xid = ((struct ofp_header *) request->data)->xid;
    struct vconn *vconn;
    bool done = false;

    open_vconn(vconn_name, &vconn);
    send_openflow_buffer(vconn, request);
    while (!done) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            struct ofp_stats_msg *osm;

            ofp_print(stdout, reply->data, reply->size, verbosity + 1);

            osm = ofpbuf_at(reply, 0, sizeof *osm);
            done = !osm || !(ntohs(osm->flags) & OFPSF_REPLY_MORE);
        } else {
            VLOG_DBG("received reply with xid %08"PRIx32" "
                     "!= expected %08"PRIx32, recv_xid, send_xid);
        }
        ofpbuf_delete(reply);
    }
    vconn_close(vconn);
}

static void
dump_trivial_stats_transaction(const char *vconn_name, uint8_t stats_type)
{
    struct ofpbuf *request;
    alloc_stats_request(sizeof(struct ofp_stats_msg), stats_type, &request);
    dump_stats_transaction(vconn_name, request);
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
        update_openflow_length(request);
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
    struct ofp_header *header;
    struct ofpbuf *request;
    struct ofpbuf *reply;

    make_openflow(sizeof(struct ofp_header), OFPT_GET_CONFIG_REQUEST,
                  &request);
    run(vconn_transact(vconn, request, &reply),
        "talking to %s", vconn_get_name(vconn));

    header = reply->data;
    if (header->type != OFPT_GET_CONFIG_REPLY ||
        header->length != htons(sizeof *config)) {
        ovs_fatal(0, "%s: bad reply to config request", vconn_get_name(vconn));
    }

    config = reply->data;
    *config_ = *config;

    ofpbuf_delete(reply);
}

static void
set_switch_config(struct vconn *vconn, struct ofp_switch_config *config_)
{
    struct ofp_switch_config *config;
    struct ofp_header save_header;
    struct ofpbuf *request;

    config = make_openflow(sizeof *config, OFPT_SET_CONFIG, &request);
    save_header = config->header;
    *config = *config_;
    config->header = save_header;

    transact_noreply(vconn, request);
}

static void
do_show(int argc OVS_UNUSED, char *argv[])
{
    const char *vconn_name = argv[1];
    struct vconn *vconn;
    struct ofpbuf *request;
    struct ofpbuf *reply;
    bool trunc;

    make_openflow(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST,
                  &request);
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
        dump_trivial_stats_transaction(vconn_name, OFPST_PORT_DESC);
    }
    dump_trivial_transaction(vconn_name, OFPT_GET_CONFIG_REQUEST);
}

static void
do_dump_desc(int argc OVS_UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPST_DESC);
}

static void
do_dump_tables(int argc OVS_UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPST_TABLE);
}

static bool
fetch_port_by_features(const char *vconn_name,
                       const char *port_name, unsigned int port_no,
                       struct ofputil_phy_port *pp, bool *trunc)
{
    struct ofputil_switch_features features;
    const struct ofp_switch_features *osf;
    struct ofpbuf *request, *reply;
    struct vconn *vconn;
    enum ofperr error;
    struct ofpbuf b;
    bool found = false;

    /* Fetch the switch's ofp_switch_features. */
    make_openflow(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, &request);
    open_vconn(vconn_name, &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);
    vconn_close(vconn);

    osf = reply->data;
    if (reply->size < sizeof *osf) {
        ovs_fatal(0, "%s: received too-short features reply (only %zu bytes)",
                  vconn_name, reply->size);
    }

    *trunc = false;
    if (ofputil_switch_features_ports_trunc(reply)) {
        *trunc = true;
        goto exit;
    }

    error = ofputil_decode_switch_features(osf, &features, &b);
    if (error) {
        ovs_fatal(0, "%s: failed to decode features reply (%s)",
                  vconn_name, ofperr_to_string(error));
    }

    while (!ofputil_pull_phy_port(osf->header.version, &b, pp)) {
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
    struct ofpbuf b;
    bool done = false;
    bool found = false;

    alloc_stats_request(sizeof(struct ofp_stats_msg), OFPST_PORT_DESC,
                        &request);
    send_xid = ((struct ofp_header *) request->data)->xid;

    open_vconn(vconn_name, &vconn);
    send_openflow_buffer(vconn, request);
    while (!done) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            const struct ofputil_msg_type *type;
            struct ofp_stats_msg *osm;

            ofputil_decode_msg_type(reply->data, &type);
            if (ofputil_msg_type_code(type) != OFPUTIL_OFPST_PORT_DESC_REPLY) {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(reply->data, reply->size,
                                        verbosity + 1));
            }

            osm = ofpbuf_at_assert(reply, 0, sizeof *osm);
            done = !(ntohs(osm->flags) & OFPSF_REPLY_MORE);

            if (found) {
                /* We've already found the port, but we need to drain
                 * the queue of any other replies for this request. */
                continue;
            }

            ofpbuf_use_const(&b, &osm->header, ntohs(osm->header.length));
            ofpbuf_pull(&b, sizeof(struct ofp_stats_msg));

            while (!ofputil_pull_phy_port(osm->header.version, &b, pp)) {
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
    unsigned int port_no;

    if (str_to_uint(port_name, 10, &port_no)) {
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

static void
do_dump_flows__(int argc, char *argv[], bool aggregate)
{
    enum ofputil_protocol usable_protocols, protocol;
    struct ofputil_flow_stats_request fsr;
    struct ofpbuf *request;
    struct vconn *vconn;

    parse_ofp_flow_stats_request_str(&fsr, aggregate, argc > 2 ? argv[2] : "");
    usable_protocols = ofputil_flow_stats_request_usable_protocols(&fsr);

    protocol = open_vconn(argv[1], &vconn);
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);
    request = ofputil_encode_flow_stats_request(&fsr, protocol);
    dump_stats_transaction(argv[1], request);
    vconn_close(vconn);
}

static void
do_dump_flows(int argc, char *argv[])
{
    return do_dump_flows__(argc, argv, false);
}

static void
do_dump_aggregate(int argc, char *argv[])
{
    return do_dump_flows__(argc, argv, true);
}

static void
do_queue_stats(int argc, char *argv[])
{
    struct ofp_queue_stats_request *req;
    struct ofpbuf *request;

    req = alloc_stats_request(sizeof *req, OFPST_QUEUE, &request);

    if (argc > 2 && argv[2][0] && strcasecmp(argv[2], "all")) {
        req->port_no = htons(str_to_port_no(argv[1], argv[2]));
    } else {
        req->port_no = htons(OFPP_ALL);
    }
    if (argc > 3 && argv[3][0] && strcasecmp(argv[3], "all")) {
        req->queue_id = htonl(atoi(argv[3]));
    } else {
        req->queue_id = htonl(OFPQ_ALL);
    }

    memset(req->pad, 0, sizeof req->pad);

    dump_stats_transaction(argv[1], request);
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
do_flow_mod__(const char *remote, struct ofputil_flow_mod *fms, size_t n_fms)
{
    enum ofputil_protocol protocol;
    struct vconn *vconn;
    size_t i;

    protocol = open_vconn_for_flow_mod(remote, fms, n_fms, &vconn);

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];

        transact_noreply(vconn, ofputil_encode_flow_mod(fm, protocol));
        free(fm->actions);
    }
    vconn_close(vconn);
}

static void
do_flow_mod_file(int argc OVS_UNUSED, char *argv[], uint16_t command)
{
    struct ofputil_flow_mod *fms = NULL;
    size_t n_fms = 0;

    parse_ofp_flow_mod_file(argv[2], command, &fms, &n_fms);
    do_flow_mod__(argv[1], fms, n_fms);
    free(fms);
}

static void
do_flow_mod(int argc, char *argv[], uint16_t command)
{
    if (argc > 2 && !strcmp(argv[2], "-")) {
        do_flow_mod_file(argc, argv, command);
    } else {
        struct ofputil_flow_mod fm;
        parse_ofp_flow_mod_str(&fm, argc > 2 ? argv[2] : "", command, false);
        do_flow_mod__(argv[1], &fm, 1);
    }
}

static void
do_add_flow(int argc, char *argv[])
{
    do_flow_mod(argc, argv, OFPFC_ADD);
}

static void
do_add_flows(int argc, char *argv[])
{
    do_flow_mod_file(argc, argv, OFPFC_ADD);
}

static void
do_mod_flows(int argc, char *argv[])
{
    do_flow_mod(argc, argv, strict ? OFPFC_MODIFY_STRICT : OFPFC_MODIFY);
}

static void
do_del_flows(int argc, char *argv[])
{
    do_flow_mod(argc, argv, strict ? OFPFC_DELETE_STRICT : OFPFC_DELETE);
}

static void
set_packet_in_format(struct vconn *vconn,
                     enum nx_packet_in_format packet_in_format)
{
    struct ofpbuf *spif = ofputil_make_set_packet_in_format(packet_in_format);
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

    msg = ofputil_encode_barrier_request();
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
monitor_vconn(struct vconn *vconn)
{
    struct barrier_aux barrier_aux = { vconn, NULL };
    struct unixctl_server *server;
    bool exiting = false;
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
    daemonize_complete();

    for (;;) {
        struct ofpbuf *b;
        int retval;

        unixctl_server_run(server);

        for (;;) {
            uint8_t msg_type;

            retval = vconn_recv(vconn, &b);
            if (retval == EAGAIN) {
                break;
            }
            run(retval, "vconn_recv");

            if (timestamp) {
                time_t now = time_wall();
                char s[32];

                strftime(s, sizeof s, "%Y-%m-%d %H:%M:%S: ", localtime(&now));
                fputs(s, stderr);
            }

            msg_type = ((const struct ofp_header *) b->data)->type;
            ofp_print(stderr, b->data, b->size, verbosity + 2);
            ofpbuf_delete(b);

            if (barrier_aux.conn && msg_type == OFPT10_BARRIER_REPLY) {
                unixctl_command_reply(barrier_aux.conn, NULL);
                barrier_aux.conn = NULL;
            }
        }

        if (exiting) {
            break;
        }

        vconn_run(vconn);
        vconn_run_wait(vconn);
        vconn_recv_wait(vconn);
        unixctl_server_wait(server);
        poll_block();
    }
    vconn_close(vconn);
    unixctl_server_destroy(server);
}

static void
do_monitor(int argc, char *argv[])
{
    struct vconn *vconn;

    open_vconn(argv[1], &vconn);
    if (argc > 2) {
        struct ofp_switch_config config;

        fetch_switch_config(vconn, &config);
        config.miss_send_len = htons(atoi(argv[2]));
        set_switch_config(vconn, &config);
    }
    if (argc > 3) {
        if (!strcmp(argv[3], "invalid_ttl")) {
            monitor_set_invalid_ttl_to_controller(vconn);
        }
    }
    if (preferred_packet_in_format >= 0) {
        set_packet_in_format(vconn, preferred_packet_in_format);
    } else {
        struct ofpbuf *spif, *reply;

        spif = ofputil_make_set_packet_in_format(NXPIF_NXM);
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
do_snoop(int argc OVS_UNUSED, char *argv[])
{
    struct vconn *vconn;

    open_vconn__(argv[1], "snoop", &vconn);
    monitor_vconn(vconn);
}

static void
do_dump_ports(int argc, char *argv[])
{
    struct ofp_port_stats_request *req;
    struct ofpbuf *request;
    uint16_t port;

    req = alloc_stats_request(sizeof *req, OFPST_PORT, &request);
    port = argc > 2 ? str_to_port_no(argv[1], argv[2]) : OFPP_NONE;
    req->port_no = htons(port);
    dump_stats_transaction(argv[1], request);
}

static void
do_dump_ports_desc(int argc OVS_UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPST_PORT_DESC);
}

static void
do_probe(int argc OVS_UNUSED, char *argv[])
{
    struct ofpbuf *request;
    struct vconn *vconn;
    struct ofpbuf *reply;

    make_openflow(sizeof(struct ofp_header), OFPT_ECHO_REQUEST, &request);
    open_vconn(argv[1], &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", argv[1]);
    if (reply->size != sizeof(struct ofp_header)) {
        ovs_fatal(0, "reply does not match request");
    }
    ofpbuf_delete(reply);
    vconn_close(vconn);
}

static void
do_packet_out(int argc, char *argv[])
{
    struct ofputil_packet_out po;
    struct ofpbuf actions;
    struct vconn *vconn;
    int i;

    ofpbuf_init(&actions, sizeof(union ofp_action));
    parse_ofp_actions(argv[3], &actions);

    po.buffer_id = UINT32_MAX;
    po.in_port = (!strcasecmp(argv[2], "none") ? OFPP_NONE
                  : !strcasecmp(argv[2], "local") ? OFPP_LOCAL
                  : str_to_port_no(argv[1], argv[2]));
    po.actions = actions.data;
    po.n_actions = actions.size / sizeof(union ofp_action);

    open_vconn(argv[1], &vconn);
    for (i = 4; i < argc; i++) {
        struct ofpbuf *packet, *opo;
        const char *error_msg;

        error_msg = eth_from_hex(argv[i], &packet);
        if (error_msg) {
            ovs_fatal(0, "%s", error_msg);
        }

        po.packet = packet->data;
        po.packet_len = packet->size;
        opo = ofputil_encode_packet_out(&po);
        transact_noreply(vconn, opo);
        ofpbuf_delete(packet);
    }
    vconn_close(vconn);
    ofpbuf_uninit(&actions);
}

static void
do_mod_port(int argc OVS_UNUSED, char *argv[])
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
do_get_frags(int argc OVS_UNUSED, char *argv[])
{
    struct ofp_switch_config config;
    struct vconn *vconn;

    open_vconn(argv[1], &vconn);
    fetch_switch_config(vconn, &config);
    puts(ofputil_frag_handling_to_string(ntohs(config.flags)));
    vconn_close(vconn);
}

static void
do_set_frags(int argc OVS_UNUSED, char *argv[])
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
do_ping(int argc, char *argv[])
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
        struct ofp_header *rq_hdr, *rpy_hdr;

        rq_hdr = make_openflow(sizeof(struct ofp_header) + payload,
                               OFPT_ECHO_REQUEST, &request);
        random_bytes(rq_hdr + 1, payload);

        xgettimeofday(&start);
        run(vconn_transact(vconn, ofpbuf_clone(request), &reply), "transact");
        xgettimeofday(&end);

        rpy_hdr = reply->data;
        if (reply->size != request->size
            || memcmp(rpy_hdr + 1, rq_hdr + 1, payload)
            || rpy_hdr->xid != rq_hdr->xid
            || rpy_hdr->type != OFPT_ECHO_REPLY) {
            printf("Reply does not match request.  Request:\n");
            ofp_print(stdout, request, request->size, verbosity + 2);
            printf("Reply:\n");
            ofp_print(stdout, reply, reply->size, verbosity + 2);
        }
        printf("%zu bytes from %s: xid=%08"PRIx32" time=%.1f ms\n",
               reply->size - sizeof *rpy_hdr, argv[1], ntohl(rpy_hdr->xid),
                   (1000*(double)(end.tv_sec - start.tv_sec))
                   + (.001*(end.tv_usec - start.tv_usec)));
        ofpbuf_delete(request);
        ofpbuf_delete(reply);
    }
    vconn_close(vconn);
}

static void
do_benchmark(int argc OVS_UNUSED, char *argv[])
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
        struct ofp_header *rq_hdr;

        rq_hdr = make_openflow(message_size, OFPT_ECHO_REQUEST, &request);
        memset(rq_hdr + 1, 0, payload_size);
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
do_help(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
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
    union ofp_action *actions;
    size_t n_actions;
};

/* Frees 'version' and the data that it owns. */
static void
fte_version_free(struct fte_version *version)
{
    if (version) {
        free(version->actions);
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
            && a->n_actions == b->n_actions
            && !memcmp(a->actions, b->actions,
                       a->n_actions * sizeof *a->actions));
}

/* Prints 'version' on stdout.  Expects the caller to have printed the rule
 * associated with the version. */
static void
fte_version_print(const struct fte_version *version)
{
    struct ds s;

    if (version->cookie != htonll(0)) {
        printf(" cookie=0x%"PRIx64, ntohll(version->cookie));
    }
    if (version->idle_timeout != OFP_FLOW_PERMANENT) {
        printf(" idle_timeout=%"PRIu16, version->idle_timeout);
    }
    if (version->hard_timeout != OFP_FLOW_PERMANENT) {
        printf(" hard_timeout=%"PRIu16, version->hard_timeout);
    }

    ds_init(&s);
    ofp_print_actions(&s, version->actions, version->n_actions);
    printf(" %s\n", ds_cstr(&s));
    ds_destroy(&s);
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
fte_insert(struct classifier *cls, const struct cls_rule *rule,
           struct fte_version *version, int index)
{
    struct fte *old, *fte;

    fte = xzalloc(sizeof *fte);
    fte->rule = *rule;
    fte->versions[index] = version;

    old = fte_from_cls_rule(classifier_replace(cls, &fte->rule));
    if (old) {
        fte_version_free(old->versions[index]);
        fte->versions[!index] = old->versions[!index];
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
        version->flags = fm.flags & (OFPFF_SEND_FLOW_REM | OFPFF_EMERG);
        version->actions = fm.actions;
        version->n_actions = fm.n_actions;

        usable_protocols &= ofputil_usable_protocols(&fm.cr);

        fte_insert(cls, &fm.cr, version, index);
    }
    ds_destroy(&s);

    if (file != stdin) {
        fclose(file);
    }

    return usable_protocols;
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
    struct ofpbuf *request;
    ovs_be32 send_xid;
    bool done;

    fsr.aggregate = false;
    cls_rule_init_catchall(&fsr.match, 0);
    fsr.out_port = OFPP_NONE;
    fsr.table_id = 0xff;
    fsr.cookie = fsr.cookie_mask = htonll(0);
    request = ofputil_encode_flow_stats_request(&fsr, protocol);
    send_xid = ((struct ofp_header *) request->data)->xid;
    send_openflow_buffer(vconn, request);

    done = false;
    while (!done) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            const struct ofputil_msg_type *type;
            const struct ofp_stats_msg *osm;
            enum ofputil_msg_code code;

            ofputil_decode_msg_type(reply->data, &type);
            code = ofputil_msg_type_code(type);
            if (code != OFPUTIL_OFPST_FLOW_REPLY &&
                code != OFPUTIL_NXST_FLOW_REPLY) {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(reply->data, reply->size,
                                        verbosity + 1));
            }

            osm = reply->data;
            if (!(osm->flags & htons(OFPSF_REPLY_MORE))) {
                done = true;
            }

            for (;;) {
                struct fte_version *version;
                struct ofputil_flow_stats fs;
                int retval;

                retval = ofputil_decode_flow_stats_reply(&fs, reply, false);
                if (retval) {
                    if (retval != EOF) {
                        ovs_fatal(0, "parse error in reply");
                    }
                    break;
                }

                version = xmalloc(sizeof *version);
                version->cookie = fs.cookie;
                version->idle_timeout = fs.idle_timeout;
                version->hard_timeout = fs.hard_timeout;
                version->flags = 0;
                version->n_actions = fs.n_actions;
                version->actions = xmemdup(fs.actions,
                                           fs.n_actions * sizeof *fs.actions);

                fte_insert(cls, &fs.rule, version, index);
            }
        } else {
            VLOG_DBG("received reply with xid %08"PRIx32" "
                     "!= expected %08"PRIx32, recv_xid, send_xid);
        }
        ofpbuf_delete(reply);
    }
}

static void
fte_make_flow_mod(const struct fte *fte, int index, uint16_t command,
                  enum ofputil_protocol protocol, struct list *packets)
{
    const struct fte_version *version = fte->versions[index];
    struct ofputil_flow_mod fm;
    struct ofpbuf *ofm;

    fm.cr = fte->rule;
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
        fm.actions = version->actions;
        fm.n_actions = version->n_actions;
    } else {
        fm.actions = NULL;
        fm.n_actions = 0;
    }

    ofm = ofputil_encode_flow_mod(&fm, protocol);
    list_push_back(packets, &ofm->list_node);
}

static void
do_replace_flows(int argc OVS_UNUSED, char *argv[])
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
do_diff_flows(int argc OVS_UNUSED, char *argv[])
{
    bool differences = false;
    struct cls_cursor cursor;
    struct classifier cls;
    struct fte *fte;

    classifier_init(&cls);
    read_flows_from_source(argv[1], &cls, 0);
    read_flows_from_source(argv[2], &cls, 1);

    cls_cursor_init(&cursor, &cls, NULL);
    CLS_CURSOR_FOR_EACH (fte, rule, &cursor) {
        struct fte_version *a = fte->versions[0];
        struct fte_version *b = fte->versions[1];

        if (!a || !b || !fte_version_equals(a, b)) {
            char *rule_s = cls_rule_to_string(&fte->rule);
            if (a) {
                printf("-%s", rule_s);
                fte_version_print(a);
            }
            if (b) {
                printf("+%s", rule_s);
                fte_version_print(b);
            }
            free(rule_s);

            differences = true;
        }
    }

    fte_free_all(&cls);

    if (differences) {
        exit(2);
    }
}

/* Undocumented commands for unit testing. */

static void
do_parse_flows__(struct ofputil_flow_mod *fms, size_t n_fms)
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

        free(fm->actions);
    }
}

/* "parse-flow FLOW": parses the argument as a flow (like add-flow) and prints
 * it back to stdout.  */
static void
do_parse_flow(int argc OVS_UNUSED, char *argv[])
{
    struct ofputil_flow_mod fm;

    parse_ofp_flow_mod_str(&fm, argv[1], OFPFC_ADD, false);
    do_parse_flows__(&fm, 1);
}

/* "parse-flows FILENAME": reads the named file as a sequence of flows (like
 * add-flows) and prints each of the flows back to stdout.  */
static void
do_parse_flows(int argc OVS_UNUSED, char *argv[])
{
    struct ofputil_flow_mod *fms = NULL;
    size_t n_fms = 0;

    parse_ofp_flow_mod_file(argv[1], OFPFC_ADD, &fms, &n_fms);
    do_parse_flows__(fms, n_fms);
    free(fms);
}

/* "parse-nx-match": reads a series of nx_match specifications as strings from
 * stdin, does some internal fussing with them, and then prints them back as
 * strings on stdout. */
static void
do_parse_nx_match(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds in;

    ds_init(&in);
    while (!ds_get_test_line(&in, stdin)) {
        struct ofpbuf nx_match;
        struct cls_rule rule;
        ovs_be64 cookie, cookie_mask;
        enum ofperr error;
        int match_len;

        /* Convert string to nx_match. */
        ofpbuf_init(&nx_match, 0);
        match_len = nx_match_from_string(ds_cstr(&in), &nx_match);

        /* Convert nx_match to cls_rule. */
        if (strict) {
            error = nx_pull_match(&nx_match, match_len, 0, &rule,
                                  &cookie, &cookie_mask);
        } else {
            error = nx_pull_match_loose(&nx_match, match_len, 0, &rule,
                                        &cookie, &cookie_mask);
        }

        if (!error) {
            char *out;

            /* Convert cls_rule back to nx_match. */
            ofpbuf_uninit(&nx_match);
            ofpbuf_init(&nx_match, 0);
            match_len = nx_put_match(&nx_match, &rule, cookie, cookie_mask);

            /* Convert nx_match to string. */
            out = nx_match_to_string(nx_match.data, match_len);
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

/* "print-error ENUM": Prints the type and code of ENUM for every OpenFlow
 * version. */
static void
do_print_error(int argc OVS_UNUSED, char *argv[])
{
    enum ofperr error;
    int version;

    error = ofperr_from_name(argv[1]);
    if (!error) {
        ovs_fatal(0, "unknown error \"%s\"", argv[1]);
    }

    for (version = 0; version <= UINT8_MAX; version++) {
        const struct ofperr_domain *domain;

        domain = ofperr_domain_from_version(version);
        if (!domain) {
            continue;
        }

        printf("%s: %d,%d\n",
               ofperr_domain_get_name(domain),
               ofperr_get_type(error, domain),
               ofperr_get_code(error, domain));
    }
}

/* "ofp-print HEXSTRING [VERBOSITY]": Converts the hex digits in HEXSTRING into
 * binary data, interpreting them as an OpenFlow message, and prints the
 * OpenFlow message on stdout, at VERBOSITY (level 2 by default).  */
static void
do_ofp_print(int argc, char *argv[])
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
    { "show", 1, 1, do_show },
    { "monitor", 1, 3, do_monitor },
    { "snoop", 1, 1, do_snoop },
    { "dump-desc", 1, 1, do_dump_desc },
    { "dump-tables", 1, 1, do_dump_tables },
    { "dump-flows", 1, 2, do_dump_flows },
    { "dump-aggregate", 1, 2, do_dump_aggregate },
    { "queue-stats", 1, 3, do_queue_stats },
    { "add-flow", 2, 2, do_add_flow },
    { "add-flows", 2, 2, do_add_flows },
    { "mod-flows", 2, 2, do_mod_flows },
    { "del-flows", 1, 2, do_del_flows },
    { "replace-flows", 2, 2, do_replace_flows },
    { "diff-flows", 2, 2, do_diff_flows },
    { "packet-out", 4, INT_MAX, do_packet_out },
    { "dump-ports", 1, 2, do_dump_ports },
    { "dump-ports-desc", 1, 1, do_dump_ports_desc },
    { "mod-port", 3, 3, do_mod_port },
    { "get-frags", 1, 1, do_get_frags },
    { "set-frags", 2, 2, do_set_frags },
    { "probe", 1, 1, do_probe },
    { "ping", 1, 2, do_ping },
    { "benchmark", 3, 3, do_benchmark },
    { "help", 0, INT_MAX, do_help },

    /* Undocumented commands for testing. */
    { "parse-flow", 1, 1, do_parse_flow },
    { "parse-flows", 1, 1, do_parse_flows },
    { "parse-nx-match", 0, 0, do_parse_nx_match },
    { "print-error", 1, 1, do_print_error },
    { "ofp-print", 1, 2, do_ofp_print },

    { NULL, 0, 0, NULL },
};
