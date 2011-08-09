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
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "byte-order.h"
#include "classifier.h"
#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "ofproto/ofproto.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "random.h"
#include "stream-ssl.h"
#include "timeval.h"
#include "util.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(ofctl);

/* --strict: Use strict matching for flow mod commands? */
static bool strict;

/* --readd: If ture, on replace-flows, re-add even flows that have not changed
 * (to reset flow counters). */
static bool readd;

/* -F, --flow-format: Flow format to use.  Either one of NXFF_* to force a
 * particular flow format or -1 to let ovs-ofctl choose intelligently. */
static int preferred_flow_format = -1;

/* -m, --more: Additional verbosity for ofp-print functions. */
static int verbosity;

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
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"timeout", required_argument, NULL, 't'},
        {"strict", no_argument, NULL, OPT_STRICT},
        {"readd", no_argument, NULL, OPT_READD},
        {"flow-format", required_argument, NULL, 'F'},
        {"more", no_argument, NULL, 'm'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
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
            preferred_flow_format = ofputil_flow_format_from_string(optarg);
            if (preferred_flow_format < 0) {
                ovs_fatal(0, "unknown flow format `%s'", optarg);
            }
            break;

        case 'm':
            verbosity++;
            break;

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(OFP_VERSION, OFP_VERSION);
            exit(EXIT_SUCCESS);

        case OPT_STRICT:
            strict = true;
            break;

        case OPT_READD:
            readd = true;
            break;

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
           "  dump-ports SWITCH [PORT]    print port statistics\n"
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
           "  monitor SWITCH [MISSLEN]    print packets received from SWITCH\n"
           "\nFor OpenFlow switches and controllers:\n"
           "  probe VCONN                 probe whether VCONN is up\n"
           "  ping VCONN [N]              latency of N-byte echos\n"
           "  benchmark VCONN N COUNT     bandwidth of COUNT N-byte echos\n"
           "where each SWITCH is an active OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, false, false);
    vlog_usage();
    printf("\nOther options:\n"
           "  --strict                    use strict match for flow commands\n"
           "  --readd                     replace flows that haven't changed\n"
           "  -F, --flow-format=FORMAT    force particular flow format\n"
           "  -m, --more                  be more verbose printing OpenFlow\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  -h, --help                  display this help message\n"
           "  -V, --version               display version information\n");
    exit(EXIT_SUCCESS);
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
    run(vconn_open_block(vconn_name, OFP_VERSION, vconnp),
        "connecting to %s", vconn_name);
    free(vconn_name);
}

static void
open_vconn__(const char *name, const char *default_suffix,
             struct vconn **vconnp)
{
    char *datapath_name, *datapath_type, *socket_name;
    char *bridge_path;
    struct stat s;

    bridge_path = xasprintf("%s/%s.%s", ovs_rundir(), name, default_suffix);

    ofproto_parse_name(name, &datapath_name, &datapath_type);
    socket_name = xasprintf("%s/%s.%s",
                            ovs_rundir(), datapath_name, default_suffix);
    free(datapath_name);
    free(datapath_type);

    if (strchr(name, ':')) {
        run(vconn_open_block(name, OFP_VERSION, vconnp),
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
}

static void
open_vconn(const char *name, struct vconn **vconnp)
{
    return open_vconn__(name, "mgmt", vconnp);
}

static void *
alloc_stats_request(size_t rq_len, uint16_t type, struct ofpbuf **bufferp)
{
    struct ofp_stats_msg *rq;

    rq = make_openflow(rq_len, OFPT_STATS_REQUEST, bufferp);
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
 * it and exits with an error. */
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
 * it and exits with an error. */
static void
transact_noreply(struct vconn *vconn, struct ofpbuf *request)
{
    struct list requests;

    list_init(&requests);
    list_push_back(&requests, &request->list_node);
    transact_multiple_noreply(vconn, &requests);
}

static void
do_show(int argc OVS_UNUSED, char *argv[])
{
    dump_trivial_transaction(argv[1], OFPT_FEATURES_REQUEST);
    dump_trivial_transaction(argv[1], OFPT_GET_CONFIG_REQUEST);
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

/* Opens a connection to 'vconn_name', fetches the ofp_phy_port structure for
 * 'port_name' (which may be a port name or number), and copies it into
 * '*oppp'. */
static void
fetch_ofp_phy_port(const char *vconn_name, const char *port_name,
                   struct ofp_phy_port *oppp)
{
    struct ofpbuf *request, *reply;
    struct ofp_switch_features *osf;
    unsigned int port_no;
    struct vconn *vconn;
    int n_ports;
    int port_idx;

    /* Try to interpret the argument as a port number. */
    if (!str_to_uint(port_name, 10, &port_no)) {
        port_no = UINT_MAX;
    }

    /* Fetch the switch's ofp_switch_features. */
    make_openflow(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, &request);
    open_vconn(vconn_name, &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);

    osf = reply->data;
    if (reply->size < sizeof *osf) {
        ovs_fatal(0, "%s: received too-short features reply (only %zu bytes)",
                  vconn_name, reply->size);
    }
    n_ports = (reply->size - sizeof *osf) / sizeof *osf->ports;

    for (port_idx = 0; port_idx < n_ports; port_idx++) {
        const struct ofp_phy_port *opp = &osf->ports[port_idx];

        if (port_no != UINT_MAX
            ? htons(port_no) == opp->port_no
            : !strncmp(opp->name, port_name, sizeof opp->name)) {
            *oppp = *opp;
            ofpbuf_delete(reply);
            vconn_close(vconn);
            return;
        }
    }
    ovs_fatal(0, "%s: couldn't find port `%s'", vconn_name, port_name);
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
        struct ofp_phy_port opp;

        fetch_ofp_phy_port(vconn_name, port_name, &opp);
        return ntohs(opp.port_no);
    }
}

static bool
try_set_flow_format(struct vconn *vconn, enum nx_flow_format flow_format)
{
    struct ofpbuf *sff, *reply;

    sff = ofputil_make_set_flow_format(flow_format);
    run(vconn_transact_noreply(vconn, sff, &reply),
        "talking to %s", vconn_get_name(vconn));
    if (reply) {
        char *s = ofp_to_string(reply->data, reply->size, 2);
        VLOG_DBG("%s: failed to set flow format %s, controller replied: %s",
                 vconn_get_name(vconn),
                 ofputil_flow_format_to_string(flow_format),
                 s);
        free(s);
        ofpbuf_delete(reply);
        return false;
    }
    return true;
}

static void
set_flow_format(struct vconn *vconn, enum nx_flow_format flow_format)
{
    struct ofpbuf *sff = ofputil_make_set_flow_format(flow_format);
    transact_noreply(vconn, sff);
    VLOG_DBG("%s: using user-specified flow format %s",
             vconn_get_name(vconn),
             ofputil_flow_format_to_string(flow_format));
}

static enum nx_flow_format
negotiate_highest_flow_format(struct vconn *vconn,
                              enum nx_flow_format min_format)
{
    if (preferred_flow_format != -1) {
        if (preferred_flow_format < min_format) {
            ovs_fatal(0, "%s: cannot use requested flow format %s for "
                      "specified flow", vconn_get_name(vconn),
                      ofputil_flow_format_to_string(min_format));
        }

        set_flow_format(vconn, preferred_flow_format);
        return preferred_flow_format;
    } else {
        enum nx_flow_format flow_format;

        if (try_set_flow_format(vconn, NXFF_NXM)) {
            flow_format = NXFF_NXM;
        } else {
            flow_format = NXFF_OPENFLOW10;
        }

        if (flow_format < min_format) {
            ovs_fatal(0, "%s: cannot use switch's most advanced flow format "
                      "%s for specified flow", vconn_get_name(vconn),
                      ofputil_flow_format_to_string(min_format));
        }

        VLOG_DBG("%s: negotiated flow format %s", vconn_get_name(vconn),
                 ofputil_flow_format_to_string(flow_format));
        return flow_format;
    }
}

static void
do_dump_flows__(int argc, char *argv[], bool aggregate)
{
    enum nx_flow_format min_flow_format, flow_format;
    struct flow_stats_request fsr;
    struct ofpbuf *request;
    struct vconn *vconn;

    parse_ofp_flow_stats_request_str(&fsr, aggregate, argc > 2 ? argv[2] : "");

    open_vconn(argv[1], &vconn);
    min_flow_format = ofputil_min_flow_format(&fsr.match);
    flow_format = negotiate_highest_flow_format(vconn, min_flow_format);
    request = ofputil_encode_flow_stats_request(&fsr, flow_format);
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

/* Sets up the flow format for a vconn that will be used to modify the flow
 * table.  Returns the flow format used, after possibly adding an OpenFlow
 * request to 'requests'.
 *
 * If 'preferred_flow_format' is -1, returns NXFF_OPENFLOW10 without modifying
 * 'requests', since NXFF_OPENFLOW10 is the default flow format for any
 * OpenFlow connection.
 *
 * If 'preferred_flow_format' is a specific format, adds a request to set that
 * format to 'requests' and returns the format. */
static enum nx_flow_format
set_initial_format_for_flow_mod(struct list *requests)
{
    if (preferred_flow_format < 0) {
        return NXFF_OPENFLOW10;
    } else {
        struct ofpbuf *sff;

        sff = ofputil_make_set_flow_format(preferred_flow_format);
        list_push_back(requests, &sff->list_node);
        return preferred_flow_format;
    }
}

/* Checks that 'flow_format' is acceptable as a flow format after a flow_mod
 * operation, given the global 'preferred_flow_format'. */
static void
check_final_format_for_flow_mod(enum nx_flow_format flow_format)
{
    if (preferred_flow_format >= 0 && flow_format > preferred_flow_format) {
        ovs_fatal(0, "flow cannot be expressed in flow format %s "
                  "(flow format %s or better is required)",
                  ofputil_flow_format_to_string(preferred_flow_format),
                  ofputil_flow_format_to_string(flow_format));
    }
}

static void
do_flow_mod_file__(int argc OVS_UNUSED, char *argv[], uint16_t command)
{
    enum nx_flow_format flow_format;
    bool flow_mod_table_id;
    struct list requests;
    struct vconn *vconn;
    FILE *file;

    file = !strcmp(argv[2], "-") ? stdin : fopen(argv[2], "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", argv[2]);
    }

    list_init(&requests);
    flow_format = set_initial_format_for_flow_mod(&requests);
    flow_mod_table_id = false;

    open_vconn(argv[1], &vconn);
    while (parse_ofp_flow_mod_file(&requests, &flow_format, &flow_mod_table_id,
                                   file, command)) {
        check_final_format_for_flow_mod(flow_format);
        transact_multiple_noreply(vconn, &requests);
    }
    vconn_close(vconn);

    if (file != stdin) {
        fclose(file);
    }
}

static void
do_flow_mod__(int argc, char *argv[], uint16_t command)
{
    enum nx_flow_format flow_format;
    bool flow_mod_table_id;
    struct list requests;
    struct vconn *vconn;

    if (argc > 2 && !strcmp(argv[2], "-")) {
        do_flow_mod_file__(argc, argv, command);
        return;
    }

    list_init(&requests);
    flow_format = set_initial_format_for_flow_mod(&requests);
    flow_mod_table_id = false;

    parse_ofp_flow_mod_str(&requests, &flow_format, &flow_mod_table_id,
                           argc > 2 ? argv[2] : "", command, false);
    check_final_format_for_flow_mod(flow_format);

    open_vconn(argv[1], &vconn);
    transact_multiple_noreply(vconn, &requests);
    vconn_close(vconn);
}

static void
do_add_flow(int argc, char *argv[])
{
    do_flow_mod__(argc, argv, OFPFC_ADD);
}

static void
do_add_flows(int argc, char *argv[])
{
    do_flow_mod_file__(argc, argv, OFPFC_ADD);
}

static void
do_mod_flows(int argc, char *argv[])
{
    do_flow_mod__(argc, argv, strict ? OFPFC_MODIFY_STRICT : OFPFC_MODIFY);
}

static void
do_del_flows(int argc, char *argv[])
{
    do_flow_mod__(argc, argv, strict ? OFPFC_DELETE_STRICT : OFPFC_DELETE);
}

static void
monitor_vconn(struct vconn *vconn)
{
    for (;;) {
        struct ofpbuf *b;
        run(vconn_recv_block(vconn, &b), "vconn_recv");
        ofp_print(stderr, b->data, b->size, verbosity + 2);
        ofpbuf_delete(b);
    }
}

static void
do_monitor(int argc, char *argv[])
{
    struct vconn *vconn;

    open_vconn(argv[1], &vconn);
    if (argc > 2) {
        int miss_send_len = atoi(argv[2]);
        struct ofp_switch_config *osc;
        struct ofpbuf *buf;

        osc = make_openflow(sizeof *osc, OFPT_SET_CONFIG, &buf);
        osc->miss_send_len = htons(miss_send_len);
        transact_noreply(vconn, buf);
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
do_mod_port(int argc OVS_UNUSED, char *argv[])
{
    struct ofp_port_mod *opm;
    struct ofp_phy_port opp;
    struct ofpbuf *request;
    struct vconn *vconn;

    fetch_ofp_phy_port(argv[1], argv[2], &opp);

    opm = make_openflow(sizeof(struct ofp_port_mod), OFPT_PORT_MOD, &request);
    opm->port_no = opp.port_no;
    memcpy(opm->hw_addr, opp.hw_addr, sizeof opm->hw_addr);
    opm->config = htonl(0);
    opm->mask = htonl(0);
    opm->advertise = htonl(0);

    if (!strcasecmp(argv[3], "up")) {
        opm->mask |= htonl(OFPPC_PORT_DOWN);
    } else if (!strcasecmp(argv[3], "down")) {
        opm->mask |= htonl(OFPPC_PORT_DOWN);
        opm->config |= htonl(OFPPC_PORT_DOWN);
    } else if (!strcasecmp(argv[3], "flood")) {
        opm->mask |= htonl(OFPPC_NO_FLOOD);
    } else if (!strcasecmp(argv[3], "noflood")) {
        opm->mask |= htonl(OFPPC_NO_FLOOD);
        opm->config |= htonl(OFPPC_NO_FLOOD);
    } else {
        ovs_fatal(0, "unknown mod-port command '%s'", argv[3]);
    }

    open_vconn(argv[1], &vconn);
    transact_noreply(vconn, request);
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
 * with the specified 'index'.  Returns the minimum flow format required to
 * represent the flows that were read. */
static enum nx_flow_format
read_flows_from_file(const char *filename, struct classifier *cls, int index)
{
    enum nx_flow_format min_flow_format;
    struct ds s;
    FILE *file;

    file = !strcmp(filename, "-") ? stdin : fopen(filename, "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", filename);
    }

    ds_init(&s);
    min_flow_format = NXFF_OPENFLOW10;
    while (!ds_get_preprocessed_line(&s, file)) {
        struct fte_version *version;
        enum nx_flow_format min_ff;
        struct flow_mod fm;

        parse_ofp_str(&fm, OFPFC_ADD, ds_cstr(&s), true);

        version = xmalloc(sizeof *version);
        version->cookie = fm.cookie;
        version->idle_timeout = fm.idle_timeout;
        version->hard_timeout = fm.hard_timeout;
        version->flags = fm.flags & (OFPFF_SEND_FLOW_REM | OFPFF_EMERG);
        version->actions = fm.actions;
        version->n_actions = fm.n_actions;

        min_ff = ofputil_min_flow_format(&fm.cr);
        min_flow_format = MAX(min_flow_format, min_ff);
        check_final_format_for_flow_mod(min_flow_format);

        fte_insert(cls, &fm.cr, version, index);
    }
    ds_destroy(&s);

    if (file != stdin) {
        fclose(file);
    }

    return min_flow_format;
}

/* Reads the OpenFlow flow table from 'vconn', which has currently active flow
 * format 'flow_format', and adds them as flow table entries in 'cls' for the
 * version with the specified 'index'. */
static void
read_flows_from_switch(struct vconn *vconn, enum nx_flow_format flow_format,
                       struct classifier *cls, int index)
{
    struct flow_stats_request fsr;
    struct ofpbuf *request;
    ovs_be32 send_xid;
    bool done;

    fsr.aggregate = false;
    cls_rule_init_catchall(&fsr.match, 0);
    fsr.out_port = OFPP_NONE;
    fsr.table_id = 0xff;
    request = ofputil_encode_flow_stats_request(&fsr, flow_format);
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

                retval = ofputil_decode_flow_stats_reply(&fs, reply);
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
                  enum nx_flow_format flow_format, struct list *packets)
{
    const struct fte_version *version = fte->versions[index];
    struct flow_mod fm;
    struct ofpbuf *ofm;

    fm.cr = fte->rule;
    fm.cookie = version->cookie;
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

    ofm = ofputil_encode_flow_mod(&fm, flow_format, false);
    list_push_back(packets, &ofm->list_node);
}

static void
do_replace_flows(int argc OVS_UNUSED, char *argv[])
{
    enum { FILE_IDX = 0, SWITCH_IDX = 1 };
    enum nx_flow_format min_flow_format, flow_format;
    struct cls_cursor cursor;
    struct classifier cls;
    struct list requests;
    struct vconn *vconn;
    struct fte *fte;

    classifier_init(&cls);
    min_flow_format = read_flows_from_file(argv[2], &cls, FILE_IDX);

    open_vconn(argv[1], &vconn);
    flow_format = negotiate_highest_flow_format(vconn, min_flow_format);
    read_flows_from_switch(vconn, flow_format, &cls, SWITCH_IDX);

    list_init(&requests);

    /* Delete flows that exist on the switch but not in the file. */
    cls_cursor_init(&cursor, &cls, NULL);
    CLS_CURSOR_FOR_EACH (fte, rule, &cursor) {
        struct fte_version *file_ver = fte->versions[FILE_IDX];
        struct fte_version *sw_ver = fte->versions[SWITCH_IDX];

        if (sw_ver && !file_ver) {
            fte_make_flow_mod(fte, SWITCH_IDX, OFPFC_DELETE_STRICT,
                              flow_format, &requests);
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
            fte_make_flow_mod(fte, FILE_IDX, OFPFC_ADD, flow_format,
                              &requests);
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
        enum nx_flow_format flow_format;
        struct vconn *vconn;

        open_vconn(source, &vconn);
        flow_format = negotiate_highest_flow_format(vconn, NXFF_OPENFLOW10);
        read_flows_from_switch(vconn, flow_format, cls, index);
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
print_packet_list(struct list *packets)
{
    struct ofpbuf *packet, *next;

    LIST_FOR_EACH_SAFE (packet, next, list_node, packets) {
        ofp_print(stdout, packet->data, packet->size, verbosity);
        list_remove(&packet->list_node);
        ofpbuf_delete(packet);
    }
}

/* "parse-flow FLOW": parses the argument as a flow (like add-flow) and prints
 * it back to stdout.  */
static void
do_parse_flow(int argc OVS_UNUSED, char *argv[])
{
    enum nx_flow_format flow_format;
    bool flow_mod_table_id;
    struct list packets;

    flow_format = NXFF_OPENFLOW10;
    if (preferred_flow_format > 0) {
        flow_format = preferred_flow_format;
    }
    flow_mod_table_id = false;

    list_init(&packets);
    parse_ofp_flow_mod_str(&packets, &flow_format, &flow_mod_table_id,
                           argv[1], OFPFC_ADD, false);
    print_packet_list(&packets);
}

/* "parse-flows FILENAME": reads the named file as a sequence of flows (like
 * add-flows) and prints each of the flows back to stdout.  */
static void
do_parse_flows(int argc OVS_UNUSED, char *argv[])
{
    enum nx_flow_format flow_format;
    bool flow_mod_table_id;
    struct list packets;
    FILE *file;

    file = fopen(argv[1], "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", argv[2]);
    }

    flow_format = NXFF_OPENFLOW10;
    if (preferred_flow_format > 0) {
        flow_format = preferred_flow_format;
    }
    flow_mod_table_id = false;

    list_init(&packets);
    while (parse_ofp_flow_mod_file(&packets, &flow_format, &flow_mod_table_id,
                                   file, OFPFC_ADD)) {
        print_packet_list(&packets);
    }
    fclose(file);
}

/* "parse-nx-match": reads a series of nx_match specifications as strings from
 * stdin, does some internal fussing with them, and then prints them back as
 * strings on stdout. */
static void
do_parse_nx_match(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct ds in;

    ds_init(&in);
    while (!ds_get_line(&in, stdin)) {
        struct ofpbuf nx_match;
        struct cls_rule rule;
        int match_len;
        int error;
        char *s;

        /* Delete comments, skip blank lines. */
        s = ds_cstr(&in);
        if (*s == '#') {
            puts(s);
            continue;
        }
        if (strchr(s, '#')) {
            *strchr(s, '#') = '\0';
        }
        if (s[strspn(s, " ")] == '\0') {
            putchar('\n');
            continue;
        }

        /* Convert string to nx_match. */
        ofpbuf_init(&nx_match, 0);
        match_len = nx_match_from_string(ds_cstr(&in), &nx_match);

        /* Convert nx_match to cls_rule. */
        error = nx_pull_match(&nx_match, match_len, 0, &rule);
        if (!error) {
            char *out;

            /* Convert cls_rule back to nx_match. */
            ofpbuf_uninit(&nx_match);
            ofpbuf_init(&nx_match, 0);
            match_len = nx_put_match(&nx_match, &rule);

            /* Convert nx_match to string. */
            out = nx_match_to_string(nx_match.data, match_len);
            puts(out);
            free(out);
        } else {
            printf("nx_pull_match() returned error %x (%s)\n", error,
                   ofputil_error_to_string(error));
        }

        ofpbuf_uninit(&nx_match);
    }
    ds_destroy(&in);
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
    { "monitor", 1, 2, do_monitor },
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
    { "dump-ports", 1, 2, do_dump_ports },
    { "mod-port", 3, 3, do_mod_port },
    { "probe", 1, 1, do_probe },
    { "ping", 1, 2, do_ping },
    { "benchmark", 3, 3, do_benchmark },
    { "help", 0, INT_MAX, do_help },

    /* Undocumented commands for testing. */
    { "parse-flow", 1, 1, do_parse_flow },
    { "parse-flows", 1, 1, do_parse_flows },
    { "parse-nx-match", 0, 0, do_parse_nx_match },
    { "ofp-print", 1, 2, do_ofp_print },

    { NULL, 0, 0, NULL },
};
