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
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
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
#include "dpif.h"
#include "dynamic-string.h"
#include "netlink.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
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
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"timeout", required_argument, 0, 't'},
        {"strict", no_argument, 0, OPT_STRICT},
        {"flow-format", required_argument, 0, 'F'},
        {"more", no_argument, 0, 'm'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        VLOG_LONG_OPTIONS,
        STREAM_SSL_LONG_OPTIONS
        {0, 0, 0, 0},
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
           "  status SWITCH [KEY]         report statistics (about KEY)\n"
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

        fprintf(stderr, "%s: ", program_name);
        va_start(args, message);
        vfprintf(stderr, message, args);
        va_end(args);
        if (retval == EOF) {
            fputs(": unexpected end of file\n", stderr);
        } else {
            fprintf(stderr, ": %s\n", strerror(retval));
        }

        exit(EXIT_FAILURE);
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
    struct dpif *dpif;
    struct stat s;
    char *bridge_path, *datapath_name, *datapath_type;

    bridge_path = xasprintf("%s/%s.%s", ovs_rundir(), name, default_suffix);
    dp_parse_name(name, &datapath_name, &datapath_type);

    if (strstr(name, ":")) {
        run(vconn_open_block(name, OFP_VERSION, vconnp),
            "connecting to %s", name);
    } else if (!stat(name, &s) && S_ISSOCK(s.st_mode)) {
        open_vconn_socket(name, vconnp);
    } else if (!stat(bridge_path, &s) && S_ISSOCK(s.st_mode)) {
        open_vconn_socket(bridge_path, vconnp);
    } else if (!dpif_open(datapath_name, datapath_type, &dpif)) {
        char dpif_name[IF_NAMESIZE + 1];
        char *socket_name;

        run(dpif_port_get_name(dpif, ODPP_LOCAL, dpif_name, sizeof dpif_name),
            "obtaining name of %s", dpif_name);
        dpif_close(dpif);
        if (strcmp(dpif_name, name)) {
            VLOG_DBG("datapath %s is named %s", name, dpif_name);
        }

        socket_name = xasprintf("%s/%s.%s",
                                ovs_rundir(), dpif_name, default_suffix);
        if (stat(socket_name, &s)) {
            ovs_fatal(errno, "cannot connect to %s: stat failed on %s",
                      name, socket_name);
        } else if (!S_ISSOCK(s.st_mode)) {
            ovs_fatal(0, "cannot connect to %s: %s is not a socket",
                      name, socket_name);
        }

        open_vconn_socket(socket_name, vconnp);
        free(socket_name);
    } else {
        ovs_fatal(0, "%s is not a valid connection method", name);
    }

    free(datapath_name);
    free(datapath_type);
    free(bridge_path);
}

static void
open_vconn(const char *name, struct vconn **vconnp)
{
    return open_vconn__(name, "mgmt", vconnp);
}

static void *
alloc_stats_request(size_t body_len, uint16_t type, struct ofpbuf **bufferp)
{
    struct ofp_stats_request *rq;
    rq = make_openflow((offsetof(struct ofp_stats_request, body)
                        + body_len), OFPT_STATS_REQUEST, bufferp);
    rq->type = htons(type);
    rq->flags = htons(0);
    return rq->body;
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
        uint32_t recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            struct ofp_stats_reply *osr;

            ofp_print(stdout, reply->data, reply->size, verbosity + 1);

            osr = ofpbuf_at(reply, 0, sizeof *osr);
            done = !osr || !(ntohs(osr->flags) & OFPSF_REPLY_MORE);
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
    alloc_stats_request(0, stats_type, &request);
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
do_status(int argc, char *argv[])
{
    struct nicira_header *request, *reply;
    struct vconn *vconn;
    struct ofpbuf *b;

    request = make_nxmsg(sizeof *request, NXT_STATUS_REQUEST, &b);
    if (argc > 2) {
        ofpbuf_put(b, argv[2], strlen(argv[2]));
        update_openflow_length(b);
    }
    open_vconn(argv[1], &vconn);
    run(vconn_transact(vconn, b, &b), "talking to %s", argv[1]);
    vconn_close(vconn);

    if (b->size < sizeof *reply) {
        ovs_fatal(0, "short reply (%zu bytes)", b->size);
    }
    reply = b->data;
    if (reply->header.type != OFPT_VENDOR
        || reply->vendor != ntohl(NX_VENDOR_ID)
        || reply->subtype != ntohl(NXT_STATUS_REPLY)) {
        ofp_print(stderr, b->data, b->size, verbosity + 2);
        ovs_fatal(0, "bad reply");
    }

    fwrite(reply + 1, b->size - sizeof *reply, 1, stdout);
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
negotiate_highest_flow_format(struct vconn *vconn, const struct cls_rule *rule,
                              bool cookie_support, ovs_be64 cookie)
{
    int flow_format;

    if (preferred_flow_format != -1) {
        enum nx_flow_format min_format;

        min_format = ofputil_min_flow_format(rule, cookie_support, cookie);
        if (preferred_flow_format >= min_format) {
            set_flow_format(vconn, preferred_flow_format);
            return preferred_flow_format;
        }

        VLOG_WARN("%s: cannot use requested flow format %s for "
                  "specified flow", vconn_get_name(vconn),
                  ofputil_flow_format_to_string(min_format));
    }

    if (try_set_flow_format(vconn, NXFF_NXM)) {
        flow_format = NXFF_NXM;
    } else if (try_set_flow_format(vconn, NXFF_TUN_ID_FROM_COOKIE)) {
        flow_format = NXFF_TUN_ID_FROM_COOKIE;
    } else {
        flow_format = NXFF_OPENFLOW10;
    }

    VLOG_DBG("%s: negotiated flow format %s", vconn_get_name(vconn),
             ofputil_flow_format_to_string(flow_format));
    return flow_format;
}

static void
do_dump_flows__(int argc, char *argv[], bool aggregate)
{
    enum nx_flow_format flow_format;
    struct flow_stats_request fsr;
    struct ofpbuf *request;
    struct vconn *vconn;

    parse_ofp_flow_stats_request_str(&fsr, aggregate, argc > 2 ? argv[2] : "");

    open_vconn(argv[1], &vconn);
    flow_format = negotiate_highest_flow_format(vconn, &fsr.match, false, 0);
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

static void
do_flow_mod__(int argc OVS_UNUSED, char *argv[], uint16_t command)
{
    enum nx_flow_format flow_format;
    struct list requests;
    struct vconn *vconn;

    list_init(&requests);
    flow_format = NXFF_OPENFLOW10;
    parse_ofp_flow_mod_str(&requests, &flow_format, argc > 2 ? argv[2] : "",
                           command);

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
do_add_flows(int argc OVS_UNUSED, char *argv[])
{
    enum nx_flow_format flow_format;
    struct list requests;
    struct vconn *vconn;
    FILE *file;

    file = fopen(argv[2], "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", argv[2]);
    }

    list_init(&requests);
    flow_format = NXFF_OPENFLOW10;

    open_vconn(argv[1], &vconn);
    while (parse_ofp_add_flow_file(&requests, &flow_format, file)) {
        transact_multiple_noreply(vconn, &requests);
    }
    vconn_close(vconn);

    fclose(file);
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

        gettimeofday(&start, NULL);
        run(vconn_transact(vconn, ofpbuf_clone(request), &reply), "transact");
        gettimeofday(&end, NULL);

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
    gettimeofday(&start, NULL);
    for (i = 0; i < count; i++) {
        struct ofpbuf *request, *reply;
        struct ofp_header *rq_hdr;

        rq_hdr = make_openflow(message_size, OFPT_ECHO_REQUEST, &request);
        memset(rq_hdr + 1, 0, payload_size);
        run(vconn_transact(vconn, request, &reply), "transact");
        ofpbuf_delete(reply);
    }
    gettimeofday(&end, NULL);
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

/* Undocumented commands for unit testing. */

static void
do_parse_flows(int argc OVS_UNUSED, char *argv[])
{
    enum nx_flow_format flow_format;
    struct list packets;
    FILE *file;

    file = fopen(argv[1], "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", argv[2]);
    }

    list_init(&packets);
    flow_format = NXFF_OPENFLOW10;
    if (preferred_flow_format > 0) {
        flow_format = preferred_flow_format;
    }

    while (parse_ofp_add_flow_file(&packets, &flow_format, file)) {
        struct ofpbuf *packet, *next;

        LIST_FOR_EACH_SAFE (packet, next, list_node, &packets) {
            ofp_print(stdout, packet->data, packet->size, verbosity);
            list_remove(&packet->list_node);
            ofpbuf_delete(packet);
        }
    }
    fclose(file);
}

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
            printf("nx_pull_match() returned error %x\n", error);
        }

        ofpbuf_uninit(&nx_match);
    }
    ds_destroy(&in);
}

static const struct command all_commands[] = {
    { "show", 1, 1, do_show },
    { "status", 1, 2, do_status },
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
    { "dump-ports", 1, 2, do_dump_ports },
    { "mod-port", 3, 3, do_mod_port },
    { "probe", 1, 1, do_probe },
    { "ping", 1, 2, do_ping },
    { "benchmark", 3, 3, do_benchmark },
    { "help", 0, INT_MAX, do_help },

    /* Undocumented commands for testing. */
    { "parse-flows", 1, 1, do_parse_flows },
    { "parse-nx-match", 0, 0, do_parse_nx_match },

    { NULL, 0, 0, NULL },
};
