/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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
#include "colors.h"
#include "compiler.h"
#include "dirs.h"
#include "dp-packet.h"
#include "fatal-signal.h"
#include "nx-match.h"
#include "odp-util.h"
#include "ofp-version-opt.h"
#include "ofproto/ofproto.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/meta-flow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofp-parse.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/shash.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "pcap-file.h"
#include "poll-loop.h"
#include "random.h"
#include "sort.h"
#include "stream-ssl.h"
#include "socket-util.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(ofctl);

/* --bundle: Use OpenFlow 1.3+ bundle for making the flow table change atomic.
 * NOTE: If OpenFlow 1.3 or higher is not selected with the '-O' option,
 * OpenFlow 1.4 will be implicitly selected.  Also the flow mod will use
 * OpenFlow 1.4, so the semantics may be different (see the comment in
 * parse_options() for details).
 */
static bool bundle = false;

/* --color: Use color markers. */
static bool enable_color;

/* --read-only: Do not execute read only commands. */
static bool read_only;

/* --strict: Use strict matching for flow mod commands?  Additionally governs
 * use of nx_pull_match() instead of nx_pull_match_loose() in parse-nx-match.
 */
static bool strict;

/* --may-create: If true, the mod-group command creates a group that does not
 * yet exist; otherwise, such a command has no effect. */
static bool may_create;

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

/* --names, --no-names: Show port names in output and accept port numbers in
 * input.  (When neither is specified, the default is to accept port numbers
 * but, for backward compatibility, not to show them unless this is an
 * interactive console session.)  */
static int use_port_names = -1;
static const struct ofputil_port_map *ports_to_accept(const char *vconn_name);
static const struct ofputil_port_map *ports_to_show(const char *vconn_name);
static bool should_accept_ports(void);
static bool should_show_ports(void);

/* --stats, --no-stats: Show statistics in flow dumps? */
static int show_stats = 1;

static const struct ovs_cmdl_command *get_all_commands(void);

OVS_NO_RETURN static void usage(void);
static void parse_options(int argc, char *argv[]);

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

    daemon_become_new_user(false);
    if (read_only) {
        ovs_cmdl_run_command_read_only(&ctx, get_all_commands());
    } else {
        ovs_cmdl_run_command(&ctx, get_all_commands());
    }
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
        OPT_BUNDLE,
        OPT_COLOR,
        OPT_MAY_CREATE,
        OPT_READ_ONLY,
        DAEMON_OPTION_ENUMS,
        OFP_VERSION_OPTION_ENUMS,
        VLOG_OPTION_ENUMS,
        SSL_OPTION_ENUMS,
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
        {"names", no_argument, &use_port_names, 1},
        {"no-names", no_argument, &use_port_names, 0},
        {"stats", no_argument, &show_stats, 1},
        {"no-stats", no_argument, &show_stats, 0},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        {"help", no_argument, NULL, 'h'},
        {"option", no_argument, NULL, 'o'},
        {"bundle", no_argument, NULL, OPT_BUNDLE},
        {"color", optional_argument, NULL, OPT_COLOR},
        {"may-create", no_argument, NULL, OPT_MAY_CREATE},
        {"read-only", no_argument, NULL, OPT_READ_ONLY},
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

        case OPT_BUNDLE:
            bundle = true;
            break;

        case OPT_STRICT:
            strict = true;
            break;

        case OPT_READ_ONLY:
            read_only = true;
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

        case OPT_COLOR:
            if (optarg) {
                if (!strcasecmp(optarg, "always")
                    || !strcasecmp(optarg, "yes")
                    || !strcasecmp(optarg, "force")) {
                    enable_color = true;
                } else if (!strcasecmp(optarg, "never")
                           || !strcasecmp(optarg, "no")
                           || !strcasecmp(optarg, "none")) {
                    enable_color = false;
                } else if (!strcasecmp(optarg, "auto")
                           || !strcasecmp(optarg, "tty")
                           || !strcasecmp(optarg, "if-tty")) {
                    /* Determine whether we need colors, i.e. whether standard
                     * output is a tty. */
                    enable_color = is_stdout_a_tty();
                } else {
                    ovs_fatal(0, "incorrect value `%s' for --color", optarg);
                }
            } else {
                enable_color = is_stdout_a_tty();
            }
        break;

        case OPT_MAY_CREATE:
            may_create = true;
            break;

        DAEMON_OPTION_HANDLERS
        OFP_VERSION_OPTION_HANDLERS
        VLOG_OPTION_HANDLERS
        STREAM_SSL_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        case 0:
            break;

        default:
            abort();
        }
    }

    if (n_criteria) {
        /* Always do a final sort pass based on priority. */
        add_sort_criterion(SORT_DESC, "priority");
    }

    free(short_options);

    /* Implicit OpenFlow 1.4 with the '--bundle' option. */
    if (bundle && !(get_allowed_ofp_versions() &
                    ofputil_protocols_to_version_bitmap(OFPUTIL_P_OF13_UP))) {
        /* Add implicit allowance for OpenFlow 1.4. */
        add_allowed_ofp_versions(ofputil_protocols_to_version_bitmap(
                                     OFPUTIL_P_OF14_OXM));
        /* Remove all versions that do not support bundles. */
        mask_allowed_ofp_versions(ofputil_protocols_to_version_bitmap(
                                     OFPUTIL_P_OF13_UP));
    }
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

    colors_init(enable_color);
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
           "  dump-table-desc SWITCH      print table description (OF1.4+)\n"
           "  mod-port SWITCH IFACE ACT   modify port behavior\n"
           "  mod-table SWITCH MOD        modify flow table behavior\n"
           "      OF1.1/1.2 MOD: controller, continue, drop\n"
           "      OF1.4+ MOD: evict, noevict, vacancy:low,high, novacancy\n"
           "  get-frags SWITCH            print fragment handling behavior\n"
           "  set-frags SWITCH FRAG_MODE  set fragment handling behavior\n"
           "      FRAG_MODE: normal, drop, reassemble, nx-match\n"
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
           "  [--may-create] mod-group SWITCH GROUP   modify specific group\n"
           "  del-groups SWITCH [GROUP]   delete matching GROUPs\n"
           "  insert-buckets SWITCH [GROUP] add buckets to GROUP\n"
           "  remove-buckets SWITCH [GROUP] remove buckets from GROUP\n"
           "  dump-group-features SWITCH  print group features\n"
           "  dump-groups SWITCH [GROUP]  print group description\n"
           "  dump-group-stats SWITCH [GROUP]  print group statistics\n"
           "  queue-get-config SWITCH [PORT]  print queue config for PORT\n"
           "  add-meter SWITCH METER      add meter described by METER\n"
           "  mod-meter SWITCH METER      modify specific METER\n"
           "  del-meter SWITCH METER      delete METER\n"
           "  del-meters SWITCH           delete all meters\n"
           "  dump-meter SWITCH METER     print METER configuration\n"
           "  dump-meters SWITCH          print all meter configuration\n"
           "  meter-stats SWITCH [METER]  print meter statistics\n"
           "  meter-features SWITCH       print meter features\n"
           "  add-tlv-map SWITCH MAP      add TLV option MAPpings\n"
           "  del-tlv-map SWITCH [MAP] delete TLV option MAPpings\n"
           "  dump-tlv-map SWITCH      print TLV option mappings\n"
           "  dump-ipfix-bridge SWITCH    print ipfix stats of bridge\n"
           "  dump-ipfix-flow SWITCH      print flow ipfix of a bridge\n"
           "  ct-flush-zone SWITCH ZONE   flush conntrack entries in ZONE\n"
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
           "  --read-only                 do not execute read/write commands\n"
           "  --readd                     replace flows that haven't changed\n"
           "  -F, --flow-format=FORMAT    force particular flow format\n"
           "  -P, --packet-in-format=FRMT force particular packet in format\n"
           "  -m, --more                  be more verbose printing OpenFlow\n"
           "  --timestamp                 (monitor, snoop) print timestamps\n"
           "  -t, --timeout=SECS          give up after SECS seconds\n"
           "  --sort[=field]              sort in ascending order\n"
           "  --rsort[=field]             sort in descending order\n"
           "  --names                     show port names instead of numbers\n"
           "  --unixctl=SOCKET            set control socket name\n"
           "  --color[=always|never|auto] control use of color in output\n"
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
    run(vconn_send_block(vconn, buffer), "failed to send packet to switch");
}

static void
dump_transaction(struct vconn *vconn, struct ofpbuf *request)
{
    const struct ofp_header *oh = request->data;
    if (ofpmsg_is_stat_request(oh)) {
        ovs_be32 send_xid = oh->xid;
        enum ofpraw request_raw;
        enum ofpraw reply_raw;
        bool done = false;

        ofpraw_decode_partial(&request_raw, request->data, request->size);
        reply_raw = ofpraw_stats_request_to_reply(request_raw, oh->version);

        send_openflow_buffer(vconn, request);
        while (!done) {
            ovs_be32 recv_xid;
            struct ofpbuf *reply;

            run(vconn_recv_block(vconn, &reply),
                "OpenFlow packet receive failed");
            recv_xid = ((struct ofp_header *) reply->data)->xid;
            if (send_xid == recv_xid) {
                enum ofpraw raw;

                ofp_print(stdout, reply->data, reply->size,
                          ports_to_show(vconn_get_name(vconn)), verbosity + 1);

                ofpraw_decode(&raw, reply->data);
                if (ofptype_from_ofpraw(raw) == OFPTYPE_ERROR) {
                    done = true;
                } else if (raw == reply_raw) {
                    done = !ofpmp_more(reply->data);
                } else {
                    ovs_fatal(0, "received bad reply: %s",
                              ofp_to_string(
                                  reply->data, reply->size,
                                  ports_to_show(vconn_get_name(vconn)),
                                  verbosity + 1));
                }
            } else {
                VLOG_DBG("received reply with xid %08"PRIx32" "
                         "!= expected %08"PRIx32, recv_xid, send_xid);
            }
            ofpbuf_delete(reply);
        }
    } else {
        struct ofpbuf *reply;

        run(vconn_transact(vconn, request, &reply), "talking to %s",
            vconn_get_name(vconn));
        ofp_print(stdout, reply->data, reply->size,
                  ports_to_show(vconn_get_name(vconn)), verbosity + 1);
        ofpbuf_delete(reply);
    }
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

/* Sends all of the 'requests', which should be requests that only have replies
 * if an error occurs, and waits for them to succeed or fail.  If an error does
 * occur, prints it and exits with an error.
 *
 * Destroys all of the 'requests'. */
static void
transact_multiple_noreply(struct vconn *vconn, struct ovs_list *requests)
{
    struct ofpbuf *reply;

    run(vconn_transact_multiple_noreply(vconn, requests, &reply),
        "talking to %s", vconn_get_name(vconn));
    if (reply) {
        ofp_print(stderr, reply->data, reply->size,
                  ports_to_show(vconn_get_name(vconn)), verbosity + 2);
        exit(1);
    }
    ofpbuf_delete(reply);
}

/* Frees the error messages as they are printed. */
static void
bundle_print_errors(struct ovs_list *errors, struct ovs_list *requests,
                    const char *vconn_name)
{
    struct ofpbuf *error, *next;
    struct ofpbuf *bmsg;

    INIT_CONTAINER(bmsg, requests, list_node);

    LIST_FOR_EACH_SAFE (error, next, list_node, errors) {
        const struct ofp_header *error_oh = error->data;
        ovs_be32 error_xid = error_oh->xid;
        enum ofperr ofperr;
        struct ofpbuf payload;

        ofperr = ofperr_decode_msg(error_oh, &payload);
        if (!ofperr) {
            fprintf(stderr, "***decode error***");
        } else {
            /* Default to the likely truncated message. */
            const struct ofp_header *ofp_msg = payload.data;
            size_t msg_len = payload.size;

            /* Find the failing message from the requests list to be able to
             * dump the whole message.  We assume the errors are returned in
             * the same order as in which the messages are sent to get O(n)
             * rather than O(n^2) processing here.  If this heuristics fails we
             * may print the truncated hexdumps instead. */
            LIST_FOR_EACH_CONTINUE (bmsg, list_node, requests) {
                const struct ofp_header *oh = bmsg->data;

                if (oh->xid == error_xid) {
                    ofp_msg = oh;
                    msg_len = bmsg->size;
                    break;
                }
            }
            fprintf(stderr, "Error %s for: ", ofperr_get_name(ofperr));
            ofp_print(stderr, ofp_msg, msg_len, ports_to_show(vconn_name),
                      verbosity + 1);
        }
        ofpbuf_uninit(&payload);
        ofpbuf_delete(error);
    }
    fflush(stderr);
}

static void
bundle_transact(struct vconn *vconn, struct ovs_list *requests, uint16_t flags)
{
    struct ovs_list errors;
    int retval = vconn_bundle_transact(vconn, requests, flags, &errors);

    bundle_print_errors(&errors, requests, vconn_get_name(vconn));

    if (retval) {
        ovs_fatal(retval, "talking to %s", vconn_get_name(vconn));
    }
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

    ovs_list_init(&requests);
    ovs_list_push_back(&requests, &request->list_node);
    transact_multiple_noreply(vconn, &requests);
}

static void
fetch_switch_config(struct vconn *vconn, struct ofputil_switch_config *config)
{
    struct ofpbuf *request;
    struct ofpbuf *reply;
    enum ofptype type;

    request = ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST,
                           vconn_get_version(vconn), 0);
    run(vconn_transact(vconn, request, &reply),
        "talking to %s", vconn_get_name(vconn));

    if (ofptype_decode(&type, reply->data)
        || type != OFPTYPE_GET_CONFIG_REPLY) {
        ovs_fatal(0, "%s: bad reply to config request", vconn_get_name(vconn));
    }
    ofputil_decode_get_config_reply(reply->data, config);
    ofpbuf_delete(reply);
}

static void
set_switch_config(struct vconn *vconn,
                  const struct ofputil_switch_config *config)
{
    enum ofp_version version = vconn_get_version(vconn);
    transact_noreply(vconn, ofputil_encode_set_config(config, version));
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
    ofp_print(stdout, reply->data, reply->size, NULL, verbosity + 1);
    ofpbuf_delete(reply);

    if (!has_ports) {
        request = ofputil_encode_port_desc_stats_request(version, OFPP_ANY);
        dump_transaction(vconn, request);
    }
    dump_trivial_transaction(vconn_name, OFPRAW_OFPT_GET_CONFIG_REQUEST);
    vconn_close(vconn);
}

static void
ofctl_dump_desc(struct ovs_cmdl_context *ctx)
{
    dump_trivial_transaction(ctx->argv[1], OFPRAW_OFPST_DESC_REQUEST);
}

static void
ofctl_dump_tables(struct ovs_cmdl_context *ctx)
{
    dump_trivial_transaction(ctx->argv[1], OFPRAW_OFPST_TABLE_REQUEST);
}

static void
ofctl_dump_table_features(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;

    open_vconn(ctx->argv[1], &vconn);
    request = ofputil_encode_table_features_request(vconn_get_version(vconn));

    /* The following is similar to dump_trivial_transaction(), but it
     * maintains the previous 'ofputil_table_features' from one stats reply
     * message to the next, which allows duplication to be eliminated in the
     * output across messages.  Otherwise the output is much larger and harder
     * to read, because only 17 or so ofputil_table_features elements fit in a
     * single 64 kB OpenFlow message and therefore you get a ton of repetition
     * (every 17th element is printed in full instead of abbreviated). */

    const struct ofp_header *request_oh = request->data;
    ovs_be32 send_xid = request_oh->xid;
    bool done = false;

    struct ofputil_table_features prev;
    int n = 0;

    send_openflow_buffer(vconn, request);
    while (!done) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            enum ofptype type;
            enum ofperr error;
            error = ofptype_decode(&type, reply->data);
            if (error) {
                ovs_fatal(0, "decode error: %s", ofperr_get_name(error));
            } else if (type == OFPTYPE_ERROR) {
                ofp_print(stdout, reply->data, reply->size, NULL,
                          verbosity + 1);
                done = true;
            } else if (type == OFPTYPE_TABLE_FEATURES_STATS_REPLY) {
                done = !ofpmp_more(reply->data);
                for (;;) {
                    struct ofputil_table_features tf;
                    int retval;

                    retval = ofputil_decode_table_features(reply, &tf, true);
                    if (retval) {
                        if (retval != EOF) {
                            ovs_fatal(0, "decode error: %s",
                                      ofperr_get_name(retval));
                        }
                        break;
                    }

                    struct ds s = DS_EMPTY_INITIALIZER;
                    ofp_print_table_features(&s, &tf, n ? &prev : NULL,
                                             NULL, NULL);
                    puts(ds_cstr(&s));
                    ds_destroy(&s);

                    prev = tf;
                    n++;
                }
            } else {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(reply->data, reply->size,
                                        ports_to_show(ctx->argv[1]),
                                        verbosity + 1));
            }
        } else {
            VLOG_DBG("received reply with xid %08"PRIx32" "
                     "!= expected %08"PRIx32, recv_xid, send_xid);
        }
        ofpbuf_delete(reply);
    }

    vconn_close(vconn);
}

static void
ofctl_dump_table_desc(struct ovs_cmdl_context *ctx)
{
    struct ofpbuf *request;
    struct vconn *vconn;

    open_vconn(ctx->argv[1], &vconn);
    request = ofputil_encode_table_desc_request(vconn_get_version(vconn));
    if (request) {
        dump_transaction(vconn, request);
    }

    vconn_close(vconn);
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

struct port_iterator {
    struct vconn *vconn;

    enum { PI_FEATURES, PI_PORT_DESC } variant;
    struct ofpbuf *reply;
    ovs_be32 send_xid;
    bool more;
};

static void
port_iterator_fetch_port_desc(struct port_iterator *pi)
{
    pi->variant = PI_PORT_DESC;
    pi->more = true;

    struct ofpbuf *rq = ofputil_encode_port_desc_stats_request(
        vconn_get_version(pi->vconn), OFPP_ANY);
    pi->send_xid = ((struct ofp_header *) rq->data)->xid;
    send_openflow_buffer(pi->vconn, rq);
}

static void
port_iterator_fetch_features(struct port_iterator *pi)
{
    pi->variant = PI_FEATURES;

    /* Fetch the switch's ofp_switch_features. */
    enum ofp_version version = vconn_get_version(pi->vconn);
    struct ofpbuf *rq = ofpraw_alloc(OFPRAW_OFPT_FEATURES_REQUEST, version, 0);
    run(vconn_transact(pi->vconn, rq, &pi->reply),
        "talking to %s", vconn_get_name(pi->vconn));

    enum ofptype type;
    if (ofptype_decode(&type, pi->reply->data)
        || type != OFPTYPE_FEATURES_REPLY) {
        ovs_fatal(0, "%s: received bad features reply",
                  vconn_get_name(pi->vconn));
    }
    if (!ofputil_switch_features_has_ports(pi->reply)) {
        /* The switch features reply does not contain a complete list of ports.
         * Probably, there are more ports than will fit into a single 64 kB
         * OpenFlow message.  Use OFPST_PORT_DESC to get a complete list of
         * ports. */
        ofpbuf_delete(pi->reply);
        pi->reply = NULL;
        port_iterator_fetch_port_desc(pi);
        return;
    }

    struct ofputil_switch_features features;
    enum ofperr error = ofputil_pull_switch_features(pi->reply, &features);
    if (error) {
        ovs_fatal(0, "%s: failed to decode features reply (%s)",
                  vconn_get_name(pi->vconn), ofperr_to_string(error));
    }
}

/* Initializes 'pi' to prepare for iterating through all of the ports on the
 * OpenFlow switch to which 'vconn' is connected.
 *
 * During iteration, the client should not make other use of 'vconn', because
 * that can cause other messages to be interleaved with the replies used by the
 * iterator and thus some ports may be missed or a hang can occur. */
static void
port_iterator_init(struct port_iterator *pi, struct vconn *vconn)
{
    memset(pi, 0, sizeof *pi);
    pi->vconn = vconn;
    if (vconn_get_version(vconn) < OFP13_VERSION) {
        port_iterator_fetch_features(pi);
    } else {
        port_iterator_fetch_port_desc(pi);
    }
}

/* Obtains the next port from 'pi'.  On success, initializes '*pp' with the
 * port's details and returns true, otherwise (if all the ports have already
 * been seen), returns false.  */
static bool
port_iterator_next(struct port_iterator *pi, struct ofputil_phy_port *pp)
{
    for (;;) {
        if (pi->reply) {
            int retval = ofputil_pull_phy_port(vconn_get_version(pi->vconn),
                                               pi->reply, pp);
            if (!retval) {
                return true;
            } else if (retval != EOF) {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(pi->reply->data, pi->reply->size,
                                        NULL, verbosity + 1));
            }
        }

        if (pi->variant == PI_FEATURES || !pi->more) {
            return false;
        }

        ovs_be32 recv_xid;
        do {
            ofpbuf_delete(pi->reply);
            run(vconn_recv_block(pi->vconn, &pi->reply),
                "OpenFlow receive failed");
            recv_xid = ((struct ofp_header *) pi->reply->data)->xid;
        } while (pi->send_xid != recv_xid);

        struct ofp_header *oh = pi->reply->data;
        enum ofptype type;
        if (ofptype_pull(&type, pi->reply)
            || type != OFPTYPE_PORT_DESC_STATS_REPLY) {
            ovs_fatal(0, "received bad reply: %s",
                      ofp_to_string(pi->reply->data, pi->reply->size, NULL,
                                    verbosity + 1));
        }

        pi->more = (ofpmp_flags(oh) & OFPSF_REPLY_MORE) != 0;
    }
}

/* Destroys iterator 'pi'. */
static void
port_iterator_destroy(struct port_iterator *pi)
{
    if (pi) {
        while (pi->variant == PI_PORT_DESC && pi->more) {
            /* Drain vconn's queue of any other replies for this request. */
            struct ofputil_phy_port pp;
            port_iterator_next(pi, &pp);
        }

        ofpbuf_delete(pi->reply);
    }
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
    bool found = false;

    /* Try to interpret the argument as a port number. */
    if (!str_to_ofp(port_name, &port_no)) {
        port_no = OFPP_NONE;
    }

    /* OpenFlow 1.0, 1.1, and 1.2 put the list of ports in the
     * OFPT_FEATURES_REPLY message.  OpenFlow 1.3 and later versions put it
     * into the OFPST_PORT_DESC reply.  Try it the correct way. */
    open_vconn(vconn_name, &vconn);
    struct port_iterator pi;
    for (port_iterator_init(&pi, vconn); port_iterator_next(&pi, pp); ) {
        if (port_no != OFPP_NONE
            ? port_no == pp->port_no
            : !strcmp(pp->name, port_name)) {
            found = true;
            break;
        }
    }
    port_iterator_destroy(&pi);
    vconn_close(vconn);

    if (!found) {
        ovs_fatal(0, "%s: couldn't find port `%s'", vconn_name, port_name);
    }
}

static const struct ofputil_port_map *
get_port_map(const char *vconn_name)
{
    static struct shash port_maps = SHASH_INITIALIZER(&port_maps);
    struct ofputil_port_map *map = shash_find_data(&port_maps, vconn_name);
    if (!map) {
        map = xmalloc(sizeof *map);
        ofputil_port_map_init(map);
        shash_add(&port_maps, vconn_name, map);

        if (!strchr(vconn_name, ':') || !vconn_verify_name(vconn_name)) {
            /* For an active vconn (which includes a vconn constructed from a
             * bridge name), connect to it and pull down the port name-number
             * mapping. */
            struct vconn *vconn;
            open_vconn(vconn_name, &vconn);

            struct port_iterator pi;
            struct ofputil_phy_port pp;
            for (port_iterator_init(&pi, vconn);
                 port_iterator_next(&pi, &pp); ) {
                ofputil_port_map_put(map, pp.port_no, pp.name);
            }
            port_iterator_destroy(&pi);

            vconn_close(vconn);
        } else {
            /* Don't bother with passive vconns, since it could take a long
             * time for the remote to try to connect to us.  Don't bother with
             * invalid vconn names either. */
        }
    }
    return map;
}

static const struct ofputil_port_map *
ports_to_accept(const char *vconn_name)
{
    return should_accept_ports() ? get_port_map(vconn_name) : NULL;
}

static const struct ofputil_port_map *
ports_to_show(const char *vconn_name)
{
    return should_show_ports() ? get_port_map(vconn_name) : NULL;
}

/* We accept port names unless the feature is turned off explicitly. */
static bool
should_accept_ports(void)
{
    return use_port_names != 0;
}

/* We show port names only if the feature is turned on explicitly, or if we're
 * interacting with a user on the console. */
static bool
should_show_ports(void)
{
    static int interactive = -1;
    if (interactive == -1) {
        interactive = isatty(STDOUT_FILENO);
    }

    return use_port_names > 0 || (use_port_names == -1 && interactive);
}

/* Returns the port number corresponding to 'port_name' (which may be a port
 * name or number) within the switch 'vconn_name'. */
static ofp_port_t
str_to_port_no(const char *vconn_name, const char *port_name)
{
    ofp_port_t port_no;
    if (ofputil_port_from_string(port_name, NULL, &port_no) ||
        ofputil_port_from_string(port_name, ports_to_accept(vconn_name),
                                 &port_no)) {
        return port_no;
    }
    ovs_fatal(0, "%s: unknown port `%s'", vconn_name, port_name);
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
            char *s = ofp_to_string(reply->data, reply->size, NULL, 2);
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
                   struct ofputil_flow_stats_request *fsr,
                   enum ofputil_protocol *protocolp)
{
    const char *vconn_name = argv[1];
    enum ofputil_protocol usable_protocols, protocol;
    struct vconn *vconn;
    char *error;

    const char *match = argc > 2 ? argv[2] : "";
    const struct ofputil_port_map *port_map
        = *match ? ports_to_accept(vconn_name) : NULL;
    error = parse_ofp_flow_stats_request_str(fsr, aggregate, match,
                                             port_map, &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    protocol = open_vconn(vconn_name, &vconn);
    *protocolp = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);
    return vconn;
}

static void
ofctl_dump_flows__(int argc, char *argv[], bool aggregate)
{
    struct ofputil_flow_stats_request fsr;
    enum ofputil_protocol protocol;
    struct vconn *vconn;

    vconn = prepare_dump_flows(argc, argv, aggregate, &fsr, &protocol);
    dump_transaction(vconn, ofputil_encode_flow_stats_request(&fsr, protocol));
    vconn_close(vconn);
}

static void
get_match_field(const struct mf_field *field, const struct match *match,
                union mf_value *value)
{
    if (!match->tun_md.valid || (field->id < MFF_TUN_METADATA0 ||
                                 field->id >= MFF_TUN_METADATA0 +
                                              TUN_METADATA_NUM_OPTS)) {
        mf_get_value(field, &match->flow, value);
    } else {
        const struct tun_metadata_loc *loc = &match->tun_md.entry[field->id -
                                                         MFF_TUN_METADATA0].loc;

        /* Since we don't have a tunnel mapping table, extract the value
         * from the locally allocated location in the match. */
        memset(value, 0, field->n_bytes - loc->len);
        memcpy(value->tun_metadata + field->n_bytes - loc->len,
               match->flow.tunnel.metadata.opts.u8 + loc->c.offset, loc->len);
    }
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

            ina = mf_are_prereqs_ok(f, &a->flow, NULL)
                && !mf_is_all_wild(f, &a->wc);
            inb = mf_are_prereqs_ok(f, &b->flow, NULL)
                && !mf_is_all_wild(f, &b->wc);
            if (ina != inb) {
                /* Skip the test for sc->order, so that missing fields always
                 * sort to the end whether we're sorting in ascending or
                 * descending order. */
                return ina ? -1 : 1;
            } else {
                union mf_value aval, bval;

                get_match_field(f, a, &aval);
                get_match_field(f, b, &bval);
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
    if (!n_criteria && !should_show_ports() && show_stats) {
        ofctl_dump_flows__(ctx->argc, ctx->argv, false);
        return;
    } else {
        struct ofputil_flow_stats_request fsr;
        enum ofputil_protocol protocol;
        struct vconn *vconn;

        vconn = prepare_dump_flows(ctx->argc, ctx->argv, false,
                                   &fsr, &protocol);

        struct ofputil_flow_stats *fses;
        size_t n_fses;
        run(vconn_dump_flows(vconn, &fsr, protocol, &fses, &n_fses),
            "dump flows");

        qsort(fses, n_fses, sizeof *fses, compare_flows);

        struct ds s = DS_EMPTY_INITIALIZER;
        for (size_t i = 0; i < n_fses; i++) {
            ds_clear(&s);
            ofp_print_flow_stats(&s, &fses[i], ports_to_show(ctx->argv[1]),
                                 show_stats);
            printf(" %s\n", ds_cstr(&s));
        }
        ds_destroy(&s);

        for (size_t i = 0; i < n_fses; i++) {
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
    dump_transaction(vconn, request);
    vconn_close(vconn);
}

static void
ofctl_queue_get_config(struct ovs_cmdl_context *ctx)
{
    const char *vconn_name = ctx->argv[1];
    const char *port_name = ctx->argc > 2 ? ctx->argv[2] : "any";
    ofp_port_t port = str_to_port_no(vconn_name, port_name);
    const char *queue_name = ctx->argc > 3 ? ctx->argv[3] : "all";
    uint32_t queue = (!strcasecmp(queue_name, "all")
                      ? OFPQ_ALL
                      : atoi(queue_name));
    struct vconn *vconn;

    enum ofputil_protocol protocol = open_vconn(vconn_name, &vconn);
    enum ofp_version version = ofputil_protocol_to_ofp_version(protocol);
    if (port == OFPP_ANY && version == OFP10_VERSION) {
        /* The user requested all queues on all ports.  OpenFlow 1.0 only
         * supports getting queues for an individual port, so to implement the
         * user's request we have to get a list of all the ports.
         *
         * We use a second vconn to avoid having to accumulate a list of all of
         * the ports. */
        struct vconn *vconn2;
        enum ofputil_protocol protocol2 = open_vconn(vconn_name, &vconn2);
        enum ofp_version version2 = ofputil_protocol_to_ofp_version(protocol2);

        struct port_iterator pi;
        struct ofputil_phy_port pp;
        for (port_iterator_init(&pi, vconn); port_iterator_next(&pi, &pp); ) {
            if (ofp_to_u16(pp.port_no) < ofp_to_u16(OFPP_MAX)) {
                dump_transaction(vconn2,
                                 ofputil_encode_queue_get_config_request(
                                     version2, pp.port_no, queue));
            }
        }
        port_iterator_destroy(&pi);
        vconn_close(vconn2);
    } else {
        dump_transaction(vconn, ofputil_encode_queue_get_config_request(
                             version, port, queue));
    }
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
bundle_flow_mod__(const char *remote, struct ofputil_flow_mod *fms,
                  size_t n_fms, enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol protocol;
    struct vconn *vconn;
    struct ovs_list requests;
    size_t i;

    ovs_list_init(&requests);

    /* Bundles need OpenFlow 1.3+. */
    usable_protocols &= OFPUTIL_P_OF13_UP;
    protocol = open_vconn_for_flow_mod(remote, &vconn, usable_protocols);

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];
        struct ofpbuf *request = ofputil_encode_flow_mod(fm, protocol);

        ovs_list_push_back(&requests, &request->list_node);
        free(CONST_CAST(struct ofpact *, fm->ofpacts));
    }

    bundle_transact(vconn, &requests, OFPBF_ORDERED | OFPBF_ATOMIC);
    ofpbuf_list_delete(&requests);
    vconn_close(vconn);
}

static void
ofctl_flow_mod__(const char *remote, struct ofputil_flow_mod *fms,
                 size_t n_fms, enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol protocol;
    struct vconn *vconn;
    size_t i;

    if (bundle) {
        bundle_flow_mod__(remote, fms, n_fms, usable_protocols);
        return;
    }

    protocol = open_vconn_for_flow_mod(remote, &vconn, usable_protocols);

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];

        transact_noreply(vconn, ofputil_encode_flow_mod(fm, protocol));
        free(CONST_CAST(struct ofpact *, fm->ofpacts));
    }
    vconn_close(vconn);
}

static void
ofctl_flow_mod_file(int argc OVS_UNUSED, char *argv[], int command)
{
    enum ofputil_protocol usable_protocols;
    struct ofputil_flow_mod *fms = NULL;
    size_t n_fms = 0;
    char *error;

    if (command == OFPFC_ADD) {
        /* Allow the file to specify a mix of commands.  If none specified at
         * the beginning of any given line, then the default is OFPFC_ADD, so
         * this is backwards compatible. */
        command = -2;
    }
    error = parse_ofp_flow_mod_file(argv[2], ports_to_accept(argv[1]), command,
                                    &fms, &n_fms, &usable_protocols);
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

        error = parse_ofp_flow_mod_str(&fm, argc > 2 ? argv[2] : "",
                                       ports_to_accept(argv[1]), command,
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

static bool
set_packet_in_format(struct vconn *vconn,
                     enum nx_packet_in_format packet_in_format,
                     bool must_succeed)
{
    struct ofpbuf *spif;

    spif = ofputil_make_set_packet_in_format(vconn_get_version(vconn),
                                             packet_in_format);
    if (must_succeed) {
        transact_noreply(vconn, spif);
    } else {
        struct ofpbuf *reply;

        run(vconn_transact_noreply(vconn, spif, &reply),
            "talking to %s", vconn_get_name(vconn));
        if (reply) {
            char *s = ofp_to_string(reply->data, reply->size, NULL, 2);
            VLOG_DBG("%s: failed to set packet in format to nx_packet_in, "
                     "controller replied: %s.",
                     vconn_get_name(vconn), s);
            free(s);
            ofpbuf_delete(reply);

            return false;
        } else {
            VLOG_DBG("%s: using user-specified packet in format %s",
                     vconn_get_name(vconn),
                     ofputil_packet_in_format_to_string(packet_in_format));
        }
    }
    return true;
}

static int
monitor_set_invalid_ttl_to_controller(struct vconn *vconn)
{
    struct ofputil_switch_config config;

    fetch_switch_config(vconn, &config);
    if (!config.invalid_ttl_to_controller) {
        config.invalid_ttl_to_controller = 1;
        set_switch_config(vconn, &config);

        /* Then retrieve the configuration to see if it really took.  OpenFlow
         * has ill-defined error reporting for bad flags, so this is about the
         * best we can do. */
        fetch_switch_config(vconn, &config);
        if (!config.invalid_ttl_to_controller) {
            ovs_fatal(0, "setting invalid_ttl_to_controller failed (this "
                      "switch probably doesn't support this flag)");
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
        ofp_print(stderr, msg->data, msg->size,
                  ports_to_show(vconn_get_name(vconn)), verbosity);

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

static void
unixctl_packet_out(struct unixctl_conn *conn, int OVS_UNUSED argc,
                   const char *argv[], void *vconn_)
{
    struct vconn *vconn = vconn_;
    enum ofputil_protocol protocol
        = ofputil_protocol_from_ofp_version(vconn_get_version(vconn));
    struct ds reply = DS_EMPTY_INITIALIZER;
    bool ok = true;

    enum ofputil_protocol usable_protocols;
    struct ofputil_packet_out po;
    char *error_msg;

    error_msg = parse_ofp_packet_out_str(
        &po, argv[1], ports_to_accept(vconn_get_name(vconn)),
        &usable_protocols);
    if (error_msg) {
        ds_put_format(&reply, "%s\n", error_msg);
        free(error_msg);
        ok = false;
    }

    if (ok && !(usable_protocols & protocol)) {
        ds_put_format(&reply, "PACKET_OUT actions are incompatible with the OpenFlow connection.\n");
        ok = false;
    }

    if (ok) {
        struct ofpbuf *msg = ofputil_encode_packet_out(&po, protocol);

        ofp_print(stderr, msg->data, msg->size,
                  ports_to_show(vconn_get_name(vconn)), verbosity);

        int error = vconn_send_block(vconn, msg);
        if (error) {
            ofpbuf_delete(msg);
            ds_put_format(&reply, "%s\n", ovs_strerror(error));
            ok = false;
        }
    }

    if (ok) {
        unixctl_command_reply(conn, ds_cstr(&reply));
    } else {
        unixctl_command_reply_error(conn, ds_cstr(&reply));
    }
    ds_destroy(&reply);

    if (!error_msg) {
        free(CONST_CAST(void *, po.packet));
        free(po.ofpacts);
    }
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

/* Prints to stderr all of the messages received on 'vconn'.
 *
 * Iff 'reply_to_echo_requests' is true, sends a reply to any echo request
 * received on 'vconn'.
 *
 * If 'resume_continuations' is true, sends an NXT_RESUME in reply to any
 * NXT_PACKET_IN2 that includes a continuation. */
static void
monitor_vconn(struct vconn *vconn, bool reply_to_echo_requests,
              bool resume_continuations)
{
    struct barrier_aux barrier_aux = { vconn, NULL };
    struct unixctl_server *server;
    bool exiting = false;
    bool blocked = false;
    int error;

    daemon_save_fd(STDERR_FILENO);
    daemonize_start(false);
    error = unixctl_server_create(unixctl_path, &server);
    if (error) {
        ovs_fatal(error, "failed to create unixctl server");
    }
    unixctl_command_register("exit", "", 0, 0, ofctl_exit, &exiting);
    unixctl_command_register("ofctl/send", "OFMSG...", 1, INT_MAX,
                             ofctl_send, vconn);
    unixctl_command_register("ofctl/packet-out", "\"in_port=<port> packet=<hex data> actions=...\"", 1, 1,
                             unixctl_packet_out, vconn);
    unixctl_command_register("ofctl/barrier", "", 0, 0,
                             ofctl_barrier, &barrier_aux);
    unixctl_command_register("ofctl/set-output-file", "FILE", 1, 1,
                             ofctl_set_output_file, NULL);

    unixctl_command_register("ofctl/block", "", 0, 0, ofctl_block, &blocked);
    unixctl_command_register("ofctl/unblock", "", 0, 0, ofctl_unblock,
                             &blocked);

    daemonize_complete();

    enum ofp_version version = vconn_get_version(vconn);
    enum ofputil_protocol protocol
        = ofputil_protocol_from_ofp_version(version);

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
            ofp_print(stderr, b->data, b->size,
                      ports_to_show(vconn_get_name(vconn)), verbosity + 2);
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

            case OFPTYPE_PACKET_IN:
                if (resume_continuations) {
                    struct ofputil_packet_in pin;
                    struct ofpbuf continuation;

                    error = ofputil_decode_packet_in(b->data, true, NULL, NULL,
                                                     &pin, NULL, NULL,
                                                     &continuation);
                    if (error) {
                        fprintf(stderr, "decoding packet-in failed: %s",
                                ofperr_to_string(error));
                    } else if (continuation.size) {
                        struct ofpbuf *reply;

                        reply = ofputil_encode_resume(&pin, &continuation,
                                                      protocol);

                        fprintf(stderr, "send: ");
                        ofp_print(stderr, reply->data, reply->size,
                                  ports_to_show(vconn_get_name(vconn)),
                                  verbosity + 2);
                        fflush(stderr);

                        retval = vconn_send_block(vconn, reply);
                        if (retval) {
                            ovs_fatal(retval, "failed to send NXT_RESUME");
                        }
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

    /* If the user wants the invalid_ttl_to_controller feature, limit the
     * OpenFlow versions to those that support that feature.  (Support in
     * OpenFlow 1.0 is an Open vSwitch extension.) */
    for (i = 2; i < ctx->argc; i++) {
        if (!strcmp(ctx->argv[i], "invalid_ttl")) {
            uint32_t usable_versions = ((1u << OFP10_VERSION) |
                                        (1u << OFP11_VERSION) |
                                        (1u << OFP12_VERSION));
            uint32_t allowed_versions = get_allowed_ofp_versions();
            if (!(allowed_versions & usable_versions)) {
                struct ds versions = DS_EMPTY_INITIALIZER;
                ofputil_format_version_bitmap_names(&versions,
                                                    usable_versions);
                ovs_fatal(0, "invalid_ttl requires one of the OpenFlow "
                          "versions %s but none is enabled (use -O)",
                          ds_cstr(&versions));
            }
            mask_allowed_ofp_versions(usable_versions);
            break;
        }
    }

    open_vconn(ctx->argv[1], &vconn);
    bool resume_continuations = false;
    for (i = 2; i < ctx->argc; i++) {
        const char *arg = ctx->argv[i];

        if (isdigit((unsigned char) *arg)) {
            struct ofputil_switch_config config;

            fetch_switch_config(vconn, &config);
            config.miss_send_len = atoi(arg);
            set_switch_config(vconn, &config);
        } else if (!strcmp(arg, "invalid_ttl")) {
            monitor_set_invalid_ttl_to_controller(vconn);
        } else if (!strncmp(arg, "watch:", 6)) {
            struct ofputil_flow_monitor_request fmr;
            struct ofpbuf *msg;
            char *error;

            error = parse_flow_monitor_request(&fmr, arg + 6,
                                               ports_to_accept(ctx->argv[1]),
                                               &usable_protocols);
            if (error) {
                ovs_fatal(0, "%s", error);
            }

            msg = ofpbuf_new(0);
            ofputil_append_flow_monitor_request(&fmr, msg);
            dump_transaction(vconn, msg);
            fflush(stdout);
        } else if (!strcmp(arg, "resume")) {
            /* This option is intentionally undocumented because it is meant
             * only for testing. */
            resume_continuations = true;

            /* Set miss_send_len to ensure that we get packet-ins. */
            struct ofputil_switch_config config;
            fetch_switch_config(vconn, &config);
            config.miss_send_len = UINT16_MAX;
            set_switch_config(vconn, &config);
        } else {
            ovs_fatal(0, "%s: unsupported \"monitor\" argument", arg);
        }
    }

    if (preferred_packet_in_format >= 0) {
        /* A particular packet-in format was requested, so we must set it. */
        set_packet_in_format(vconn, preferred_packet_in_format, true);
    } else {
        /* Otherwise, we always prefer NXT_PACKET_IN2. */
        if (!set_packet_in_format(vconn, NXPIF_NXT_PACKET_IN2, false)) {
            /* We can't get NXT_PACKET_IN2.  For OpenFlow 1.0 only, request
             * NXT_PACKET_IN.  (Before 2.6, Open vSwitch will accept a request
             * for NXT_PACKET_IN with OF1.1+, but even after that it still
             * sends packet-ins in the OpenFlow native format.) */
            if (vconn_get_version(vconn) == OFP10_VERSION) {
                set_packet_in_format(vconn, NXPIF_NXT_PACKET_IN, false);
            }
        }
    }

    monitor_vconn(vconn, true, resume_continuations);
}

static void
ofctl_snoop(struct ovs_cmdl_context *ctx)
{
    struct vconn *vconn;

    open_vconn__(ctx->argv[1], SNOOP, &vconn);
    monitor_vconn(vconn, false, false);
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
    dump_transaction(vconn, request);
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
    dump_transaction(vconn, request);
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
    enum ofputil_protocol usable_protocols;
    enum ofputil_protocol protocol;
    struct ofputil_packet_out po;
    struct vconn *vconn;
    struct ofpbuf *opo;
    char *error;

    match_init_catchall(&po.flow_metadata);
    /* Use the old syntax when more than 4 arguments are given. */
    if (ctx->argc > 4) {
        struct ofpbuf ofpacts;
        int i;

        ofpbuf_init(&ofpacts, 64);
        error = ofpacts_parse_actions(ctx->argv[3],
                                      ports_to_accept(ctx->argv[1]), &ofpacts,
                                      &usable_protocols);
        if (error) {
            ovs_fatal(0, "%s", error);
        }

        po.buffer_id = UINT32_MAX;
        match_set_in_port(&po.flow_metadata,
                          str_to_port_no(ctx->argv[1], ctx->argv[2]));
        po.ofpacts = ofpacts.data;
        po.ofpacts_len = ofpacts.size;
        po.flow_metadata.flow.packet_type = htonl(PT_ETH);

        protocol = open_vconn_for_flow_mod(ctx->argv[1], &vconn,
                                           usable_protocols);
        for (i = 4; i < ctx->argc; i++) {
            struct dp_packet *packet;
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
    } else if (ctx->argc == 3) {
        error = parse_ofp_packet_out_str(&po, ctx->argv[2],
                                         ports_to_accept(ctx->argv[1]),
                                         &usable_protocols);
        if (error) {
            ovs_fatal(0, "%s", error);
        }
        protocol = open_vconn_for_flow_mod(ctx->argv[1], &vconn,
                                           usable_protocols);
        opo = ofputil_encode_packet_out(&po, protocol);
        transact_noreply(vconn, opo);
        vconn_close(vconn);
        free(CONST_CAST(void *, po.packet));
        free(po.ofpacts);
    } else {
        ovs_fatal(0, "Too many arguments (%d)", ctx->argc);
    }
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
    pm.hw_addr = pp.hw_addr;
    pm.hw_addr64 = pp.hw_addr64;
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

/* This function uses OFPMP14_TABLE_DESC request to get the current
 * table configuration from switch. The function then modifies
 * only that table-config property, which has been requested. */
static void
fetch_table_desc(struct vconn *vconn, struct ofputil_table_mod *tm,
                 struct ofputil_table_desc *td)
{
    struct ofpbuf *request;
    ovs_be32 send_xid;
    bool done = false;
    bool found = false;

    request = ofputil_encode_table_desc_request(vconn_get_version(vconn));
    send_xid = ((struct ofp_header *) request->data)->xid;
    send_openflow_buffer(vconn, request);
    while (!done) {
        ovs_be32 recv_xid;
        struct ofpbuf *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            struct ofp_header *oh = reply->data;
            struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));

            enum ofptype type;
            if (ofptype_pull(&type, &b)
                || type != OFPTYPE_TABLE_DESC_REPLY) {
                ovs_fatal(0, "received bad reply: %s",
                          ofp_to_string(reply->data, reply->size, NULL,
                                        verbosity + 1));
            }
            uint16_t flags = ofpmp_flags(oh);
            done = !(flags & OFPSF_REPLY_MORE);
            if (found) {
                /* We've already found the table desc consisting of current
                 * table configuration, but we need to drain the queue of
                 * any other replies for this request. */
                continue;
            }
            while (!ofputil_decode_table_desc(&b, td, oh->version)) {
                if (td->table_id == tm->table_id) {
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
    if (tm->eviction != OFPUTIL_TABLE_EVICTION_DEFAULT) {
        tm->vacancy = td->vacancy;
        tm->table_vacancy.vacancy_down = td->table_vacancy.vacancy_down;
        tm->table_vacancy.vacancy_up = td->table_vacancy.vacancy_up;
    } else if (tm->vacancy != OFPUTIL_TABLE_VACANCY_DEFAULT) {
        tm->eviction = td->eviction;
        tm->eviction_flags = td->eviction_flags;
    }
}

static void
ofctl_mod_table(struct ovs_cmdl_context *ctx)
{
    uint32_t usable_versions;
    struct ofputil_table_mod tm;
    struct vconn *vconn;
    char *error;
    int i;

    error = parse_ofp_table_mod(&tm, ctx->argv[2], ctx->argv[3],
                                &usable_versions);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    uint32_t allowed_versions = get_allowed_ofp_versions();
    if (!(allowed_versions & usable_versions)) {
        struct ds versions = DS_EMPTY_INITIALIZER;
        ofputil_format_version_bitmap_names(&versions, usable_versions);
        ovs_fatal(0, "table_mod '%s' requires one of the OpenFlow "
                  "versions %s",
                  ctx->argv[3], ds_cstr(&versions));
    }
    mask_allowed_ofp_versions(usable_versions);
    enum ofputil_protocol protocol = open_vconn(ctx->argv[1], &vconn);

    /* For OpenFlow 1.4+, ovs-ofctl mod-table should not affect table-config
     * properties that the user didn't ask to change, so it is necessary to
     * restore the current configuration of table-config parameters using
     * OFPMP14_TABLE_DESC request. */
    if ((allowed_versions & (1u << OFP14_VERSION)) ||
        (allowed_versions & (1u << OFP15_VERSION))) {
        struct ofputil_table_desc td;

        if (tm.table_id == OFPTT_ALL) {
            for (i = 0; i < OFPTT_MAX; i++) {
                tm.table_id = i;
                fetch_table_desc(vconn, &tm, &td);
                transact_noreply(vconn,
                                 ofputil_encode_table_mod(&tm, protocol));
            }
        } else {
            fetch_table_desc(vconn, &tm, &td);
            transact_noreply(vconn, ofputil_encode_table_mod(&tm, protocol));
        }
    } else {
        transact_noreply(vconn, ofputil_encode_table_mod(&tm, protocol));
    }
    vconn_close(vconn);
}

static void
ofctl_get_frags(struct ovs_cmdl_context *ctx)
{
    struct ofputil_switch_config config;
    struct vconn *vconn;

    open_vconn(ctx->argv[1], &vconn);
    fetch_switch_config(vconn, &config);
    puts(ofputil_frag_handling_to_string(config.frag));
    vconn_close(vconn);
}

static void
ofctl_set_frags(struct ovs_cmdl_context *ctx)
{
    struct ofputil_switch_config config;
    enum ofputil_frag_handling frag;
    struct vconn *vconn;

    if (!ofputil_frag_handling_from_string(ctx->argv[2], &frag)) {
        ovs_fatal(0, "%s: unknown fragment handling mode", ctx->argv[2]);
    }

    open_vconn(ctx->argv[1], &vconn);
    fetch_switch_config(vconn, &config);
    if (frag != config.frag) {
        /* Set the configuration. */
        config.frag = frag;
        set_switch_config(vconn, &config);

        /* Then retrieve the configuration to see if it really took.  OpenFlow
         * has ill-defined error reporting for bad flags, so this is about the
         * best we can do. */
        fetch_switch_config(vconn, &config);
        if (frag != config.frag) {
            ovs_fatal(0, "%s: setting fragment handling mode failed (this "
                      "switch probably doesn't support mode \"%s\")",
                      ctx->argv[1], ofputil_frag_handling_to_string(frag));
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

        ofp_print(stdout, b.data, b.size, NULL, verbosity + 2);
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
        pkt_metadata_init(&packet->md, ODPP_NONE);
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
                    ofp_print(stdout, dp_packet_data(payload), length,
                              NULL, verbosity + 1);
                    dp_packet_pull(payload, length);
                }
            }
        }
        dp_packet_delete(packet);
    }
    tcp_reader_close(reader);
    fclose(file);
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
            ofp_print(stdout, request, request->size, NULL, verbosity + 2);
            printf("Reply:\n");
            ofp_print(stdout, reply, reply->size, NULL, verbosity + 2);
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
ofctl_dump_ipfix_bridge(struct ovs_cmdl_context *ctx)
{
    dump_trivial_transaction(ctx->argv[1], OFPRAW_NXST_IPFIX_BRIDGE_REQUEST);
}

static void
ofctl_ct_flush_zone(struct ovs_cmdl_context *ctx)
{
    uint16_t zone_id;
    char *error = str_to_u16(ctx->argv[2], "zone_id", &zone_id);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    struct vconn *vconn;
    open_vconn(ctx->argv[1], &vconn);
    enum ofp_version version = vconn_get_version(vconn);

    struct ofpbuf *msg = ofpraw_alloc(OFPRAW_NXT_CT_FLUSH_ZONE, version, 0);
    struct nx_zone_id *nzi = ofpbuf_put_zeros(msg, sizeof *nzi);
    nzi->zone_id = htons(zone_id);

    transact_noreply(vconn, msg);
    vconn_close(vconn);
}

static void
ofctl_dump_ipfix_flow(struct ovs_cmdl_context *ctx)
{
    dump_trivial_transaction(ctx->argv[1], OFPRAW_NXST_IPFIX_FLOW_REQUEST);
}

static void
bundle_group_mod__(const char *remote, struct ofputil_group_mod *gms,
                   size_t n_gms, enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol protocol;
    enum ofp_version version;
    struct vconn *vconn;
    struct ovs_list requests;
    size_t i;

    ovs_list_init(&requests);

    /* Bundles need OpenFlow 1.3+. */
    usable_protocols &= OFPUTIL_P_OF13_UP;
    protocol = open_vconn_for_flow_mod(remote, &vconn, usable_protocols);
    version = ofputil_protocol_to_ofp_version(protocol);

    for (i = 0; i < n_gms; i++) {
        struct ofputil_group_mod *gm = &gms[i];
        struct ofpbuf *request = ofputil_encode_group_mod(version, gm);

        ovs_list_push_back(&requests, &request->list_node);
        ofputil_uninit_group_mod(gm);
    }

    bundle_transact(vconn, &requests, OFPBF_ORDERED | OFPBF_ATOMIC);
    ofpbuf_list_delete(&requests);
    vconn_close(vconn);
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

    if (bundle) {
        bundle_group_mod__(remote, gms, n_gms, usable_protocols);
        return;
    }

    protocol = open_vconn_for_flow_mod(remote, &vconn, usable_protocols);
    version = ofputil_protocol_to_ofp_version(protocol);

    for (i = 0; i < n_gms; i++) {
        gm = &gms[i];
        request = ofputil_encode_group_mod(version, gm);
        transact_noreply(vconn, request);
        ofputil_uninit_group_mod(gm);
    }

    vconn_close(vconn);
}

static void
ofctl_group_mod_file(int argc OVS_UNUSED, char *argv[], int command)
{
    struct ofputil_group_mod *gms = NULL;
    enum ofputil_protocol usable_protocols;
    size_t n_gms = 0;
    char *error;

    if (command == OFPGC11_ADD) {
        /* Allow the file to specify a mix of commands.  If none specified at
         * the beginning of any given line, then the default is OFPGC11_ADD, so
         * this is backwards compatible. */
        command = -2;
    }
    error = parse_ofp_group_mod_file(argv[2], ports_to_accept(argv[1]),
                                     command, &gms, &n_gms, &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }
    ofctl_group_mod__(argv[1], gms, n_gms, usable_protocols);
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
                                        ports_to_accept(argv[1]),
                                        &usable_protocols);
        if (error) {
            ovs_fatal(0, "%s", error);
        }
        ofctl_group_mod__(argv[1], &gm, 1, usable_protocols);
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
    ofctl_group_mod(ctx->argc, ctx->argv,
                    may_create ? OFPGC11_ADD_OR_MOD : OFPGC11_MODIFY);
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
                                    ports_to_accept(ctx->argv[1]),
                                    &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    group_id = gm.group_id;

    open_vconn(ctx->argv[1], &vconn);
    request = ofputil_encode_group_stats_request(vconn_get_version(vconn),
                                                 group_id);
    if (request) {
        dump_transaction(vconn, request);
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
        group_id = OFPG_ALL;
    }

    request = ofputil_encode_group_desc_request(vconn_get_version(vconn),
                                                group_id);
    if (request) {
        dump_transaction(vconn, request);
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
        dump_transaction(vconn, request);
    }

    vconn_close(vconn);
}

static void
ofctl_bundle(struct ovs_cmdl_context *ctx)
{
    enum ofputil_protocol protocol, usable_protocols;
    struct ofputil_bundle_msg *bms;
    struct ovs_list requests;
    struct vconn *vconn;
    size_t n_bms;
    char *error;

    error = parse_ofp_bundle_file(ctx->argv[2], ports_to_accept(ctx->argv[1]),
                                  &bms, &n_bms, &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    /* Implicit OpenFlow 1.4. */
    if (!(get_allowed_ofp_versions() &
          ofputil_protocols_to_version_bitmap(OFPUTIL_P_OF13_UP))) {

        /* Add implicit allowance for OpenFlow 1.4. */
        add_allowed_ofp_versions(ofputil_protocols_to_version_bitmap(
                                     OFPUTIL_P_OF14_OXM));
        /* Remove all versions that do not support bundles. */
        mask_allowed_ofp_versions(ofputil_protocols_to_version_bitmap(
                                     OFPUTIL_P_OF13_UP));
        allowed_protocols = ofputil_protocols_from_version_bitmap(
                                     get_allowed_ofp_versions());
    }

    /* Bundles need OpenFlow 1.3+. */
    usable_protocols &= OFPUTIL_P_OF13_UP;
    protocol = open_vconn_for_flow_mod(ctx->argv[1], &vconn, usable_protocols);

    ovs_list_init(&requests);
    ofputil_encode_bundle_msgs(bms, n_bms, &requests, protocol);
    ofputil_free_bundle_msgs(bms, n_bms);
    bundle_transact(vconn, &requests, OFPBF_ORDERED | OFPBF_ATOMIC);
    ofpbuf_list_delete(&requests);

    vconn_close(vconn);
}

static void
ofctl_tlv_mod(struct ovs_cmdl_context *ctx, uint16_t command)
{
    enum ofputil_protocol usable_protocols;
    enum ofputil_protocol protocol;
    struct ofputil_tlv_table_mod ttm;
    char *error;
    enum ofp_version version;
    struct ofpbuf *request;
    struct vconn *vconn;

    error = parse_ofp_tlv_table_mod_str(&ttm, command, ctx->argc > 2 ?
                                           ctx->argv[2] : "",
                                           &usable_protocols);
    if (error) {
        ovs_fatal(0, "%s", error);
    }

    protocol = open_vconn_for_flow_mod(ctx->argv[1], &vconn, usable_protocols);
    version = ofputil_protocol_to_ofp_version(protocol);

    request = ofputil_encode_tlv_table_mod(version, &ttm);
    if (request) {
        transact_noreply(vconn, request);
    }

    vconn_close(vconn);
    ofputil_uninit_tlv_table(&ttm.mappings);
}

static void
ofctl_add_tlv_map(struct ovs_cmdl_context *ctx)
{
    ofctl_tlv_mod(ctx, NXTTMC_ADD);
}

static void
ofctl_del_tlv_map(struct ovs_cmdl_context *ctx)
{
    ofctl_tlv_mod(ctx, ctx->argc > 2 ? NXTTMC_DELETE : NXTTMC_CLEAR);
}

static void
ofctl_dump_tlv_map(struct ovs_cmdl_context *ctx)
{
    dump_trivial_transaction(ctx->argv[1], OFPRAW_NXT_TLV_TABLE_REQUEST);
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

struct flow_tables {
    struct classifier tables[OFPTT_MAX + 1];
};

#define FOR_EACH_TABLE(CLS, TABLES)                               \
    for ((CLS) = (TABLES)->tables;                                \
         (CLS) < &(TABLES)->tables[ARRAY_SIZE((TABLES)->tables)]; \
         (CLS)++)

static void
flow_tables_init(struct flow_tables *tables)
{
    struct classifier *cls;

    FOR_EACH_TABLE (cls, tables) {
        classifier_init(cls, NULL);
    }
}

static void
flow_tables_defer(struct flow_tables *tables)
{
    struct classifier *cls;

    FOR_EACH_TABLE (cls, tables) {
        classifier_defer(cls);
    }
}

static void
flow_tables_publish(struct flow_tables *tables)
{
    struct classifier *cls;

    FOR_EACH_TABLE (cls, tables) {
        classifier_publish(cls);
    }
}

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
    uint8_t table_id;
};

/* A FTE entry that has been queued for later insertion after all
 * flows have been scanned to correctly allocation tunnel metadata. */
struct fte_pending {
    struct match *match;
    int priority;
    struct fte_version *version;
    int index;

    struct ovs_list list_node;
};

/* Processing state during two stage processing of flow table entries.
 * Tracks the maximum size seen for each tunnel metadata entry as well
 * as a list of the pending FTE entries. */
struct fte_state {
    int tun_metadata_size[TUN_METADATA_NUM_OPTS];
    struct ovs_list fte_pending_list;

    /* The final metadata table that we have constructed. */
    struct tun_table *tun_tab;

    /* Port map.  There is only one port map, not one per source, because it
     * only makes sense to display a single name for a given port number. */
    const struct ofputil_port_map *port_map;
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
            && a->table_id == b->table_id
            && ofpacts_equal_stringwise(a->ofpacts, a->ofpacts_len,
                                        b->ofpacts, b->ofpacts_len));
}

/* Clears 's', then if 's' has a version 'index', formats 'fte' and version
 * 'index' into 's', followed by a new-line. */
static void
fte_version_format(const struct fte_state *fte_state, const struct fte *fte,
                   int index, struct ds *s)
{
    const struct fte_version *version = fte->versions[index];

    ds_clear(s);
    if (!version) {
        return;
    }

    if (version->table_id) {
        ds_put_format(s, "table=%"PRIu8" ", version->table_id);
    }
    cls_rule_format(&fte->rule, fte_state->tun_tab, fte_state->port_map, s);
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
    ofpacts_format(version->ofpacts, version->ofpacts_len,
                   fte_state->port_map, s);

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

/* Frees all of the FTEs within 'tables'. */
static void
fte_free_all(struct flow_tables *tables)
{
    struct classifier *cls;

    FOR_EACH_TABLE (cls, tables) {
        struct fte *fte;

        classifier_defer(cls);
        CLS_FOR_EACH (fte, rule, cls) {
            classifier_remove(cls, &fte->rule);
            ovsrcu_postpone(fte_free, fte);
        }
        classifier_destroy(cls);
    }
}

/* Searches 'tables' for an FTE matching 'rule', inserting a new one if
 * necessary.  Sets 'version' as the version of that rule with the given
 * 'index', replacing any existing version, if any.
 *
 * Takes ownership of 'version'. */
static void
fte_insert(struct flow_tables *tables, const struct match *match,
           int priority, struct fte_version *version, int index)
{
    struct classifier *cls = &tables->tables[version->table_id];
    struct fte *old, *fte;

    fte = xzalloc(sizeof *fte);
    cls_rule_init(&fte->rule, match, priority);
    fte->versions[index] = version;

    old = fte_from_cls_rule(classifier_replace(cls, &fte->rule,
                                               OVS_VERSION_MIN, NULL, 0));
    if (old) {
        fte->versions[!index] = old->versions[!index];
        old->versions[!index] = NULL;

        ovsrcu_postpone(fte_free, old);
    }
}

/* Given a list of the field sizes for each tunnel metadata entry, install
 * a mapping table for later operations. */
static void
generate_tun_metadata(struct fte_state *state)
{
    struct ofputil_tlv_table_mod ttm;
    int i;

    ttm.command = NXTTMC_ADD;
    ovs_list_init(&ttm.mappings);

    for (i = 0; i < TUN_METADATA_NUM_OPTS; i++) {
        if (state->tun_metadata_size[i] != -1) {
            struct ofputil_tlv_map *map = xmalloc(sizeof *map);

            ovs_list_push_back(&ttm.mappings, &map->list_node);

            /* We don't care about the actual option class and type since there
             * won't be any lookup. We just need to make them unique. */
            map->option_class = i / UINT8_MAX;
            map->option_type = i;
            map->option_len = ROUND_UP(state->tun_metadata_size[i], 4);
            map->index = i;
        }
    }

    tun_metadata_table_mod(&ttm, NULL, &state->tun_tab);
    ofputil_uninit_tlv_table(&ttm.mappings);
}

/* Once we have created a tunnel mapping table with a consistent overall
 * allocation, we need to remap each flow to use this table from its own
 * allocation. Since the mapping table has already been installed, we
 * can just read the data from the match and rewrite it. On rewrite, it
 * will use the new table. */
static void
remap_match(struct fte_state *state, struct match *match)
{
    int i;

    if (!match->tun_md.valid) {
        return;
    }

    struct tun_metadata flow = match->flow.tunnel.metadata;
    struct tun_metadata flow_mask = match->wc.masks.tunnel.metadata;
    memset(&match->flow.tunnel.metadata, 0, sizeof match->flow.tunnel.metadata);
    memset(&match->wc.masks.tunnel.metadata, 0,
           sizeof match->wc.masks.tunnel.metadata);
    match->tun_md.valid = false;

    match->flow.tunnel.metadata.tab = state->tun_tab;
    match->wc.masks.tunnel.metadata.tab = match->flow.tunnel.metadata.tab;

    ULLONG_FOR_EACH_1 (i, flow_mask.present.map) {
        const struct mf_field *field = mf_from_id(MFF_TUN_METADATA0 + i);
        int offset = match->tun_md.entry[i].loc.c.offset;
        int len = match->tun_md.entry[i].loc.len;
        union mf_value value, mask;

        memset(&value, 0, field->n_bytes - len);
        memset(&mask, match->tun_md.entry[i].masked ? 0 : 0xff,
               field->n_bytes - len);

        memcpy(value.tun_metadata + field->n_bytes - len,
               flow.opts.u8 + offset, len);
        memcpy(mask.tun_metadata + field->n_bytes - len,
               flow_mask.opts.u8 + offset, len);
        mf_set(field, &value, &mask, match, NULL);
    }
}

/* In order to correctly handle tunnel metadata, we need to have
 * two passes over the flows. This happens because tunnel metadata
 * doesn't have fixed locations in a flow entry but is instead dynamically
 * allocated space. In the case of flows coming from a file, we don't
 * even know the size of each field when we need to do the allocation.
 * When the flows come in, each flow has an individual allocation based
 * on its own fields. However, this allocation is not the same across
 * different flows and therefore fields are not directly comparable.
 *
 * In the first pass, we record the maximum size of each tunnel metadata
 * field as well as queue FTE entries for later processing.
 *
 * In the second pass, we use the metadata size information to create a
 * tunnel mapping table and set that through the tunnel metadata processing
 * code. We then remap all individual flows to use this common allocation
 * scheme. Finally, we load the queued entries into the classifier for
 * comparison.
 *
 * fte_state_init() should be called before processing any flows. */
static void
fte_state_init(struct fte_state *state)
{
    int i;

    for (i = 0; i < TUN_METADATA_NUM_OPTS; i++) {
        state->tun_metadata_size[i] = -1;
    }

    ovs_list_init(&state->fte_pending_list);
    state->tun_tab = NULL;
    state->port_map = NULL;
}

static void
fte_state_destroy(struct fte_state *state)
{
    tun_metadata_free(state->tun_tab);
}

/* The first pass of the processing described in the comment about
 * fte_state_init(). fte_queue() is the first pass to be called as each
 * flow is read from its source. */
static void
fte_queue(struct fte_state *state, const struct match *match,
          int priority, struct fte_version *version, int index)
{
    struct fte_pending *pending = xmalloc(sizeof *pending);
    int i;

    pending->match = xmemdup(match, sizeof *match);
    pending->priority = priority;
    pending->version = version;
    pending->index = index;
    ovs_list_push_back(&state->fte_pending_list, &pending->list_node);

    if (!match->tun_md.valid) {
        return;
    }

    ULLONG_FOR_EACH_1 (i, match->wc.masks.tunnel.metadata.present.map) {
        if (match->tun_md.entry[i].loc.len > state->tun_metadata_size[i]) {
            state->tun_metadata_size[i] = match->tun_md.entry[i].loc.len;
        }
    }
}

/* The second pass of the processing described in the comment about
 * fte_state_init(). This should be called once all flows (from both
 * sides of the comparison) have been added through fte_queue(). */
static void
fte_fill(struct fte_state *state, struct flow_tables *tables)
{
    struct fte_pending *pending;

    generate_tun_metadata(state);

    flow_tables_init(tables);
    flow_tables_defer(tables);

    LIST_FOR_EACH_POP(pending, list_node, &state->fte_pending_list) {
        remap_match(state, pending->match);
        fte_insert(tables, pending->match, pending->priority, pending->version,
                   pending->index);
        free(pending->match);
        free(pending);
    }

    flow_tables_publish(tables);
}

/* Reads the flows in 'filename' as flow table entries in 'tables' for the
 * version with the specified 'index'.  Returns the flow formats able to
 * represent the flows that were read. */
static enum ofputil_protocol
read_flows_from_file(const char *filename, struct fte_state *state, int index)
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
    while (!ds_get_preprocessed_line(&s, file, &line_number)) {
        struct fte_version *version;
        struct ofputil_flow_mod fm;
        char *error;
        enum ofputil_protocol usable;

        error = parse_ofp_str(&fm, OFPFC_ADD, ds_cstr(&s), state->port_map,
                              &usable);
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
        version->table_id = fm.table_id != OFPTT_ALL ? fm.table_id : 0;

        fte_queue(state, &fm.match, fm.priority, version, index);
    }
    ds_destroy(&s);

    if (file != stdin) {
        fclose(file);
    }

    return usable_protocols;
}

/* Reads the OpenFlow flow table from 'vconn', which has currently active flow
 * format 'protocol', and adds them as flow table entries in 'tables' for the
 * version with the specified 'index'. */
static void
read_flows_from_switch(struct vconn *vconn,
                       enum ofputil_protocol protocol,
                       struct fte_state *state, int index)
{
    struct ofputil_flow_stats_request fsr;

    fsr.aggregate = false;
    match_init_catchall(&fsr.match);
    fsr.out_port = OFPP_ANY;
    fsr.out_group = OFPG_ANY;
    fsr.table_id = 0xff;
    fsr.cookie = fsr.cookie_mask = htonll(0);

    struct ofputil_flow_stats *fses;
    size_t n_fses;
    run(vconn_dump_flows(vconn, &fsr, protocol, &fses, &n_fses),
        "dump flows");
    for (size_t i = 0; i < n_fses; i++) {
        const struct ofputil_flow_stats *fs = &fses[i];
        struct fte_version *version;

        version = xmalloc(sizeof *version);
        version->cookie = fs->cookie;
        version->idle_timeout = fs->idle_timeout;
        version->hard_timeout = fs->hard_timeout;
        version->importance = fs->importance;
        version->flags = 0;
        version->ofpacts_len = fs->ofpacts_len;
        version->ofpacts = xmemdup(fs->ofpacts, fs->ofpacts_len);
        version->table_id = fs->table_id;

        fte_queue(state, &fs->match, fs->priority, version, index);
    }

    for (size_t i = 0; i < n_fses; i++) {
        free(CONST_CAST(struct ofpact *, fses[i].ofpacts));
    }
    free(fses);
}

static void
fte_make_flow_mod(const struct fte *fte, int index, uint16_t command,
                  enum ofputil_protocol protocol, struct ovs_list *packets)
{
    const struct fte_version *version = fte->versions[index];
    struct ofpbuf *ofm;

    struct ofputil_flow_mod fm = {
        .priority = fte->rule.priority,
        .new_cookie = version->cookie,
        .modify_cookie = true,
        .table_id = version->table_id,
        .command = command,
        .idle_timeout = version->idle_timeout,
        .hard_timeout = version->hard_timeout,
        .importance = version->importance,
        .buffer_id = UINT32_MAX,
        .out_port = OFPP_ANY,
        .out_group = OFPG_ANY,
        .flags = version->flags,
    };
    minimatch_expand(&fte->rule.match, &fm.match);
    if (command == OFPFC_ADD || command == OFPFC_MODIFY ||
        command == OFPFC_MODIFY_STRICT) {
        fm.ofpacts = version->ofpacts;
        fm.ofpacts_len = version->ofpacts_len;
    } else {
        fm.ofpacts = NULL;
        fm.ofpacts_len = 0;
    }

    ofm = ofputil_encode_flow_mod(&fm, protocol);
    ovs_list_push_back(packets, &ofm->list_node);
}

static void
ofctl_replace_flows(struct ovs_cmdl_context *ctx)
{
    enum { FILE_IDX = 0,  SWITCH_IDX = 1 };
    enum ofputil_protocol usable_protocols, protocol;
    struct fte_state fte_state;
    struct flow_tables tables;
    struct classifier *cls;
    struct ovs_list requests;
    struct vconn *vconn;
    struct fte *fte;

    fte_state_init(&fte_state);
    fte_state.port_map = ports_to_accept(ctx->argv[1]);
    usable_protocols = read_flows_from_file(ctx->argv[2], &fte_state, FILE_IDX);

    protocol = open_vconn(ctx->argv[1], &vconn);
    protocol = set_protocol_for_flow_dump(vconn, protocol, usable_protocols);

    read_flows_from_switch(vconn, protocol, &fte_state, SWITCH_IDX);

    fte_fill(&fte_state, &tables);

    ovs_list_init(&requests);

    FOR_EACH_TABLE (cls, &tables) {
        /* Delete flows that exist on the switch but not in the file. */
        CLS_FOR_EACH (fte, rule, cls) {
            struct fte_version *file_ver = fte->versions[FILE_IDX];
            struct fte_version *sw_ver = fte->versions[SWITCH_IDX];

            if (sw_ver && !file_ver) {
                fte_make_flow_mod(fte, SWITCH_IDX, OFPFC_DELETE_STRICT,
                                  protocol, &requests);
            }
        }

        /* Add flows that exist in the file but not on the switch.
         * Update flows that exist in both places but differ. */
        CLS_FOR_EACH (fte, rule, cls) {
            struct fte_version *file_ver = fte->versions[FILE_IDX];
            struct fte_version *sw_ver = fte->versions[SWITCH_IDX];

            if (file_ver &&
                (readd || !sw_ver || !fte_version_equals(sw_ver, file_ver))) {
                fte_make_flow_mod(fte, FILE_IDX, OFPFC_ADD, protocol,
                                  &requests);
            }
        }
    }
    if (bundle) {
        bundle_transact(vconn, &requests, OFPBF_ORDERED | OFPBF_ATOMIC);
    } else {
        transact_multiple_noreply(vconn, &requests);
    }

    ofpbuf_list_delete(&requests);
    vconn_close(vconn);

    fte_free_all(&tables);
    fte_state_destroy(&fte_state);
}

static void
read_flows_from_source(const char *source, struct fte_state *state, int index)
{
    struct stat s;

    if (source[0] == '/' || source[0] == '.'
        || (!strchr(source, ':') && !stat(source, &s))) {
        read_flows_from_file(source, state, index);
    } else {
        enum ofputil_protocol protocol;
        struct vconn *vconn;

        protocol = open_vconn(source, &vconn);
        protocol = set_protocol_for_flow_dump(vconn, protocol, OFPUTIL_P_ANY);
        read_flows_from_switch(vconn, protocol, state, index);
        vconn_close(vconn);

        if (!state->port_map) {
            state->port_map = ports_to_show(source);
        }
    }
}

static void
ofctl_diff_flows(struct ovs_cmdl_context *ctx)
{
    bool differences = false;
    struct fte_state fte_state;
    struct flow_tables tables;
    struct classifier *cls;
    struct ds a_s, b_s;
    struct fte *fte;

    fte_state_init(&fte_state);
    read_flows_from_source(ctx->argv[1], &fte_state, 0);
    read_flows_from_source(ctx->argv[2], &fte_state, 1);
    fte_fill(&fte_state, &tables);

    ds_init(&a_s);
    ds_init(&b_s);

    FOR_EACH_TABLE (cls, &tables) {
        CLS_FOR_EACH (fte, rule, cls) {
            struct fte_version *a = fte->versions[0];
            struct fte_version *b = fte->versions[1];

            if (!a || !b || !fte_version_equals(a, b)) {
                fte_version_format(&fte_state, fte, 0, &a_s);
                fte_version_format(&fte_state, fte, 1, &b_s);
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

    fte_free_all(&tables);
    fte_state_destroy(&fte_state);

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
        mm.meter.bands = NULL;
    }

    protocol = open_vconn_for_flow_mod(bridge, &vconn, usable_protocols);
    version = ofputil_protocol_to_ofp_version(protocol);
    transact_noreply(vconn, ofputil_encode_meter_mod(version, &mm));
    free(mm.meter.bands);
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
        mm.meter.bands = NULL;
    }

    protocol = open_vconn_for_flow_mod(bridge, &vconn, usable_protocols);
    version = ofputil_protocol_to_ofp_version(protocol);
    dump_transaction(vconn, ofputil_encode_meter_request(version, type,
                                                         mm.meter.meter_id));
    free(mm.meter.bands);
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
        ofp_print(stdout, msg->data, msg->size, NULL, verbosity);
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

    error = parse_ofp_flow_mod_str(&fm, ctx->argv[1], NULL,
                                   OFPFC_ADD, &usable_protocols);
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

    error = parse_ofp_flow_mod_file(ctx->argv[1], NULL, OFPFC_ADD,
                                    &fms, &n_fms, &usable_protocols);
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
                error = oxm_pull_match(&nx_match, false, NULL, NULL, &match);
            } else {
                error = nx_pull_match(&nx_match, match_len, &match, &cookie,
                                      &cookie_mask, false, NULL, NULL);
            }
        } else {
            if (oxm) {
                error = oxm_pull_match_loose(&nx_match, false, NULL, &match);
            } else {
                error = nx_pull_match_loose(&nx_match, match_len, &match,
                                            &cookie, &cookie_mask, false,
                                            NULL);
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
                     &of_in, of_in.size, version, NULL, NULL, &ofpacts);
        if (!error && instructions) {
            /* Verify actions, enforce consistency. */
            enum ofputil_protocol protocol;
            struct match match;

            memset(&match, 0, sizeof match);
            protocol = ofputil_protocols_from_ofp_version(version);
            error = ofpacts_check_consistency(ofpacts.data, ofpacts.size,
                                              &match, OFPP_MAX,
                                              table_id ? atoi(table_id) : 0,
                                              OFPTT_MAX + 1, protocol);
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
        ofpacts_format(ofpacts.data, ofpacts.size, NULL, &s);
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
        match_print(&match, NULL);

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
        match_print(&match, NULL);

        /* Convert back to ofp11_match and print differences from input. */
        ofputil_match_to_ofp11_match(&match, &match_out);

        print_differences("", match_in.data, match_in.size,
                          &match_out, sizeof match_out);
        putchar('\n');

        ofpbuf_uninit(&match_in);
    }
    ds_destroy(&in);
}

/* "parse-pcap PCAP...": read packets from each PCAP file and print their
 * flows. */
static void
ofctl_parse_pcap(struct ovs_cmdl_context *ctx)
{
    int error = 0;
    for (int i = 1; i < ctx->argc; i++) {
        const char *filename = ctx->argv[i];
        FILE *pcap = ovs_pcap_open(filename, "rb");
        if (!pcap) {
            error = errno;
            ovs_error(error, "%s: open failed", filename);
            continue;
        }

        for (;;) {
            struct dp_packet *packet;
            struct flow flow;
            int retval;

            retval = ovs_pcap_read(pcap, &packet, NULL);
            if (retval == EOF) {
                break;
            } else if (retval) {
                error = retval;
                ovs_error(error, "%s: read failed", filename);
            }

            pkt_metadata_init(&packet->md, u32_to_odp(ofp_to_u16(OFPP_ANY)));
            flow_extract(packet, &flow);
            flow_print(stdout, &flow, NULL);
            putchar('\n');
            dp_packet_delete(packet);
        }
        fclose(pcap);
    }
    exit(error);
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
    match.flow.vlans[0].tci = htons(strtoul(ctx->argv[1], NULL, 16));
    match.wc.masks.vlans[0].tci = htons(strtoul(ctx->argv[2], NULL, 16));

    /* Convert to and from string. */
    string_s = match_to_string(&match, NULL, OFP_DEFAULT_PRIORITY);
    printf("%s -> ", string_s);
    fflush(stdout);
    error_s = parse_ofp_str(&fm, -1, string_s, NULL, &usable_protocols);
    if (error_s) {
        ovs_fatal(0, "%s", error_s);
    }
    printf("%04"PRIx16"/%04"PRIx16"\n",
           ntohs(fm.match.flow.vlans[0].tci),
           ntohs(fm.match.wc.masks.vlans[0].tci));
    free(string_s);

    /* Convert to and from NXM. */
    ofpbuf_init(&nxm, 0);
    nxm_match_len = nx_put_match(&nxm, &match, htonll(0), htonll(0));
    nxm_s = nx_match_to_string(nxm.data, nxm_match_len);
    error = nx_pull_match(&nxm, nxm_match_len, &nxm_match, NULL, NULL, false,
                          NULL, NULL);
    printf("NXM: %s -> ", nxm_s);
    if (error) {
        printf("%s\n", ofperr_to_string(error));
    } else {
        printf("%04"PRIx16"/%04"PRIx16"\n",
               ntohs(nxm_match.flow.vlans[0].tci),
               ntohs(nxm_match.wc.masks.vlans[0].tci));
    }
    free(nxm_s);
    ofpbuf_uninit(&nxm);

    /* Convert to and from OXM. */
    ofpbuf_init(&nxm, 0);
    nxm_match_len = oxm_put_match(&nxm, &match, OFP12_VERSION);
    nxm_s = oxm_match_to_string(&nxm, nxm_match_len);
    error = oxm_pull_match(&nxm, false, NULL, NULL, &nxm_match);
    printf("OXM: %s -> ", nxm_s);
    if (error) {
        printf("%s\n", ofperr_to_string(error));
    } else {
        uint16_t vid = ntohs(nxm_match.flow.vlans[0].tci) &
            (VLAN_VID_MASK | VLAN_CFI);
        uint16_t mask = ntohs(nxm_match.wc.masks.vlans[0].tci) &
            (VLAN_VID_MASK | VLAN_CFI);

        printf("%04"PRIx16"/%04"PRIx16",", vid, mask);
        if (vid && vlan_tci_to_pcp(nxm_match.wc.masks.vlans[0].tci)) {
            printf("%02d\n", vlan_tci_to_pcp(nxm_match.flow.vlans[0].tci));
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
           ntohs(of10_match.flow.vlans[0].tci),
           ntohs(of10_match.wc.masks.vlans[0].tci));

    /* Convert to and from OpenFlow 1.1. */
    ofputil_match_to_ofp11_match(&match, &of11_raw);
    ofputil_match_from_ofp11_match(&of11_raw, &of11_match);
    printf("OF1.1: %04"PRIx16"/%d,%02"PRIx8"/%d -> %04"PRIx16"/%04"PRIx16"\n",
           ntohs(of11_raw.dl_vlan),
           (of11_raw.wildcards & htonl(OFPFW11_DL_VLAN)) != 0,
           of11_raw.dl_vlan_pcp,
           (of11_raw.wildcards & htonl(OFPFW11_DL_VLAN_PCP)) != 0,
           ntohs(of11_match.flow.vlans[0].tci),
           ntohs(of11_match.wc.masks.vlans[0].tci));
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
    ofp_print(stdout, packet.data, packet.size, NULL, verbosity);
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
    ofp_print(stdout, hello->data, hello->size, NULL, verbosity);
    ofpbuf_delete(hello);
}

static void
ofctl_parse_key_value(struct ovs_cmdl_context *ctx)
{
    for (size_t i = 1; i < ctx->argc; i++) {
        char *s = ctx->argv[i];
        char *key, *value;
        int j = 0;
        while (ofputil_parse_key_value(&s, &key, &value)) {
            if (j++) {
                fputs(", ", stdout);
            }
            fputs(key, stdout);
            if (value[0]) {
                printf("=%s", value);
            }
        }
        putchar('\n');
    }
}

static const struct ovs_cmdl_command all_commands[] = {
    { "show", "switch",
      1, 1, ofctl_show, OVS_RO },
    { "monitor", "switch [misslen] [invalid_ttl] [watch:[...]]",
      1, 3, ofctl_monitor, OVS_RO },
    { "snoop", "switch",
      1, 1, ofctl_snoop, OVS_RO },
    { "dump-desc", "switch",
      1, 1, ofctl_dump_desc, OVS_RO },
    { "dump-tables", "switch",
      1, 1, ofctl_dump_tables, OVS_RO },
    { "dump-table-features", "switch",
      1, 1, ofctl_dump_table_features, OVS_RO },
    { "dump-table-desc", "switch",
      1, 1, ofctl_dump_table_desc, OVS_RO },
    { "dump-flows", "switch",
      1, 2, ofctl_dump_flows, OVS_RO },
    { "dump-aggregate", "switch",
      1, 2, ofctl_dump_aggregate, OVS_RO },
    { "queue-stats", "switch [port [queue]]",
      1, 3, ofctl_queue_stats, OVS_RO },
    { "queue-get-config", "switch [port [queue]]",
      1, 3, ofctl_queue_get_config, OVS_RO },
    { "add-flow", "switch flow",
      2, 2, ofctl_add_flow, OVS_RW },
    { "add-flows", "switch file",
      2, 2, ofctl_add_flows, OVS_RW },
    { "mod-flows", "switch flow",
      2, 2, ofctl_mod_flows, OVS_RW },
    { "del-flows", "switch [flow]",
      1, 2, ofctl_del_flows, OVS_RW },
    { "replace-flows", "switch file",
      2, 2, ofctl_replace_flows, OVS_RW },
    { "diff-flows", "source1 source2",
      2, 2, ofctl_diff_flows, OVS_RW },
    { "add-meter", "switch meter",
      2, 2, ofctl_add_meter, OVS_RW },
    { "mod-meter", "switch meter",
      2, 2, ofctl_mod_meter, OVS_RW },
    { "del-meter", "switch meter",
      2, 2, ofctl_del_meters, OVS_RW },
    { "del-meters", "switch",
      1, 1, ofctl_del_meters, OVS_RW },
    { "dump-meter", "switch meter",
      2, 2, ofctl_dump_meters, OVS_RO },
    { "dump-meters", "switch",
      1, 1, ofctl_dump_meters, OVS_RO },
    { "meter-stats", "switch [meter]",
      1, 2, ofctl_meter_stats, OVS_RO },
    { "meter-features", "switch",
      1, 1, ofctl_meter_features, OVS_RO },
    { "packet-out", "switch \"in_port=<port> packet=<hex data> actions=...\"",
      2, INT_MAX, ofctl_packet_out, OVS_RW },
    { "dump-ports", "switch [port]",
      1, 2, ofctl_dump_ports, OVS_RO },
    { "dump-ports-desc", "switch [port]",
      1, 2, ofctl_dump_ports_desc, OVS_RO },
    { "mod-port", "switch iface act",
      3, 3, ofctl_mod_port, OVS_RW },
    { "mod-table", "switch mod",
      3, 3, ofctl_mod_table, OVS_RW },
    { "get-frags", "switch",
      1, 1, ofctl_get_frags, OVS_RO },
    { "set-frags", "switch frag_mode",
      2, 2, ofctl_set_frags, OVS_RW },
    { "probe", "target",
      1, 1, ofctl_probe, OVS_RO },
    { "ping", "target [n]",
      1, 2, ofctl_ping, OVS_RO },
    { "benchmark", "target n count",
      3, 3, ofctl_benchmark, OVS_RO },

    { "dump-ipfix-bridge", "switch",
      1, 1, ofctl_dump_ipfix_bridge, OVS_RO },
    { "dump-ipfix-flow", "switch",
      1, 1, ofctl_dump_ipfix_flow, OVS_RO },

    { "ct-flush-zone", "switch zone",
      2, 2, ofctl_ct_flush_zone, OVS_RO },

    { "ofp-parse", "file",
      1, 1, ofctl_ofp_parse, OVS_RW },
    { "ofp-parse-pcap", "pcap",
      1, INT_MAX, ofctl_ofp_parse_pcap, OVS_RW },

    { "add-group", "switch group",
      1, 2, ofctl_add_group, OVS_RW },
    { "add-groups", "switch file",
      1, 2, ofctl_add_groups, OVS_RW },
    { "mod-group", "switch group",
      1, 2, ofctl_mod_group, OVS_RW },
    { "del-groups", "switch [group]",
      1, 2, ofctl_del_groups, OVS_RW },
    { "insert-buckets", "switch [group]",
      1, 2, ofctl_insert_bucket, OVS_RW },
    { "remove-buckets", "switch [group]",
      1, 2, ofctl_remove_bucket, OVS_RW },
    { "dump-groups", "switch [group]",
      1, 2, ofctl_dump_group_desc, OVS_RO },
    { "dump-group-stats", "switch [group]",
      1, 2, ofctl_dump_group_stats, OVS_RO },
    { "dump-group-features", "switch",
      1, 1, ofctl_dump_group_features, OVS_RO },

    { "bundle", "switch file",
      2, 2, ofctl_bundle, OVS_RW },

    { "add-tlv-map", "switch map",
      2, 2, ofctl_add_tlv_map, OVS_RO },
    { "del-tlv-map", "switch [map]",
      1, 2, ofctl_del_tlv_map, OVS_RO },
    { "dump-tlv-map", "switch",
      1, 1, ofctl_dump_tlv_map, OVS_RO },
    { "help", NULL, 0, INT_MAX, ofctl_help, OVS_RO },
    { "list-commands", NULL, 0, INT_MAX, ofctl_list_commands, OVS_RO },

    /* Undocumented commands for testing. */
    { "parse-flow", NULL, 1, 1, ofctl_parse_flow, OVS_RW },
    { "parse-flows", NULL, 1, 1, ofctl_parse_flows, OVS_RW },
    { "parse-nx-match", NULL, 0, 0, ofctl_parse_nxm, OVS_RW },
    { "parse-nxm", NULL, 0, 0, ofctl_parse_nxm, OVS_RW },
    { "parse-oxm", NULL, 1, 1, ofctl_parse_oxm, OVS_RW },
    { "parse-actions", NULL, 1, 1, ofctl_parse_actions, OVS_RW },
    { "parse-instructions", NULL, 1, 1, ofctl_parse_instructions, OVS_RW },
    { "parse-ofp10-match", NULL, 0, 0, ofctl_parse_ofp10_match, OVS_RW },
    { "parse-ofp11-match", NULL, 0, 0, ofctl_parse_ofp11_match, OVS_RW },
    { "parse-pcap", NULL, 1, INT_MAX, ofctl_parse_pcap, OVS_RW },
    { "check-vlan", NULL, 2, 2, ofctl_check_vlan, OVS_RW },
    { "print-error", NULL, 1, 1, ofctl_print_error, OVS_RW },
    { "encode-error-reply", NULL, 2, 2, ofctl_encode_error_reply, OVS_RW },
    { "ofp-print", NULL, 1, 2, ofctl_ofp_print, OVS_RW },
    { "encode-hello", NULL, 1, 1, ofctl_encode_hello, OVS_RW },
    { "parse-key-value", NULL, 1, INT_MAX, ofctl_parse_key_value, OVS_RW },

    { NULL, NULL, 0, 0, NULL, OVS_RO },
};

static const struct ovs_cmdl_command *get_all_commands(void)
{
    return all_commands;
}
