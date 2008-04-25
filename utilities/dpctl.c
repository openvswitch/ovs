/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "command-line.h"
#include "compiler.h"
#include "buffer.h"
#include "dpif.h"
#ifdef HAVE_NETLINK
#include "netlink.h"
#include "openflow-netlink.h"
#endif
#include "util.h"
#include "socket-util.h"
#include "openflow.h"
#include "ofp-print.h"
#include "vconn.h"
#include "vconn-ssl.h"

#include "vlog.h"
#define THIS_MODULE VLM_dpctl

static const char* ifconfigbin = "/sbin/ifconfig";

struct command {
    const char *name;
    int min_args;
    int max_args;
    void (*handler)(int argc, char *argv[]);
};

static struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[]);

int main(int argc, char *argv[])
{
    struct command *p;

    set_program_name(argv[0]);
    vlog_init();
    parse_options(argc, argv);

    argc -= optind;
    argv += optind;
    if (argc < 1)
        fatal(0, "missing command name; use --help for help");

    for (p = all_commands; p->name != NULL; p++) {
        if (!strcmp(p->name, argv[0])) {
            int n_arg = argc - 1;
            if (n_arg < p->min_args)
                fatal(0, "'%s' command requires at least %d arguments",
                      p->name, p->min_args);
            else if (n_arg > p->max_args)
                fatal(0, "'%s' command takes at most %d arguments",
                      p->name, p->max_args);
            else {
                p->handler(argc, argv);
                exit(0);
            }
        }
    }
    fatal(0, "unknown command '%s'; use --help for help", argv[0]);

    return 0;
}

static void
parse_options(int argc, char *argv[])
{
    static struct option long_options[] = {
        {"verbose", optional_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        VCONN_SSL_LONG_OPTIONS
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
        case 'h':
            usage();

        case 'V':
            printf("%s "VERSION" compiled "__DATE__" "__TIME__"\n", argv[0]);
            exit(EXIT_SUCCESS);

        case 'v':
            vlog_set_verbosity(optarg);
            break;

        VCONN_SSL_OPTION_HANDLERS

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
#ifdef HAVE_NETLINK
           "\nCommands that apply to local datapaths only:\n"
           "  adddp nl:DP_ID              add a new local datapath DP_ID\n"
           "  deldp nl:DP_ID              delete local datapath DP_ID\n"
           "  addif nl:DP_ID IFACE        add IFACE as a port on DP_ID\n"
           "  delif nl:DP_ID IFACE        delete IFACE as a port on DP_ID\n"
           "  monitor nl:DP_ID            print packets received\n"
           "  benchmark-nl nl:DP_ID N SIZE   send N packets of SIZE bytes\n"
#endif
           "\nCommands that apply to local datapaths and remote switches:\n"
           "  show SWITCH                 show information\n"
           "  dump-tables SWITCH          print table stats\n"
           "  dump-ports SWITCH           print port statistics\n"
           "  dump-flows SWITCH           print all flow entries\n"
           "  dump-flows SWITCH FLOW      print matching FLOWs\n"
           "  add-flows SWITCH FILE       add flows from FILE\n"
           "  del-flows SWITCH FLOW       delete matching FLOWs\n"
           "where each SWITCH is an active OpenFlow connection method.\n",
           program_name, program_name);
    vconn_usage(true, false);
    printf("\nOptions:\n"
           "  -v, --verbose               set maximum verbosity level\n"
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

#ifdef HAVE_NETLINK
/* Netlink-only commands. */

static int  if_up(const char* intf)
{
    char command[256];
    snprintf(command, sizeof command, "%s %s up &> /dev/null",
            ifconfigbin, intf);
    return system(command);
}

static void open_nl_vconn(const char *name, bool subscribe, struct dpif *dpif)
{
    if (strncmp(name, "nl:", 3)
        || strlen(name) < 4
        || name[strspn(name + 3, "0123456789") + 3]) {
        fatal(0, "%s: argument is not of the form \"nl:DP_ID\"", name);
    }
    run(dpif_open(atoi(name + 3), subscribe, dpif), "opening datapath");
}

static void do_add_dp(int argc UNUSED, char *argv[])
{
    struct dpif dp;
    open_nl_vconn(argv[1], false, &dp);
    run(dpif_add_dp(&dp), "add_dp");
    dpif_close(&dp);
}

static void do_del_dp(int argc UNUSED, char *argv[])
{
    struct dpif dp;
    open_nl_vconn(argv[1], false, &dp);
    run(dpif_del_dp(&dp), "del_dp");
    dpif_close(&dp);
}

static void do_add_port(int argc UNUSED, char *argv[])
{
    struct dpif dp;
    if_up(argv[2]);
    open_nl_vconn(argv[1], false, &dp);
    run(dpif_add_port(&dp, argv[2]), "add_port");
    dpif_close(&dp);
}

static void do_del_port(int argc UNUSED, char *argv[])
{
    struct dpif dp;
    open_nl_vconn(argv[1], false, &dp);
    run(dpif_del_port(&dp, argv[2]), "del_port");
    dpif_close(&dp);
}

static void do_monitor(int argc UNUSED, char *argv[])
{
    struct dpif dp;
    open_nl_vconn(argv[1], false, &dp);
    for (;;) {
        struct buffer *b;
        run(dpif_recv_openflow(&dp, &b, true), "dpif_recv_openflow");
        ofp_print(stderr, b->data, b->size, 2);
        buffer_delete(b);
    }
}

#define BENCHMARK_INCR   100

static void do_benchmark_nl(int argc UNUSED, char *argv[])
{
    struct dpif dp;
    uint32_t num_packets, i, milestone;
    struct timeval start, end;

    open_nl_vconn(argv[1], false, &dp);
    num_packets = atoi(argv[2]);
    milestone = BENCHMARK_INCR;
    run(dpif_benchmark_nl(&dp, num_packets, atoi(argv[3])), "benchmark_nl");
    if (gettimeofday(&start, NULL) == -1) {
        run(errno, "gettimeofday");
    }
    for (i = 0; i < num_packets;i++) {
        struct buffer *b;
        run(dpif_recv_openflow(&dp, &b, true), "dpif_recv_openflow");
        if (i == milestone) {
            gettimeofday(&end, NULL);
            printf("%u packets received in %f ms\n",
                   BENCHMARK_INCR,
                   (1000*(double)(end.tv_sec - start.tv_sec))
                   + (.001*(end.tv_usec - start.tv_usec)));
            milestone += BENCHMARK_INCR;
            start = end;
        }
        buffer_delete(b);
    }
    gettimeofday(&end, NULL);
    printf("%u packets received in %f ms\n",
           i - (milestone - BENCHMARK_INCR),
           (1000*(double)(end.tv_sec - start.tv_sec))
           + (.001*(end.tv_usec - start.tv_usec)));

    dpif_close(&dp);
}
#endif /* HAVE_NETLINK */

/* Generic commands. */

static uint32_t
random_xid(void)
{
    static bool inited = false;
    if (!inited) {
        struct timeval tv;
        inited = true;
        if (gettimeofday(&tv, NULL) < 0) {
            fatal(errno, "gettimeofday");
        }
        srand(tv.tv_sec ^ tv.tv_usec);
    }
    return rand();
}

static void *
alloc_openflow_buffer(size_t openflow_len, uint8_t type,
                      struct buffer **bufferp)
{
	struct buffer *buffer;
	struct ofp_header *oh;

	buffer = *bufferp = buffer_new(openflow_len);
	oh = buffer_put_uninit(buffer, openflow_len);
    memset(oh, 0, openflow_len);
	oh->version = OFP_VERSION;
	oh->type = type;
	oh->length = 0;
	oh->xid = random_xid();
	return oh;
}

static void
send_openflow_buffer(struct vconn *vconn, struct buffer *buffer)
{
    struct ofp_header *oh;

    oh = buffer_at_assert(buffer, 0, sizeof *oh);
    oh->length = htons(buffer->size);

    run(vconn_send_block(vconn, buffer), "failed to send packet to switch");
}

static struct buffer *
transact_openflow(struct vconn *vconn, struct buffer *request)
{
    uint32_t send_xid = ((struct ofp_header *) request->data)->xid;

    send_openflow_buffer(vconn, request);
    for (;;) {
        uint32_t recv_xid;
        struct buffer *reply;

        run(vconn_recv_block(vconn, &reply), "OpenFlow packet receive failed");
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (send_xid == recv_xid) {
            return reply;
        }

        VLOG_DBG("received reply with xid %08"PRIx32" != expected %08"PRIx32,
                 recv_xid, send_xid);
        buffer_delete(reply);
    }
}

static void
dump_transaction(const char *vconn_name, uint8_t request_type)
{
    struct vconn *vconn;
    struct buffer *request, *reply;

    run(vconn_open_block(vconn_name, &vconn), "connecting to %s", vconn_name);
    alloc_openflow_buffer(sizeof(struct ofp_header), request_type, &request);
    reply = transact_openflow(vconn, request);
    ofp_print(stdout, reply->data, reply->size, 1);
    vconn_close(vconn);
}

static void
do_show(int argc UNUSED, char *argv[])
{
    dump_transaction(argv[1], OFPT_FEATURES_REQUEST);
}


static void
do_dump_tables(int argc, char *argv[])
{
    dump_transaction(argv[1], OFPT_TABLE_STATS_REQUEST);
}


static uint32_t
str_to_int(const char *str) 
{
    uint32_t value;
    if (sscanf(str, "%"SCNu32, &value) != 1) {
        fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static void
str_to_mac(const char *str, uint8_t mac[6]) 
{
    if (sscanf(str, "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8,
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        fatal(0, "invalid mac address %s", str);
    }
}

static void
str_to_ip(const char *str, uint32_t *ip) 
{
    struct in_addr in_addr;
    int retval;

    retval = lookup_ip(str, &in_addr);
    if (retval) {
        fatal(0, "%s: could not convert to IP address", str);
    }
    *ip = in_addr.s_addr;
}

static void
str_to_action(const char *str, struct ofp_action *action) 
{
    uint16_t port;

    if (!strcasecmp(str, "flood")) {
        port = OFPP_FLOOD;
    } else if (!strcasecmp(str, "controller")) {
        port = OFPP_CONTROLLER;
    } else {
        port = str_to_int(str);
    }

    memset(action, 0, sizeof *action);
    action->type = OFPAT_OUTPUT;
    action->arg.output.port = htons(port);
}

static void
str_to_flow(char *string, struct ofp_match *match, struct ofp_action *action,
            uint8_t *table_idx, uint16_t *priority)
{
    struct field {
        const char *name;
        uint32_t wildcard;
        enum { F_U8, F_U16, F_MAC, F_IP } type;
        size_t offset;
    };

#define F_OFS(MEMBER) offsetof(struct ofp_match, MEMBER)
    static const struct field fields[] = { 
        { "in_port", OFPFW_IN_PORT, F_U16, F_OFS(in_port) },
        { "dl_vlan", OFPFW_DL_VLAN, F_U16, F_OFS(dl_vlan) },
        { "dl_src", OFPFW_DL_SRC, F_MAC, F_OFS(dl_src) },
        { "dl_dst", OFPFW_DL_DST, F_MAC, F_OFS(dl_dst) },
        { "dl_type", OFPFW_DL_TYPE, F_U16, F_OFS(dl_type) },
        { "nw_src", OFPFW_NW_SRC, F_IP, F_OFS(nw_src) },
        { "nw_dst", OFPFW_NW_DST, F_IP, F_OFS(nw_dst) },
        { "nw_proto", OFPFW_NW_PROTO, F_U8, F_OFS(nw_proto) },
        { "tp_src", OFPFW_TP_SRC, F_U16, F_OFS(tp_src) },
        { "tp_dst", OFPFW_TP_DST, F_U16, F_OFS(tp_dst) },
    };

    char *name, *value;
    uint32_t wildcards;
    bool got_action = false;

    if (table_idx) {
        *table_idx = 0xff;
    }
    memset(match, 0, sizeof *match);
    wildcards = OFPFW_ALL;
    for (name = strtok(string, "="), value = strtok(NULL, " \t\n");
         name && value;
         name = strtok(NULL, "="), value = strtok(NULL, " \t\n"))
    {
        const struct field *f;
        void *data;

        if (action && !strcmp(name, "action")) {
            got_action = true;
            str_to_action(value, action);
            continue;
        }

        if (table_idx && !strcmp(name, "table")) {
            *table_idx = atoi(value);
            continue;
        }

        if (priority && !strcmp(name, "priority")) {
            *priority = atoi(value);
            continue;
        }

        for (f = fields; f < &fields[ARRAY_SIZE(fields)]; f++) {
            if (!strcmp(f->name, name)) {
                goto found;
            }
        }
        fprintf(stderr, "%s: unknown field %s (fields are",
                program_name, name);
        for (f = fields; f < &fields[ARRAY_SIZE(fields)]; f++) {
            if (f != fields) {
                putc(',', stderr);
            }
            fprintf(stderr, " %s", f->name);
        }
        fprintf(stderr, ")\n");
        exit(1);

    found:
        data = (char *) match + f->offset;
        if (!strcmp(value, "*")) {
            wildcards |= f->wildcard;
        } else {
            wildcards &= ~f->wildcard;
            if (f->type == F_U8) {
                *(uint8_t *) data = str_to_int(value);
            } else if (f->type == F_U16) {
                *(uint16_t *) data = htons(str_to_int(value));
            } else if (f->type == F_MAC) {
                str_to_mac(value, data);
            } else if (f->type == F_IP) {
                str_to_ip(value, data);
            } else {
                NOT_REACHED();
            }
        }
    }
    if (name && !value) {
        fatal(0, "field %s missing value", name);
    }
    if (action && !got_action) {
        fatal(0, "must specify an action");
    }
    match->wildcards = htons(wildcards);
}

static void do_dump_flows(int argc, char *argv[])
{
    struct vconn *vconn;
    struct buffer *request, *reply;
    struct ofp_flow_stats_request *fsr;

    run(vconn_open_block(argv[1], &vconn), "connecting to %s", argv[1]);
    fsr = alloc_openflow_buffer(sizeof *fsr, OFPT_FLOW_STATS_REQUEST, &request);
    str_to_flow(argc > 2 ? argv[2] : "", &fsr->match, NULL, &fsr->table_id, 
            NULL);
    fsr->type = OFPFS_INDIV;
    fsr->pad = 0;
    reply = transact_openflow(vconn, request);
    ofp_print(stdout, reply->data, reply->size, 1);
    vconn_close(vconn);
}

static void do_add_flows(int argc, char *argv[])
{
    struct vconn *vconn;

    FILE *file;
    char line[1024];

    file = fopen(argv[2], "r");
    if (file == NULL) {
        fatal(errno, "%s: open", argv[2]);
    }

    run(vconn_open_block(argv[1], &vconn), "connecting to %s", argv[1]);
    while (fgets(line, sizeof line, file)) {
        struct buffer *buffer;
        struct ofp_flow_mod *ofm;
        uint16_t priority=0;
        size_t size;

        char *comment;

        /* Delete comments. */
        comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }

        /* Drop empty lines. */
        if (line[strspn(line, " \t\n")] == '\0') {
            continue;
        }

        /* Parse and send. */
        size = sizeof *ofm + sizeof ofm->actions[0];
        ofm = alloc_openflow_buffer(size, OFPT_FLOW_MOD, &buffer);
        ofm->command = htons(OFPFC_ADD);
        ofm->max_idle = htons(50);
        ofm->buffer_id = htonl(UINT32_MAX);
        ofm->group_id = htonl(0);
        str_to_flow(line, &ofm->match, &ofm->actions[0], NULL, &priority);
        ofm->priority = htons(priority);

        send_openflow_buffer(vconn, buffer);
    }
    vconn_close(vconn);
    fclose(file);
}

static void do_del_flows(int argc, char *argv[])
{
    struct vconn *vconn;

    run(vconn_open_block(argv[1], &vconn), "connecting to %s", argv[1]);
    struct buffer *buffer;
    struct ofp_flow_mod *ofm;
    size_t size;


    /* Parse and send. */
    size = sizeof *ofm;
    ofm = alloc_openflow_buffer(size, OFPT_FLOW_MOD, &buffer);
    ofm->command = htons(OFPFC_DELETE);
    ofm->max_idle = 0;
    ofm->buffer_id = htonl(UINT32_MAX);
    ofm->group_id = 0;
    ofm->priority = 0;
    str_to_flow(argc > 2 ? argv[2] : "", &ofm->match, NULL, NULL, NULL);

    send_openflow_buffer(vconn, buffer);

    vconn_close(vconn);
}

static void
do_dump_ports(int argc, char *argv[])
{
    dump_transaction(argv[1], OFPT_PORT_STATS_REQUEST);
}

static void do_help(int argc UNUSED, char *argv[] UNUSED)
{
    usage();
}

static struct command all_commands[] = {
#ifdef HAVE_NETLINK
    { "adddp", 1, 1, do_add_dp },
    { "deldp", 1, 1, do_del_dp },
    { "addif", 2, 2, do_add_port },
    { "delif", 2, 2, do_del_port },
    { "benchmark-nl", 3, 3, do_benchmark_nl },
#endif

    { "show", 1, 1, do_show },

    { "help", 0, INT_MAX, do_help },
    { "monitor", 1, 1, do_monitor },
    { "dump-tables", 1, 1, do_dump_tables },
    { "dump-flows", 1, 2, do_dump_flows },
    { "add-flows", 2, 2, do_add_flows },
    { "del-flows", 1, 2, do_del_flows },
    { "dump-ports", 1, 1, do_dump_ports },
};
