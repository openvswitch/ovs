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
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <net/if.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "command-line.h"
#include "compiler.h"
#include "dirs.h"
#include "dpif.h"
#include "dynamic-string.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofpbuf.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "random.h"
#include "socket-util.h"
#include "timeval.h"
#include "util.h"
#include "vconn-ssl.h"
#include "vconn.h"
#include "xtoxll.h"

#include "vlog.h"
#define THIS_MODULE VLM_ofctl

#define DEFAULT_IDLE_TIMEOUT 60

#define MOD_PORT_CMD_UP      "up"
#define MOD_PORT_CMD_DOWN    "down"
#define MOD_PORT_CMD_FLOOD   "flood"
#define MOD_PORT_CMD_NOFLOOD "noflood"


/* Settings that may be configured by the user. */
struct settings {
    bool strict;        /* Use strict matching for flow mod commands */
};

struct command {
    const char *name;
    int min_args;
    int max_args;
    void (*handler)(const struct settings *, int argc, char *argv[]);
};

static struct command all_commands[];

static void usage(void) NO_RETURN;
static void parse_options(int argc, char *argv[], struct settings *);

int main(int argc, char *argv[])
{
    struct settings s;
    struct command *p;

    set_program_name(argv[0]);
    time_init();
    vlog_init();
    parse_options(argc, argv, &s);
    signal(SIGPIPE, SIG_IGN);

    argc -= optind;
    argv += optind;
    if (argc < 1)
        ovs_fatal(0, "missing command name; use --help for help");

    for (p = all_commands; p->name != NULL; p++) {
        if (!strcmp(p->name, argv[0])) {
            int n_arg = argc - 1;
            if (n_arg < p->min_args)
                ovs_fatal(0, "'%s' command requires at least %d arguments",
                          p->name, p->min_args);
            else if (n_arg > p->max_args)
                ovs_fatal(0, "'%s' command takes at most %d arguments",
                          p->name, p->max_args);
            else {
                p->handler(&s, argc, argv);
                if (ferror(stdout)) {
                    ovs_fatal(0, "write to stdout failed");
                }
                if (ferror(stderr)) {
                    ovs_fatal(0, "write to stderr failed");
                }
                exit(0);
            }
        }
    }
    ovs_fatal(0, "unknown command '%s'; use --help for help", argv[0]);

    return 0;
}

static void
parse_options(int argc, char *argv[], struct settings *s)
{
    enum {
        OPT_STRICT = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS
    };
    static struct option long_options[] = {
        {"timeout", required_argument, 0, 't'},
        {"strict", no_argument, 0, OPT_STRICT},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        VLOG_LONG_OPTIONS,
        VCONN_SSL_LONG_OPTIONS
        {0, 0, 0, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    /* Set defaults that we can figure out before parsing options. */
    s->strict = false;

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

        case 'h':
            usage();

        case 'V':
            OVS_PRINT_VERSION(OFP_VERSION, OFP_VERSION);
            exit(EXIT_SUCCESS);

        case OPT_STRICT:
            s->strict = true;
            break;

        VLOG_OPTION_HANDLERS
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
           "  add-flow SWITCH FLOW        add flow described by FLOW\n"
           "  add-flows SWITCH FILE       add flows from FILE\n"
           "  mod-flows SWITCH FLOW       modify actions of matching FLOWs\n"
           "  del-flows SWITCH [FLOW]     delete matching FLOWs\n"
           "  monitor SWITCH MISSLEN EXP  print packets received from SWITCH\n"
           "  execute SWITCH CMD [ARG...] execute CMD with ARGS on SWITCH\n"
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
open_vconn(const char *name, struct vconn **vconnp)
{
    struct dpif *dpif;
    struct stat s;

    if (strstr(name, ":")) {
        run(vconn_open_block(name, OFP_VERSION, vconnp),
            "connecting to %s", name);
    } else if (!stat(name, &s) && S_ISSOCK(s.st_mode)) {
        char *vconn_name = xasprintf("unix:%s", name);
        VLOG_INFO("connecting to %s", vconn_name);
        run(vconn_open_block(vconn_name, OFP_VERSION, vconnp),
            "connecting to %s", vconn_name);
        free(vconn_name);
    } else if (!dpif_open(name, &dpif)) {
        char dpif_name[IF_NAMESIZE + 1];
        char *socket_name;
        char *vconn_name;

        run(dpif_port_get_name(dpif, ODPP_LOCAL, dpif_name, sizeof dpif_name),
            "obtaining name of %s", dpif_name);
        dpif_close(dpif);
        if (strcmp(dpif_name, name)) {
            VLOG_INFO("datapath %s is named %s", name, dpif_name);
        }

        socket_name = xasprintf("%s/%s.mgmt", ovs_rundir, dpif_name);
        if (stat(socket_name, &s)) {
            ovs_fatal(errno, "cannot connect to %s: stat failed on %s",
                      name, socket_name);
        } else if (!S_ISSOCK(s.st_mode)) {
            ovs_fatal(0, "cannot connect to %s: %s is not a socket",
                      name, socket_name);
        }

        vconn_name = xasprintf("unix:%s", socket_name);
        VLOG_INFO("connecting to %s", vconn_name);
        run(vconn_open_block(vconn_name, OFP_VERSION, vconnp),
            "connecting to %s", vconn_name);
        free(socket_name);
        free(vconn_name);
    } else {
        ovs_fatal(0, "%s is not a valid connection method", name);
    }
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
    ofp_print(stdout, reply->data, reply->size, 1);
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
    uint32_t send_xid = ((struct ofp_header *) request->data)->xid;
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

            ofp_print(stdout, reply->data, reply->size, 1);

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

static void
do_show(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    dump_trivial_transaction(argv[1], OFPT_FEATURES_REQUEST);
    dump_trivial_transaction(argv[1], OFPT_GET_CONFIG_REQUEST);
}

static void
do_status(const struct settings *s UNUSED, int argc, char *argv[])
{
    struct nicira_header *request, *reply;
    struct vconn *vconn;
    struct ofpbuf *b;

    request = make_openflow(sizeof *request, OFPT_VENDOR, &b);
    request->vendor = htonl(NX_VENDOR_ID);
    request->subtype = htonl(NXT_STATUS_REQUEST);
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
        ofp_print(stderr, b->data, b->size, 2);
        ovs_fatal(0, "bad reply");
    }

    fwrite(reply + 1, b->size - sizeof *reply, 1, stdout);
}

static void
do_dump_desc(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPST_DESC);
}

static void
do_dump_tables(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    dump_trivial_stats_transaction(argv[1], OFPST_TABLE);
}


static uint32_t
str_to_u32(const char *str) 
{
    char *tail;
    uint32_t value;

    errno = 0;
    value = strtoul(str, &tail, 0);
    if (errno == EINVAL || errno == ERANGE || *tail) {
        ovs_fatal(0, "invalid numeric format %s", str);
    }
    return value;
}

static void
str_to_mac(const char *str, uint8_t mac[6]) 
{
    if (sscanf(str, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))
        != ETH_ADDR_SCAN_COUNT) {
        ovs_fatal(0, "invalid mac address %s", str);
    }
}

static uint32_t
str_to_ip(const char *str_, uint32_t *ip)
{
    char *str = xstrdup(str_);
    char *save_ptr = NULL;
    const char *name, *netmask;
    struct in_addr in_addr;
    int n_wild, retval;

    name = strtok_r(str, "/", &save_ptr);
    retval = name ? lookup_ip(name, &in_addr) : EINVAL;
    if (retval) {
        ovs_fatal(0, "%s: could not convert to IP address", str);
    }
    *ip = in_addr.s_addr;

    netmask = strtok_r(NULL, "/", &save_ptr);
    if (netmask) {
        uint8_t o[4];
        if (sscanf(netmask, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8,
                   &o[0], &o[1], &o[2], &o[3]) == 4) {
            uint32_t nm = (o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3];
            int i;

            /* Find first 1-bit. */
            for (i = 0; i < 32; i++) {
                if (nm & (1u << i)) {
                    break;
                }
            }
            n_wild = i;

            /* Verify that the rest of the bits are 1-bits. */
            for (; i < 32; i++) {
                if (!(nm & (1u << i))) {
                    ovs_fatal(0, "%s: %s is not a valid netmask",
                              str, netmask);
                }
            }
        } else {
            int prefix = atoi(netmask);
            if (prefix <= 0 || prefix > 32) {
                ovs_fatal(0, "%s: network prefix bits not between 1 and 32",
                          str);
            }
            n_wild = 32 - prefix;
        }
    } else {
        n_wild = 0;
    }

    free(str);
    return n_wild;
}

static uint16_t
str_to_port_no(const char *vconn_name, const char *str)
{
    struct ofpbuf *request, *reply;
    struct ofp_switch_features *osf;
    struct vconn *vconn;
    int n_ports;
    int port_idx;
    unsigned int port_no;
    

    /* Check if the argument is a port index.  Otherwise, treat it as
     * the port name. */
    if (str_to_uint(str, 10, &port_no)) {
        return port_no;
    }

    /* Send a "Features Request" to resolve the name into a number. */
    make_openflow(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, &request);
    open_vconn(vconn_name, &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", vconn_name);

    osf = reply->data;
    n_ports = (reply->size - sizeof *osf) / sizeof *osf->ports;

    for (port_idx = 0; port_idx < n_ports; port_idx++) {
        /* Check argument as an interface name */
        if (!strncmp((char *)osf->ports[port_idx].name, str,
                    sizeof osf->ports[0].name)) {
            break;
        }
    }
    if (port_idx == n_ports) {
        ovs_fatal(0, "couldn't find monitored port: %s", str);
    }

    ofpbuf_delete(reply);
    vconn_close(vconn);

    return port_idx;
}

static void *
put_action(struct ofpbuf *b, size_t size, uint16_t type)
{
    struct ofp_action_header *ah = ofpbuf_put_zeros(b, size);
    ah->type = htons(type);
    ah->len = htons(size);
    return ah;
}

static struct ofp_action_output *
put_output_action(struct ofpbuf *b, uint16_t port)
{
    struct ofp_action_output *oao = put_action(b, sizeof *oao, OFPAT_OUTPUT);
    oao->port = htons(port);
    return oao;
}

static void
put_dl_addr_action(struct ofpbuf *b, uint16_t type, const char *addr)
{
    struct ofp_action_dl_addr *oada = put_action(b, sizeof *oada, type);
    str_to_mac(addr, oada->dl_addr);
}


static bool
parse_port_name(const char *name, uint16_t *port)
{
    struct pair {
        const char *name;
        uint16_t value;
    };
    static const struct pair pairs[] = {
#define DEF_PAIR(NAME) {#NAME, OFPP_##NAME}
        DEF_PAIR(IN_PORT),
        DEF_PAIR(TABLE),
        DEF_PAIR(NORMAL),
        DEF_PAIR(FLOOD),
        DEF_PAIR(ALL),
        DEF_PAIR(CONTROLLER),
        DEF_PAIR(LOCAL),
        DEF_PAIR(NONE),
#undef DEF_PAIR
    };
    static const int n_pairs = ARRAY_SIZE(pairs);
    size_t i;

    for (i = 0; i < n_pairs; i++) {
        if (!strcasecmp(name, pairs[i].name)) {
            *port = pairs[i].value;
            return true;
        }
    }
    return false;
}

static void
str_to_action(char *str, struct ofpbuf *b)
{
    char *act, *arg;
    char *saveptr = NULL;
    bool drop = false;
    int n_actions;

    for (act = strtok_r(str, ", \t\r\n", &saveptr), n_actions = 0; act;
         act = strtok_r(NULL, ", \t\r\n", &saveptr), n_actions++) 
    {
        uint16_t port;

        if (drop) {
            ovs_fatal(0, "Drop actions must not be followed by other actions");
        }

        /* Arguments are separated by colons */
        arg = strchr(act, ':');
        if (arg) {
            *arg = '\0';
            arg++;
        }

        if (!strcasecmp(act, "mod_vlan_vid")) {
            struct ofp_action_vlan_vid *va;
            va = put_action(b, sizeof *va, OFPAT_SET_VLAN_VID);
            va->vlan_vid = htons(str_to_u32(arg));
        } else if (!strcasecmp(act, "mod_vlan_pcp")) {
            struct ofp_action_vlan_pcp *va;
            va = put_action(b, sizeof *va, OFPAT_SET_VLAN_PCP);
            va->vlan_pcp = str_to_u32(arg);
        } else if (!strcasecmp(act, "strip_vlan")) {
            struct ofp_action_header *ah;
            ah = put_action(b, sizeof *ah, OFPAT_STRIP_VLAN);
            ah->type = htons(OFPAT_STRIP_VLAN);
        } else if (!strcasecmp(act, "mod_dl_src")) {
            put_dl_addr_action(b, OFPAT_SET_DL_SRC, arg);
        } else if (!strcasecmp(act, "mod_dl_dst")) {
            put_dl_addr_action(b, OFPAT_SET_DL_DST, arg);
        } else if (!strcasecmp(act, "mod_nw_src")) {
            struct ofp_action_nw_addr *na;
            na = put_action(b, sizeof *na, OFPAT_SET_NW_SRC);
            str_to_ip(arg, &na->nw_addr);
        } else if (!strcasecmp(act, "mod_nw_dst")) {
            struct ofp_action_nw_addr *na;
            na = put_action(b, sizeof *na, OFPAT_SET_NW_DST);
            str_to_ip(arg, &na->nw_addr);
        } else if (!strcasecmp(act, "mod_tp_src")) {
            struct ofp_action_tp_port *ta;
            ta = put_action(b, sizeof *ta, OFPAT_SET_TP_SRC);
            ta->tp_port = htons(str_to_u32(arg));
        } else if (!strcasecmp(act, "mod_tp_dst")) {
            struct ofp_action_tp_port *ta;
            ta = put_action(b, sizeof *ta, OFPAT_SET_TP_DST);
            ta->tp_port = htons(str_to_u32(arg));
        } else if (!strcasecmp(act, "mod_nw_tos")) {
            struct ofp_action_nw_tos *nt;
            nt = put_action(b, sizeof *nt, OFPAT_SET_NW_TOS);
            nt->nw_tos = str_to_u32(arg);
        } else if (!strcasecmp(act, "output")) {
            put_output_action(b, str_to_u32(arg));
        } else if (!strcasecmp(act, "drop")) {
            /* A drop action in OpenFlow occurs by just not setting 
             * an action. */
            drop = true;
            if (n_actions) {
                ovs_fatal(0, "Drop actions must not be preceded by other "
                          "actions");
            }
        } else if (!strcasecmp(act, "CONTROLLER")) {
            struct ofp_action_output *oao;
            oao = put_output_action(b, OFPP_CONTROLLER);

            /* Unless a numeric argument is specified, we send the whole
             * packet to the controller. */
            if (arg && (strspn(arg, "0123456789") == strlen(arg))) {
               oao->max_len = htons(str_to_u32(arg));
            } else {
                oao->max_len = htons(UINT16_MAX);
            }
        } else if (parse_port_name(act, &port)) {
            put_output_action(b, port);
        } else if (strspn(act, "0123456789") == strlen(act)) {
            put_output_action(b, str_to_u32(act));
        } else {
            ovs_fatal(0, "Unknown action: %s", act);
        }
    }
}

struct protocol {
    const char *name;
    uint16_t dl_type;
    uint8_t nw_proto;
};

static bool
parse_protocol(const char *name, const struct protocol **p_out)
{
    static const struct protocol protocols[] = {
        { "ip", ETH_TYPE_IP, 0 },
        { "arp", ETH_TYPE_ARP, 0 },
        { "icmp", ETH_TYPE_IP, IP_TYPE_ICMP },
        { "tcp", ETH_TYPE_IP, IP_TYPE_TCP },
        { "udp", ETH_TYPE_IP, IP_TYPE_UDP },
    };
    const struct protocol *p;

    for (p = protocols; p < &protocols[ARRAY_SIZE(protocols)]; p++) {
        if (!strcmp(p->name, name)) {
            *p_out = p;
            return true;
        }
    }
    *p_out = NULL;
    return false;
}

struct field {
    const char *name;
    uint32_t wildcard;
    enum { F_U8, F_U16, F_MAC, F_IP } type;
    size_t offset, shift;
};

static bool
parse_field(const char *name, const struct field **f_out) 
{
#define F_OFS(MEMBER) offsetof(struct ofp_match, MEMBER)
    static const struct field fields[] = { 
        { "in_port", OFPFW_IN_PORT, F_U16, F_OFS(in_port), 0 },
        { "dl_vlan", OFPFW_DL_VLAN, F_U16, F_OFS(dl_vlan), 0 },
        { "dl_vlan_pcp", OFPFW_DL_VLAN_PCP, F_U8, F_OFS(dl_vlan_pcp), 0 },
        { "dl_src", OFPFW_DL_SRC, F_MAC, F_OFS(dl_src), 0 },
        { "dl_dst", OFPFW_DL_DST, F_MAC, F_OFS(dl_dst), 0 },
        { "dl_type", OFPFW_DL_TYPE, F_U16, F_OFS(dl_type), 0 },
        { "nw_src", OFPFW_NW_SRC_MASK, F_IP,
          F_OFS(nw_src), OFPFW_NW_SRC_SHIFT },
        { "nw_dst", OFPFW_NW_DST_MASK, F_IP,
          F_OFS(nw_dst), OFPFW_NW_DST_SHIFT },
        { "nw_proto", OFPFW_NW_PROTO, F_U8, F_OFS(nw_proto), 0 },
        { "nw_tos", OFPFW_NW_TOS, F_U8, F_OFS(nw_tos), 0 },
        { "tp_src", OFPFW_TP_SRC, F_U16, F_OFS(tp_src), 0 },
        { "tp_dst", OFPFW_TP_DST, F_U16, F_OFS(tp_dst), 0 },
        { "icmp_type", OFPFW_ICMP_TYPE, F_U16, F_OFS(icmp_type), 0 },
        { "icmp_code", OFPFW_ICMP_CODE, F_U16, F_OFS(icmp_code), 0 }
    };
    const struct field *f;

    for (f = fields; f < &fields[ARRAY_SIZE(fields)]; f++) {
        if (!strcmp(f->name, name)) {
            *f_out = f;
            return true;
        }
    }
    *f_out = NULL;
    return false;
}

static void
str_to_flow(char *string, struct ofp_match *match, struct ofpbuf *actions,
            uint8_t *table_idx, uint16_t *out_port, uint16_t *priority, 
            uint16_t *idle_timeout, uint16_t *hard_timeout, 
            uint64_t *cookie)
{
    char *save_ptr = NULL;
    char *name;
    uint32_t wildcards;

    if (table_idx) {
        *table_idx = 0xff;
    }
    if (out_port) {
        *out_port = OFPP_NONE;
    }
    if (priority) {
        *priority = OFP_DEFAULT_PRIORITY;
    }
    if (idle_timeout) {
        *idle_timeout = DEFAULT_IDLE_TIMEOUT;
    }
    if (hard_timeout) {
        *hard_timeout = OFP_FLOW_PERMANENT;
    }
    if (cookie) {
        *cookie = 0;
    }
    if (actions) {
        char *act_str = strstr(string, "action");
        if (!act_str) {
            ovs_fatal(0, "must specify an action");
        }
        *(act_str-1) = '\0';

        act_str = strchr(act_str, '=');
        if (!act_str) {
            ovs_fatal(0, "must specify an action");
        }

        act_str++;

        str_to_action(act_str, actions);
    }
    memset(match, 0, sizeof *match);
    wildcards = OFPFW_ALL;
    for (name = strtok_r(string, "=, \t\r\n", &save_ptr); name;
         name = strtok_r(NULL, "=, \t\r\n", &save_ptr)) {
        const struct protocol *p;

        if (parse_protocol(name, &p)) {
            wildcards &= ~OFPFW_DL_TYPE;
            match->dl_type = htons(p->dl_type);
            if (p->nw_proto) {
                wildcards &= ~OFPFW_NW_PROTO;
                match->nw_proto = p->nw_proto;
            }
        } else {
            const struct field *f;
            char *value;

            value = strtok_r(NULL, ", \t\r\n", &save_ptr);
            if (!value) {
                ovs_fatal(0, "field %s missing value", name);
            }
        
            if (table_idx && !strcmp(name, "table")) {
                *table_idx = atoi(value);
            } else if (out_port && !strcmp(name, "out_port")) {
                *out_port = atoi(value);
            } else if (priority && !strcmp(name, "priority")) {
                *priority = atoi(value);
            } else if (idle_timeout && !strcmp(name, "idle_timeout")) {
                *idle_timeout = atoi(value);
            } else if (hard_timeout && !strcmp(name, "hard_timeout")) {
                *hard_timeout = atoi(value);
            } else if (cookie && !strcmp(name, "cookie")) {
                *cookie = atoi(value);
            } else if (parse_field(name, &f)) {
                void *data = (char *) match + f->offset;
                if (!strcmp(value, "*") || !strcmp(value, "ANY")) {
                    wildcards |= f->wildcard;
                } else {
                    wildcards &= ~f->wildcard;
                    if (f->wildcard == OFPFW_IN_PORT
                        && parse_port_name(value, (uint16_t *) data)) {
                        /* Nothing to do. */
                    } else if (f->type == F_U8) {
                        *(uint8_t *) data = str_to_u32(value);
                    } else if (f->type == F_U16) {
                        *(uint16_t *) data = htons(str_to_u32(value));
                    } else if (f->type == F_MAC) {
                        str_to_mac(value, data);
                    } else if (f->type == F_IP) {
                        wildcards |= str_to_ip(value, data) << f->shift;
                    } else {
                        NOT_REACHED();
                    }
                }
            } else {
                ovs_fatal(0, "unknown keyword %s", name);
            }
        }
    }
    match->wildcards = htonl(wildcards);
}

static void
do_dump_flows(const struct settings *s UNUSED, int argc, char *argv[])
{
    struct ofp_flow_stats_request *req;
    uint16_t out_port;
    struct ofpbuf *request;

    req = alloc_stats_request(sizeof *req, OFPST_FLOW, &request);
    str_to_flow(argc > 2 ? argv[2] : "", &req->match, NULL,
                &req->table_id, &out_port, NULL, NULL, NULL, NULL);
    memset(&req->pad, 0, sizeof req->pad);
    req->out_port = htons(out_port);

    dump_stats_transaction(argv[1], request);
}

static void
do_dump_aggregate(const struct settings *s UNUSED, int argc, char *argv[])
{
    struct ofp_aggregate_stats_request *req;
    struct ofpbuf *request;
    uint16_t out_port;

    req = alloc_stats_request(sizeof *req, OFPST_AGGREGATE, &request);
    str_to_flow(argc > 2 ? argv[2] : "", &req->match, NULL,
                &req->table_id, &out_port, NULL, NULL, NULL, NULL);
    memset(&req->pad, 0, sizeof req->pad);
    req->out_port = htons(out_port);

    dump_stats_transaction(argv[1], request);
}

static void
do_add_flow(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct vconn *vconn;
    struct ofpbuf *buffer;
    struct ofp_flow_mod *ofm;
    uint16_t priority, idle_timeout, hard_timeout;
    uint64_t cookie;
    struct ofp_match match;

    /* Parse and send.  str_to_flow() will expand and reallocate the data in
     * 'buffer', so we can't keep pointers to across the str_to_flow() call. */
    make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &buffer);
    str_to_flow(argv[2], &match, buffer,
                NULL, NULL, &priority, &idle_timeout, &hard_timeout,
                &cookie);
    ofm = buffer->data;
    ofm->match = match;
    ofm->command = htons(OFPFC_ADD);
    ofm->cookie = htonll(cookie);
    ofm->idle_timeout = htons(idle_timeout);
    ofm->hard_timeout = htons(hard_timeout);
    ofm->buffer_id = htonl(UINT32_MAX);
    ofm->priority = htons(priority);

    open_vconn(argv[1], &vconn);
    send_openflow_buffer(vconn, buffer);
    vconn_close(vconn);
}

static void
do_add_flows(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct vconn *vconn;
    FILE *file;
    char line[1024];

    file = fopen(argv[2], "r");
    if (file == NULL) {
        ovs_fatal(errno, "%s: open", argv[2]);
    }

    open_vconn(argv[1], &vconn);
    while (fgets(line, sizeof line, file)) {
        struct ofpbuf *buffer;
        struct ofp_flow_mod *ofm;
        uint16_t priority, idle_timeout, hard_timeout;
        uint64_t cookie;
        struct ofp_match match;

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

        /* Parse and send.  str_to_flow() will expand and reallocate the data
         * in 'buffer', so we can't keep pointers to across the str_to_flow()
         * call. */
        ofm = make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &buffer);
        str_to_flow(line, &match, buffer,
                    NULL, NULL, &priority, &idle_timeout, &hard_timeout,
                    &cookie);
        ofm = buffer->data;
        ofm->match = match;
        ofm->command = htons(OFPFC_ADD);
        ofm->cookie = htonll(cookie);
        ofm->idle_timeout = htons(idle_timeout);
        ofm->hard_timeout = htons(hard_timeout);
        ofm->buffer_id = htonl(UINT32_MAX);
        ofm->priority = htons(priority);

        send_openflow_buffer(vconn, buffer);
    }
    vconn_close(vconn);
    fclose(file);
}

static void
do_mod_flows(const struct settings *s, int argc UNUSED, char *argv[])
{
    uint16_t priority, idle_timeout, hard_timeout;
    uint64_t cookie;
    struct vconn *vconn;
    struct ofpbuf *buffer;
    struct ofp_flow_mod *ofm;
    struct ofp_match match;

    /* Parse and send.  str_to_flow() will expand and reallocate the data in
     * 'buffer', so we can't keep pointers to across the str_to_flow() call. */
    make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &buffer);
    str_to_flow(argv[2], &match, buffer,
                NULL, NULL, &priority, &idle_timeout, &hard_timeout,
                &cookie);
    ofm = buffer->data;
    ofm->match = match;
    if (s->strict) {
        ofm->command = htons(OFPFC_MODIFY_STRICT);
    } else {
        ofm->command = htons(OFPFC_MODIFY);
    }
    ofm->idle_timeout = htons(idle_timeout);
    ofm->hard_timeout = htons(hard_timeout);
    ofm->cookie = htonll(cookie);
    ofm->buffer_id = htonl(UINT32_MAX);
    ofm->priority = htons(priority);

    open_vconn(argv[1], &vconn);
    send_openflow_buffer(vconn, buffer);
    vconn_close(vconn);
}

static void do_del_flows(const struct settings *s, int argc, char *argv[])
{
    struct vconn *vconn;
    uint16_t priority;
    uint16_t out_port;
    struct ofpbuf *buffer;
    struct ofp_flow_mod *ofm;

    /* Parse and send. */
    ofm = make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &buffer);
    str_to_flow(argc > 2 ? argv[2] : "", &ofm->match, NULL, NULL, 
                &out_port, &priority, NULL, NULL, NULL);
    if (s->strict) {
        ofm->command = htons(OFPFC_DELETE_STRICT);
    } else {
        ofm->command = htons(OFPFC_DELETE);
    }
    ofm->idle_timeout = htons(0);
    ofm->hard_timeout = htons(0);
    ofm->buffer_id = htonl(UINT32_MAX);
    ofm->out_port = htons(out_port);
    ofm->priority = htons(priority);

    open_vconn(argv[1], &vconn);
    send_openflow_buffer(vconn, buffer);
    vconn_close(vconn);
}

static void
do_monitor(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct vconn *vconn;

    open_vconn(argv[1], &vconn);
    if (argc > 2) {
        int miss_send_len = atoi(argv[2]);
        struct ofp_switch_config *osc;
        struct ofpbuf *buf;

        osc = make_openflow(sizeof *osc, OFPT_SET_CONFIG, &buf);
        osc->miss_send_len = htons(miss_send_len);
        send_openflow_buffer(vconn, buf);
    }
    for (;;) {
        struct ofpbuf *b;
        run(vconn_recv_block(vconn, &b), "vconn_recv");
        ofp_print(stderr, b->data, b->size, 2);
        ofpbuf_delete(b);
    }
}

static void
do_dump_ports(const struct settings *s UNUSED, int argc, char *argv[])
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
do_probe(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
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
do_mod_port(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
{
    struct ofpbuf *request, *reply;
    struct ofp_switch_features *osf;
    struct ofp_port_mod *opm;
    struct vconn *vconn;
    char *endptr;
    int n_ports;
    int port_idx;
    int port_no;
    

    /* Check if the argument is a port index.  Otherwise, treat it as
     * the port name. */
    port_no = strtol(argv[2], &endptr, 10);
    if (port_no == 0 && endptr == argv[2]) {
        port_no = -1;
    }

    /* Send a "Features Request" to get the information we need in order 
     * to modify the port. */
    make_openflow(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, &request);
    open_vconn(argv[1], &vconn);
    run(vconn_transact(vconn, request, &reply), "talking to %s", argv[1]);

    osf = reply->data;
    n_ports = (reply->size - sizeof *osf) / sizeof *osf->ports;

    for (port_idx = 0; port_idx < n_ports; port_idx++) {
        if (port_no != -1) {
            /* Check argument as a port index */
            if (osf->ports[port_idx].port_no == htons(port_no)) {
                break;
            }
        } else {
            /* Check argument as an interface name */
            if (!strncmp((char *)osf->ports[port_idx].name, argv[2], 
                        sizeof osf->ports[0].name)) {
                break;
            }

        }
    }
    if (port_idx == n_ports) {
        ovs_fatal(0, "couldn't find monitored port: %s", argv[2]);
    }

    opm = make_openflow(sizeof(struct ofp_port_mod), OFPT_PORT_MOD, &request);
    opm->port_no = osf->ports[port_idx].port_no;
    memcpy(opm->hw_addr, osf->ports[port_idx].hw_addr, sizeof opm->hw_addr);
    opm->config = htonl(0);
    opm->mask = htonl(0);
    opm->advertise = htonl(0);

    printf("modifying port: %s\n", osf->ports[port_idx].name);

    if (!strncasecmp(argv[3], MOD_PORT_CMD_UP, sizeof MOD_PORT_CMD_UP)) {
        opm->mask |= htonl(OFPPC_PORT_DOWN);
    } else if (!strncasecmp(argv[3], MOD_PORT_CMD_DOWN, 
                sizeof MOD_PORT_CMD_DOWN)) {
        opm->mask |= htonl(OFPPC_PORT_DOWN);
        opm->config |= htonl(OFPPC_PORT_DOWN);
    } else if (!strncasecmp(argv[3], MOD_PORT_CMD_FLOOD, 
                sizeof MOD_PORT_CMD_FLOOD)) {
        opm->mask |= htonl(OFPPC_NO_FLOOD);
    } else if (!strncasecmp(argv[3], MOD_PORT_CMD_NOFLOOD, 
                sizeof MOD_PORT_CMD_NOFLOOD)) {
        opm->mask |= htonl(OFPPC_NO_FLOOD);
        opm->config |= htonl(OFPPC_NO_FLOOD);
    } else {
        ovs_fatal(0, "unknown mod-port command '%s'", argv[3]);
    }

    send_openflow_buffer(vconn, request);

    ofpbuf_delete(reply);
    vconn_close(vconn);
}

static void
do_ping(const struct settings *s UNUSED, int argc, char *argv[])
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
            ofp_print(stdout, request, request->size, 2);
            printf("Reply:\n");
            ofp_print(stdout, reply, reply->size, 2);
        }
        printf("%zu bytes from %s: xid=%08"PRIx32" time=%.1f ms\n",
               reply->size - sizeof *rpy_hdr, argv[1], rpy_hdr->xid,
                   (1000*(double)(end.tv_sec - start.tv_sec))
                   + (.001*(end.tv_usec - start.tv_usec)));
        ofpbuf_delete(request);
        ofpbuf_delete(reply);
    }
    vconn_close(vconn);
}

static void
do_benchmark(const struct settings *s UNUSED, int argc UNUSED, char *argv[])
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
do_execute(const struct settings *s UNUSED, int argc, char *argv[])
{
    struct vconn *vconn;
    struct ofpbuf *request;
    struct nicira_header *nicira;
    struct nx_command_reply *ncr;
    uint32_t xid;
    int i;

    nicira = make_openflow(sizeof *nicira, OFPT_VENDOR, &request);
    xid = nicira->header.xid;
    nicira->vendor = htonl(NX_VENDOR_ID);
    nicira->subtype = htonl(NXT_COMMAND_REQUEST);
    ofpbuf_put(request, argv[2], strlen(argv[2]));
    for (i = 3; i < argc; i++) {
        ofpbuf_put_zeros(request, 1);
        ofpbuf_put(request, argv[i], strlen(argv[i]));
    }
    update_openflow_length(request);

    open_vconn(argv[1], &vconn);
    run(vconn_send_block(vconn, request), "send");

    for (;;) {
        struct ofpbuf *reply;
        uint32_t status;

        run(vconn_recv_xid(vconn, xid, &reply), "recv_xid");
        if (reply->size < sizeof *ncr) {
            ovs_fatal(0, "reply is too short (%zu bytes < %zu bytes)",
                      reply->size, sizeof *ncr);
        }
        ncr = reply->data;
        if (ncr->nxh.header.type != OFPT_VENDOR
            || ncr->nxh.vendor != htonl(NX_VENDOR_ID)
            || ncr->nxh.subtype != htonl(NXT_COMMAND_REPLY)) {
            ovs_fatal(0, "reply is invalid");
        }

        status = ntohl(ncr->status);
        if (status & NXT_STATUS_STARTED) {
            /* Wait for a second reply. */
            continue;
        } else if (status & NXT_STATUS_EXITED) {
            fprintf(stderr, "process terminated normally with exit code %d",
                    status & NXT_STATUS_EXITSTATUS);
        } else if (status & NXT_STATUS_SIGNALED) {
            fprintf(stderr, "process terminated by signal %d",
                    status & NXT_STATUS_TERMSIG);
        } else if (status & NXT_STATUS_ERROR) {
            fprintf(stderr, "error executing command");
        } else {
            fprintf(stderr, "process terminated for unknown reason");
        }
        if (status & NXT_STATUS_COREDUMP) {
            fprintf(stderr, " (core dumped)");
        }
        putc('\n', stderr);

        fwrite(ncr + 1, reply->size - sizeof *ncr, 1, stdout);
        break;
    }
}

static void
do_help(const struct settings *s UNUSED, int argc UNUSED, char *argv[] UNUSED)
{
    usage();
}

static struct command all_commands[] = {
    { "show", 1, 1, do_show },
    { "status", 1, 2, do_status },
    { "monitor", 1, 3, do_monitor },
    { "dump-desc", 1, 1, do_dump_desc },
    { "dump-tables", 1, 1, do_dump_tables },
    { "dump-flows", 1, 2, do_dump_flows },
    { "dump-aggregate", 1, 2, do_dump_aggregate },
    { "add-flow", 2, 2, do_add_flow },
    { "add-flows", 2, 2, do_add_flows },
    { "mod-flows", 2, 2, do_mod_flows },
    { "del-flows", 1, 2, do_del_flows },
    { "dump-ports", 1, 2, do_dump_ports },
    { "mod-port", 3, 3, do_mod_port },
    { "probe", 1, 1, do_probe },
    { "ping", 1, 2, do_ping },
    { "benchmark", 3, 3, do_benchmark },
    { "execute", 2, INT_MAX, do_execute },
    { "help", 0, INT_MAX, do_help },
    { NULL, 0, 0, NULL },
};
