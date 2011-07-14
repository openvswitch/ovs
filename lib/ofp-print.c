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
#include "ofp-print.h"

#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "bundle.h"
#include "byte-order.h"
#include "compiler.h"
#include "dynamic-string.h"
#include "flow.h"
#include "multipath.h"
#include "nx-match.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "pcap.h"
#include "type-props.h"
#include "unaligned.h"
#include "util.h"

static void ofp_print_port_name(struct ds *string, uint16_t port);
static void ofp_print_queue_name(struct ds *string, uint32_t port);
static void ofp_print_error(struct ds *, int error);


/* Returns a string that represents the contents of the Ethernet frame in the
 * 'len' bytes starting at 'data' to 'stream' as output by tcpdump.
 * 'total_len' specifies the full length of the Ethernet frame (of which 'len'
 * bytes were captured).
 *
 * The caller must free the returned string.
 *
 * This starts and kills a tcpdump subprocess so it's quite expensive. */
char *
ofp_packet_to_string(const void *data, size_t len, size_t total_len OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct ofpbuf buf;

    char command[128];
    FILE *pcap;
    FILE *tcpdump;
    int status;
    int c;

    ofpbuf_use_const(&buf, data, len);

    pcap = tmpfile();
    if (!pcap) {
        ovs_error(errno, "tmpfile");
        return xstrdup("<error>");
    }
    pcap_write_header(pcap);
    pcap_write(pcap, &buf);
    fflush(pcap);
    if (ferror(pcap)) {
        ovs_error(errno, "error writing temporary file");
    }
    rewind(pcap);

    snprintf(command, sizeof command, "/usr/sbin/tcpdump -t -e -n -r /dev/fd/%d 2>/dev/null",
             fileno(pcap));
    tcpdump = popen(command, "r");
    fclose(pcap);
    if (!tcpdump) {
        ovs_error(errno, "exec(\"%s\")", command);
        return xstrdup("<error>");
    }

    while ((c = getc(tcpdump)) != EOF) {
        ds_put_char(&ds, c);
    }

    status = pclose(tcpdump);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status))
            ovs_error(0, "tcpdump exited with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        ovs_error(0, "tcpdump exited with signal %d", WTERMSIG(status));
    }
    return ds_cstr(&ds);
}

static void
ofp_print_packet_in(struct ds *string, const struct ofp_packet_in *op,
                    int verbosity)
{
    size_t len = ntohs(op->header.length);
    size_t data_len;

    ds_put_format(string, " total_len=%"PRIu16" in_port=",
                  ntohs(op->total_len));
    ofp_print_port_name(string, ntohs(op->in_port));

    if (op->reason == OFPR_ACTION)
        ds_put_cstr(string, " (via action)");
    else if (op->reason != OFPR_NO_MATCH)
        ds_put_format(string, " (***reason %"PRIu8"***)", op->reason);

    data_len = len - offsetof(struct ofp_packet_in, data);
    ds_put_format(string, " data_len=%zu", data_len);
    if (op->buffer_id == htonl(UINT32_MAX)) {
        ds_put_format(string, " (unbuffered)");
        if (ntohs(op->total_len) != data_len)
            ds_put_format(string, " (***total_len != data_len***)");
    } else {
        ds_put_format(string, " buffer=0x%08"PRIx32, ntohl(op->buffer_id));
        if (ntohs(op->total_len) < data_len)
            ds_put_format(string, " (***total_len < data_len***)");
    }
    ds_put_char(string, '\n');

    if (verbosity > 0) {
        struct flow flow;
        struct ofpbuf packet;

        ofpbuf_use_const(&packet, op->data, data_len);
        flow_extract(&packet, 0, ntohs(op->in_port), &flow);
        flow_format(string, &flow);
        ds_put_char(string, '\n');
    }
    if (verbosity > 1) {
        char *packet = ofp_packet_to_string(op->data, data_len,
                                            ntohs(op->total_len));
        ds_put_cstr(string, packet);
        free(packet);
    }
}

static void ofp_print_port_name(struct ds *string, uint16_t port)
{
    const char *name;
    switch (port) {
    case OFPP_IN_PORT:
        name = "IN_PORT";
        break;
    case OFPP_TABLE:
        name = "TABLE";
        break;
    case OFPP_NORMAL:
        name = "NORMAL";
        break;
    case OFPP_FLOOD:
        name = "FLOOD";
        break;
    case OFPP_ALL:
        name = "ALL";
        break;
    case OFPP_CONTROLLER:
        name = "CONTROLLER";
        break;
    case OFPP_LOCAL:
        name = "LOCAL";
        break;
    case OFPP_NONE:
        name = "NONE";
        break;
    default:
        ds_put_format(string, "%"PRIu16, port);
        return;
    }
    ds_put_cstr(string, name);
}


static void
print_note(struct ds *string, const struct nx_action_note *nan)
{
    size_t len;
    size_t i;

    ds_put_cstr(string, "note:");
    len = ntohs(nan->len) - offsetof(struct nx_action_note, note);
    for (i = 0; i < len; i++) {
        if (i) {
            ds_put_char(string, '.');
        }
        ds_put_format(string, "%02"PRIx8, nan->note[i]);
    }
}

static void
ofp_print_action(struct ds *s, const union ofp_action *a,
                 enum ofputil_action_code code)
{
    const struct ofp_action_enqueue *oae;
    const struct ofp_action_dl_addr *oada;
    const struct nx_action_set_tunnel64 *nast64;
    const struct nx_action_set_tunnel *nast;
    const struct nx_action_set_queue *nasq;
    const struct nx_action_resubmit *nar;
    const struct nx_action_reg_move *move;
    const struct nx_action_reg_load *load;
    const struct nx_action_multipath *nam;
    const struct nx_action_autopath *naa;
    uint16_t port;

    switch (code) {
    case OFPUTIL_OFPAT_OUTPUT:
        port = ntohs(a->output.port);
        if (port < OFPP_MAX) {
            ds_put_format(s, "output:%"PRIu16, port);
        } else {
            ofp_print_port_name(s, port);
            if (port == OFPP_CONTROLLER) {
                if (a->output.max_len != htons(0)) {
                    ds_put_format(s, ":%"PRIu16, ntohs(a->output.max_len));
                } else {
                    ds_put_cstr(s, ":all");
                }
            }
        }
        break;

    case OFPUTIL_OFPAT_ENQUEUE:
        oae = (const struct ofp_action_enqueue *) a;
        ds_put_format(s, "enqueue:");
        ofp_print_port_name(s, ntohs(oae->port));
        ds_put_format(s, "q%"PRIu32, ntohl(oae->queue_id));
        break;

    case OFPUTIL_OFPAT_SET_VLAN_VID:
        ds_put_format(s, "mod_vlan_vid:%"PRIu16,
                      ntohs(a->vlan_vid.vlan_vid));
        break;

    case OFPUTIL_OFPAT_SET_VLAN_PCP:
        ds_put_format(s, "mod_vlan_pcp:%"PRIu8, a->vlan_pcp.vlan_pcp);
        break;

    case OFPUTIL_OFPAT_STRIP_VLAN:
        ds_put_cstr(s, "strip_vlan");
        break;

    case OFPUTIL_OFPAT_SET_DL_SRC:
        oada = (const struct ofp_action_dl_addr *) a;
        ds_put_format(s, "mod_dl_src:"ETH_ADDR_FMT,
                      ETH_ADDR_ARGS(oada->dl_addr));
        break;

    case OFPUTIL_OFPAT_SET_DL_DST:
        oada = (const struct ofp_action_dl_addr *) a;
        ds_put_format(s, "mod_dl_dst:"ETH_ADDR_FMT,
                      ETH_ADDR_ARGS(oada->dl_addr));
        break;

    case OFPUTIL_OFPAT_SET_NW_SRC:
        ds_put_format(s, "mod_nw_src:"IP_FMT, IP_ARGS(&a->nw_addr.nw_addr));
        break;

    case OFPUTIL_OFPAT_SET_NW_DST:
        ds_put_format(s, "mod_nw_dst:"IP_FMT, IP_ARGS(&a->nw_addr.nw_addr));
        break;

    case OFPUTIL_OFPAT_SET_NW_TOS:
        ds_put_format(s, "mod_nw_tos:%d", a->nw_tos.nw_tos);
        break;

    case OFPUTIL_OFPAT_SET_TP_SRC:
        ds_put_format(s, "mod_tp_src:%d", ntohs(a->tp_port.tp_port));
        break;

    case OFPUTIL_OFPAT_SET_TP_DST:
        ds_put_format(s, "mod_tp_dst:%d", ntohs(a->tp_port.tp_port));
        break;

    case OFPUTIL_NXAST_RESUBMIT:
        nar = (struct nx_action_resubmit *)a;
        ds_put_format(s, "resubmit:");
        ofp_print_port_name(s, ntohs(nar->in_port));
        break;

    case OFPUTIL_NXAST_SET_TUNNEL:
        nast = (struct nx_action_set_tunnel *)a;
        ds_put_format(s, "set_tunnel:%#"PRIx32, ntohl(nast->tun_id));
        break;

    case OFPUTIL_NXAST_SET_QUEUE:
        nasq = (struct nx_action_set_queue *)a;
        ds_put_format(s, "set_queue:%u", ntohl(nasq->queue_id));
        break;

    case OFPUTIL_NXAST_POP_QUEUE:
        ds_put_cstr(s, "pop_queue");
        break;

    case OFPUTIL_NXAST_NOTE:
        print_note(s, (const struct nx_action_note *) a);
        break;

    case OFPUTIL_NXAST_REG_MOVE:
        move = (const struct nx_action_reg_move *) a;
        nxm_format_reg_move(move, s);
        break;

    case OFPUTIL_NXAST_REG_LOAD:
        load = (const struct nx_action_reg_load *) a;
        nxm_format_reg_load(load, s);
        break;

    case OFPUTIL_NXAST_SET_TUNNEL64:
        nast64 = (const struct nx_action_set_tunnel64 *) a;
        ds_put_format(s, "set_tunnel64:%#"PRIx64,
                      ntohll(nast64->tun_id));
        break;

    case OFPUTIL_NXAST_MULTIPATH:
        nam = (const struct nx_action_multipath *) a;
        multipath_format(nam, s);
        break;

    case OFPUTIL_NXAST_AUTOPATH:
        naa = (const struct nx_action_autopath *)a;
        ds_put_format(s, "autopath(%u,", ntohl(naa->id));
        nxm_format_field_bits(s, ntohl(naa->dst),
                              nxm_decode_ofs(naa->ofs_nbits),
                              nxm_decode_n_bits(naa->ofs_nbits));
        ds_put_char(s, ')');
        break;

    case OFPUTIL_NXAST_BUNDLE:
    case OFPUTIL_NXAST_BUNDLE_LOAD:
        bundle_format((const struct nx_action_bundle *) a, s);
        break;

    default:
        break;
    }
}

void
ofp_print_actions(struct ds *string, const union ofp_action *actions,
                  size_t n_actions)
{
    const union ofp_action *a;
    size_t left;

    ds_put_cstr(string, "actions=");
    if (!n_actions) {
        ds_put_cstr(string, "drop");
    }

    OFPUTIL_ACTION_FOR_EACH (a, left, actions, n_actions) {
        int code = ofputil_decode_action(a);
        if (code >= 0) {
            if (a != actions) {
                ds_put_cstr(string, ",");
            }
            ofp_print_action(string, a, code);
        } else {
            ofp_print_error(string, -code);
        }
    }
    if (left > 0) {
        ds_put_format(string, " ***%zu leftover bytes following actions",
                      left * sizeof *a);
    }
}

static void
ofp_print_packet_out(struct ds *string, const struct ofp_packet_out *opo,
                     int verbosity)
{
    size_t len = ntohs(opo->header.length);
    size_t actions_len = ntohs(opo->actions_len);

    ds_put_cstr(string, " in_port=");
    ofp_print_port_name(string, ntohs(opo->in_port));

    ds_put_format(string, " actions_len=%zu ", actions_len);
    if (actions_len > (ntohs(opo->header.length) - sizeof *opo)) {
        ds_put_format(string, "***packet too short for action length***\n");
        return;
    }
    if (actions_len % sizeof(union ofp_action)) {
        ds_put_format(string, "***action length not a multiple of %zu***\n",
                      sizeof(union ofp_action));
    }
    ofp_print_actions(string, (const union ofp_action *) opo->actions,
                      actions_len / sizeof(union ofp_action));

    if (ntohl(opo->buffer_id) == UINT32_MAX) {
        int data_len = len - sizeof *opo - actions_len;
        ds_put_format(string, " data_len=%d", data_len);
        if (verbosity > 0 && len > sizeof *opo) {
            char *packet = ofp_packet_to_string(
                    (uint8_t *)opo->actions + actions_len, data_len, data_len);
            ds_put_char(string, '\n');
            ds_put_cstr(string, packet);
            free(packet);
        }
    } else {
        ds_put_format(string, " buffer=0x%08"PRIx32, ntohl(opo->buffer_id));
    }
    ds_put_char(string, '\n');
}

/* qsort comparison function. */
static int
compare_ports(const void *a_, const void *b_)
{
    const struct ofp_phy_port *a = a_;
    const struct ofp_phy_port *b = b_;
    uint16_t ap = ntohs(a->port_no);
    uint16_t bp = ntohs(b->port_no);

    return ap < bp ? -1 : ap > bp;
}

struct bit_name {
    uint32_t bit;
    const char *name;
};

static void
ofp_print_bit_names(struct ds *string, uint32_t bits,
                    const struct bit_name bit_names[])
{
    int n = 0;

    if (!bits) {
        ds_put_cstr(string, "0");
        return;
    }

    for (; bits && bit_names->name; bit_names++) {
        if (bits & bit_names->bit) {
            if (n++) {
                ds_put_char(string, ' ');
            }
            ds_put_cstr(string, bit_names->name);
            bits &= ~bit_names->bit;
        }
    }

    if (bits) {
        if (n++) {
            ds_put_char(string, ' ');
        }
        ds_put_format(string, "0x%"PRIx32, bits);
    }
}

static void
ofp_print_port_features(struct ds *string, uint32_t features)
{
    static const struct bit_name feature_bits[] = {
        { OFPPF_10MB_HD,    "10MB-HD" },
        { OFPPF_10MB_FD,    "10MB-FD" },
        { OFPPF_100MB_HD,   "100MB-HD" },
        { OFPPF_100MB_FD,   "100MB-FD" },
        { OFPPF_1GB_HD,     "1GB-HD" },
        { OFPPF_1GB_FD,     "1GB-FD" },
        { OFPPF_10GB_FD,    "10GB-FD" },
        { OFPPF_COPPER,     "COPPER" },
        { OFPPF_FIBER,      "FIBER" },
        { OFPPF_AUTONEG,    "AUTO_NEG" },
        { OFPPF_PAUSE,      "AUTO_PAUSE" },
        { OFPPF_PAUSE_ASYM, "AUTO_PAUSE_ASYM" },
        { 0,                NULL },
    };

    ofp_print_bit_names(string, features, feature_bits);
    ds_put_char(string, '\n');
}

static void
ofp_print_port_config(struct ds *string, uint32_t config)
{
    static const struct bit_name config_bits[] = {
        { OFPPC_PORT_DOWN,    "PORT_DOWN" },
        { OFPPC_NO_STP,       "NO_STP" },
        { OFPPC_NO_RECV,      "NO_RECV" },
        { OFPPC_NO_RECV_STP,  "NO_RECV_STP" },
        { OFPPC_NO_FLOOD,     "NO_FLOOD" },
        { OFPPC_NO_FWD,       "NO_FWD" },
        { OFPPC_NO_PACKET_IN, "NO_PACKET_IN" },
        { 0,                  NULL },
    };

    ofp_print_bit_names(string, config, config_bits);
    ds_put_char(string, '\n');
}

static void
ofp_print_port_state(struct ds *string, uint32_t state)
{
    static const struct bit_name state_bits[] = {
        { OFPPS_LINK_DOWN, "LINK_DOWN" },
        { 0,               NULL },
    };
    uint32_t stp_state;

    /* The STP state is a 2-bit field so it doesn't fit in with the bitmask
     * pattern.  We have to special case it.
     *
     * OVS doesn't support STP, so this field will always be 0 if we are
     * talking to OVS, so we'd always print STP_LISTEN in that case.
     * Therefore, we don't print anything at all if the value is STP_LISTEN, to
     * avoid confusing users. */
    stp_state = state & OFPPS_STP_MASK;
    if (stp_state) {
        ds_put_cstr(string, (stp_state == OFPPS_STP_LEARN ? "STP_LEARN"
                             : stp_state == OFPPS_STP_FORWARD ? "STP_FORWARD"
                             : "STP_BLOCK"));
        state &= ~OFPPS_STP_MASK;
        if (state) {
            ofp_print_bit_names(string, state, state_bits);
        }
    } else {
        ofp_print_bit_names(string, state, state_bits);
    }
    ds_put_char(string, '\n');
}

static void
ofp_print_phy_port(struct ds *string, const struct ofp_phy_port *port)
{
    char name[OFP_MAX_PORT_NAME_LEN];
    int j;

    memcpy(name, port->name, sizeof name);
    for (j = 0; j < sizeof name - 1; j++) {
        if (!isprint((unsigned char) name[j])) {
            break;
        }
    }
    name[j] = '\0';

    ds_put_char(string, ' ');
    ofp_print_port_name(string, ntohs(port->port_no));
    ds_put_format(string, "(%s): addr:"ETH_ADDR_FMT"\n",
                  name, ETH_ADDR_ARGS(port->hw_addr));

    ds_put_cstr(string, "     config:     ");
    ofp_print_port_config(string, ntohl(port->config));

    ds_put_cstr(string, "     state:      ");
    ofp_print_port_state(string, ntohl(port->state));

    if (port->curr) {
        ds_put_format(string, "     current:    ");
        ofp_print_port_features(string, ntohl(port->curr));
    }
    if (port->advertised) {
        ds_put_format(string, "     advertised: ");
        ofp_print_port_features(string, ntohl(port->advertised));
    }
    if (port->supported) {
        ds_put_format(string, "     supported:  ");
        ofp_print_port_features(string, ntohl(port->supported));
    }
    if (port->peer) {
        ds_put_format(string, "     peer:       ");
        ofp_print_port_features(string, ntohl(port->peer));
    }
}

static void
ofp_print_switch_features(struct ds *string,
                          const struct ofp_switch_features *osf)
{
    size_t len = ntohs(osf->header.length);
    struct ofp_phy_port *port_list;
    int n_ports;
    int i;

    ds_put_format(string, " ver:0x%x, dpid:%016"PRIx64"\n",
            osf->header.version, ntohll(osf->datapath_id));
    ds_put_format(string, "n_tables:%d, n_buffers:%d\n", osf->n_tables,
            ntohl(osf->n_buffers));
    ds_put_format(string, "features: capabilities:%#x, actions:%#x\n",
           ntohl(osf->capabilities), ntohl(osf->actions));

    n_ports = (len - sizeof *osf) / sizeof *osf->ports;

    port_list = xmemdup(osf->ports, len - sizeof *osf);
    qsort(port_list, n_ports, sizeof *port_list, compare_ports);
    for (i = 0; i < n_ports; i++) {
        ofp_print_phy_port(string, &port_list[i]);
    }
    free(port_list);
}

static void
ofp_print_switch_config(struct ds *string, const struct ofp_switch_config *osc)
{
    uint16_t flags;

    flags = ntohs(osc->flags);

    ds_put_cstr(string, " frags=");
    switch (flags & OFPC_FRAG_MASK) {
    case OFPC_FRAG_NORMAL:
        ds_put_cstr(string, "normal");
        flags &= ~OFPC_FRAG_MASK;
        break;
    case OFPC_FRAG_DROP:
        ds_put_cstr(string, "drop");
        flags &= ~OFPC_FRAG_MASK;
        break;
    case OFPC_FRAG_REASM:
        ds_put_cstr(string, "reassemble");
        flags &= ~OFPC_FRAG_MASK;
        break;
    }
    if (flags) {
        ds_put_format(string, " ***unknown flags 0x%04"PRIx16"***", flags);
    }

    ds_put_format(string, " miss_send_len=%"PRIu16"\n", ntohs(osc->miss_send_len));
}

static void print_wild(struct ds *string, const char *leader, int is_wild,
            int verbosity, const char *format, ...)
            __attribute__((format(printf, 5, 6)));

static void print_wild(struct ds *string, const char *leader, int is_wild,
                       int verbosity, const char *format, ...)
{
    if (is_wild && verbosity < 2) {
        return;
    }
    ds_put_cstr(string, leader);
    if (!is_wild) {
        va_list args;

        va_start(args, format);
        ds_put_format_valist(string, format, args);
        va_end(args);
    } else {
        ds_put_char(string, '*');
    }
    ds_put_char(string, ',');
}

static void
print_ip_netmask(struct ds *string, const char *leader, ovs_be32 ip,
                 uint32_t wild_bits, int verbosity)
{
    if (wild_bits >= 32 && verbosity < 2) {
        return;
    }
    ds_put_cstr(string, leader);
    if (wild_bits < 32) {
        ds_put_format(string, IP_FMT, IP_ARGS(&ip));
        if (wild_bits) {
            ds_put_format(string, "/%d", 32 - wild_bits);
        }
    } else {
        ds_put_char(string, '*');
    }
    ds_put_char(string, ',');
}

void
ofp_print_match(struct ds *f, const struct ofp_match *om, int verbosity)
{
    char *s = ofp_match_to_string(om, verbosity);
    ds_put_cstr(f, s);
    free(s);
}

char *
ofp_match_to_string(const struct ofp_match *om, int verbosity)
{
    struct ds f = DS_EMPTY_INITIALIZER;
    uint32_t w = ntohl(om->wildcards);
    bool skip_type = false;
    bool skip_proto = false;

    if (!(w & OFPFW_DL_TYPE)) {
        skip_type = true;
        if (om->dl_type == htons(ETH_TYPE_IP)) {
            if (!(w & OFPFW_NW_PROTO)) {
                skip_proto = true;
                if (om->nw_proto == IPPROTO_ICMP) {
                    ds_put_cstr(&f, "icmp,");
                } else if (om->nw_proto == IPPROTO_TCP) {
                    ds_put_cstr(&f, "tcp,");
                } else if (om->nw_proto == IPPROTO_UDP) {
                    ds_put_cstr(&f, "udp,");
                } else {
                    ds_put_cstr(&f, "ip,");
                    skip_proto = false;
                }
            } else {
                ds_put_cstr(&f, "ip,");
            }
        } else if (om->dl_type == htons(ETH_TYPE_ARP)) {
            ds_put_cstr(&f, "arp,");
        } else {
            skip_type = false;
        }
    }
    print_wild(&f, "in_port=", w & OFPFW_IN_PORT, verbosity,
               "%d", ntohs(om->in_port));
    print_wild(&f, "dl_vlan=", w & OFPFW_DL_VLAN, verbosity,
               "%d", ntohs(om->dl_vlan));
    print_wild(&f, "dl_vlan_pcp=", w & OFPFW_DL_VLAN_PCP, verbosity,
               "%d", om->dl_vlan_pcp);
    print_wild(&f, "dl_src=", w & OFPFW_DL_SRC, verbosity,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_src));
    print_wild(&f, "dl_dst=", w & OFPFW_DL_DST, verbosity,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_dst));
    if (!skip_type) {
        print_wild(&f, "dl_type=", w & OFPFW_DL_TYPE, verbosity,
                   "0x%04x", ntohs(om->dl_type));
    }
    print_ip_netmask(&f, "nw_src=", om->nw_src,
                     (w & OFPFW_NW_SRC_MASK) >> OFPFW_NW_SRC_SHIFT, verbosity);
    print_ip_netmask(&f, "nw_dst=", om->nw_dst,
                     (w & OFPFW_NW_DST_MASK) >> OFPFW_NW_DST_SHIFT, verbosity);
    if (!skip_proto) {
        if (om->dl_type == htons(ETH_TYPE_ARP)) {
            print_wild(&f, "arp_op=", w & OFPFW_NW_PROTO, verbosity,
                       "%u", om->nw_proto);
        } else {
            print_wild(&f, "nw_proto=", w & OFPFW_NW_PROTO, verbosity,
                       "%u", om->nw_proto);
        }
    }
    print_wild(&f, "nw_tos=", w & OFPFW_NW_TOS, verbosity,
               "%u", om->nw_tos);
    if (om->nw_proto == IPPROTO_ICMP) {
        print_wild(&f, "icmp_type=", w & OFPFW_ICMP_TYPE, verbosity,
                   "%d", ntohs(om->icmp_type));
        print_wild(&f, "icmp_code=", w & OFPFW_ICMP_CODE, verbosity,
                   "%d", ntohs(om->icmp_code));
    } else {
        print_wild(&f, "tp_src=", w & OFPFW_TP_SRC, verbosity,
                   "%d", ntohs(om->tp_src));
        print_wild(&f, "tp_dst=", w & OFPFW_TP_DST, verbosity,
                   "%d", ntohs(om->tp_dst));
    }
    if (ds_last(&f) == ',') {
        f.length--;
    }
    return ds_cstr(&f);
}

static void
ofp_print_flow_mod(struct ds *s, const struct ofp_header *oh,
                   enum ofputil_msg_code code, int verbosity)
{
    struct flow_mod fm;
    bool need_priority;
    int error;

    error = ofputil_decode_flow_mod(&fm, oh, true);
    if (error) {
        ofp_print_error(s, error);
        return;
    }

    ds_put_char(s, ' ');
    switch (fm.command) {
    case OFPFC_ADD:
        ds_put_cstr(s, "ADD");
        break;
    case OFPFC_MODIFY:
        ds_put_cstr(s, "MOD");
        break;
    case OFPFC_MODIFY_STRICT:
        ds_put_cstr(s, "MOD_STRICT");
        break;
    case OFPFC_DELETE:
        ds_put_cstr(s, "DEL");
        break;
    case OFPFC_DELETE_STRICT:
        ds_put_cstr(s, "DEL_STRICT");
        break;
    default:
        ds_put_format(s, "cmd:%d", fm.command);
    }
    if (fm.table_id != 0) {
        ds_put_format(s, " table:%d", fm.table_id);
    }

    ds_put_char(s, ' ');
    if (verbosity >= 3 && code == OFPUTIL_OFPT_FLOW_MOD) {
        const struct ofp_flow_mod *ofm = (const struct ofp_flow_mod *) oh;
        ofp_print_match(s, &ofm->match, verbosity);

        /* ofp_print_match() doesn't print priority. */
        need_priority = true;
    } else if (verbosity >= 3 && code == OFPUTIL_NXT_FLOW_MOD) {
        const struct nx_flow_mod *nfm = (const struct nx_flow_mod *) oh;
        const void *nxm = nfm + 1;
        char *nxm_s;

        nxm_s = nx_match_to_string(nxm, ntohs(nfm->match_len));
        ds_put_cstr(s, nxm_s);
        free(nxm_s);

        /* nx_match_to_string() doesn't print priority. */
        need_priority = true;
    } else {
        cls_rule_format(&fm.cr, s);

        /* cls_rule_format() does print priority. */
        need_priority = false;
    }

    if (ds_last(s) != ' ') {
        ds_put_char(s, ' ');
    }
    if (fm.cookie != htonll(0)) {
        ds_put_format(s, "cookie:0x%"PRIx64" ", ntohll(fm.cookie));
    }
    if (fm.idle_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, "idle:%"PRIu16" ", fm.idle_timeout);
    }
    if (fm.hard_timeout != OFP_FLOW_PERMANENT) {
        ds_put_format(s, "hard:%"PRIu16" ", fm.hard_timeout);
    }
    if (fm.cr.priority != OFP_DEFAULT_PRIORITY && need_priority) {
        ds_put_format(s, "pri:%"PRIu16" ", fm.cr.priority);
    }
    if (fm.buffer_id != UINT32_MAX) {
        ds_put_format(s, "buf:0x%"PRIx32" ", fm.buffer_id);
    }
    if (fm.flags != 0) {
        ds_put_format(s, "flags:0x%"PRIx16" ", fm.flags);
    }

    ofp_print_actions(s, fm.actions, fm.n_actions);
}

static void
ofp_print_duration(struct ds *string, unsigned int sec, unsigned int nsec)
{
    ds_put_format(string, "%u", sec);
    if (nsec > 0) {
        ds_put_format(string, ".%09u", nsec);
        while (string->string[string->length - 1] == '0') {
            string->length--;
        }
    }
    ds_put_char(string, 's');
}

static void
ofp_print_flow_removed(struct ds *string, const struct ofp_header *oh)
{
    struct ofputil_flow_removed fr;
    int error;

    error = ofputil_decode_flow_removed(&fr, oh);
    if (error) {
        ofp_print_error(string, error);
        return;
    }

    ds_put_char(string, ' ');
    cls_rule_format(&fr.rule, string);

    ds_put_cstr(string, " reason=");
    switch (fr.reason) {
    case OFPRR_IDLE_TIMEOUT:
        ds_put_cstr(string, "idle");
        break;
    case OFPRR_HARD_TIMEOUT:
        ds_put_cstr(string, "hard");
        break;
    case OFPRR_DELETE:
        ds_put_cstr(string, "delete");
        break;
    default:
        ds_put_format(string, "**%"PRIu8"**", fr.reason);
        break;
    }

    if (fr.cookie != htonll(0)) {
        ds_put_format(string, " cookie:0x%"PRIx64, ntohll(fr.cookie));
    }
    ds_put_cstr(string, " duration");
    ofp_print_duration(string, fr.duration_sec, fr.duration_nsec);
    ds_put_format(string, " idle%"PRIu16" pkts%"PRIu64" bytes%"PRIu64"\n",
         fr.idle_timeout, fr.packet_count, fr.byte_count);
}

static void
ofp_print_port_mod(struct ds *string, const struct ofp_port_mod *opm)
{
    ds_put_format(string, "port: %d: addr:"ETH_ADDR_FMT", config: %#x, mask:%#x\n",
            ntohs(opm->port_no), ETH_ADDR_ARGS(opm->hw_addr),
            ntohl(opm->config), ntohl(opm->mask));
    ds_put_format(string, "     advertise: ");
    if (opm->advertise) {
        ofp_print_port_features(string, ntohl(opm->advertise));
    } else {
        ds_put_format(string, "UNCHANGED\n");
    }
}

static void
ofp_print_error(struct ds *string, int error)
{
    if (string->length) {
        ds_put_char(string, ' ');
    }
    ds_put_cstr(string, "***decode error: ");
    ofputil_format_error(string, error);
    ds_put_cstr(string, "***\n");
}

static void
ofp_print_error_msg(struct ds *string, const struct ofp_error_msg *oem)
{
    size_t len = ntohs(oem->header.length);
    size_t payload_ofs, payload_len;
    const void *payload;
    int error;
    char *s;

    error = ofputil_decode_error_msg(&oem->header, &payload_ofs);
    if (!is_ofp_error(error)) {
        ofp_print_error(string, error);
        ds_put_hex_dump(string, oem->data, len - sizeof *oem, 0, true);
        return;
    }

    ds_put_char(string, ' ');
    ofputil_format_error(string, error);
    ds_put_char(string, '\n');

    payload = (const uint8_t *) oem + payload_ofs;
    payload_len = len - payload_ofs;
    switch (get_ofp_err_type(error)) {
    case OFPET_HELLO_FAILED:
        ds_put_printable(string, payload, payload_len);
        break;

    case OFPET_BAD_REQUEST:
        s = ofp_to_string(payload, payload_len, 1);
        ds_put_cstr(string, s);
        free(s);
        break;

    default:
        ds_put_hex_dump(string, payload, payload_len, 0, true);
        break;
    }
}

static void
ofp_print_port_status(struct ds *string, const struct ofp_port_status *ops)
{
    if (ops->reason == OFPPR_ADD) {
        ds_put_format(string, " ADD:");
    } else if (ops->reason == OFPPR_DELETE) {
        ds_put_format(string, " DEL:");
    } else if (ops->reason == OFPPR_MODIFY) {
        ds_put_format(string, " MOD:");
    }

    ofp_print_phy_port(string, &ops->desc);
}

static void
ofp_print_ofpst_desc_reply(struct ds *string, const struct ofp_desc_stats *ods)
{
    ds_put_char(string, '\n');
    ds_put_format(string, "Manufacturer: %.*s\n",
            (int) sizeof ods->mfr_desc, ods->mfr_desc);
    ds_put_format(string, "Hardware: %.*s\n",
            (int) sizeof ods->hw_desc, ods->hw_desc);
    ds_put_format(string, "Software: %.*s\n",
            (int) sizeof ods->sw_desc, ods->sw_desc);
    ds_put_format(string, "Serial Num: %.*s\n",
            (int) sizeof ods->serial_num, ods->serial_num);
    ds_put_format(string, "DP Description: %.*s\n",
            (int) sizeof ods->dp_desc, ods->dp_desc);
}

static void
ofp_print_flow_stats_request(struct ds *string,
                             const struct ofp_stats_msg *osm)
{
    struct flow_stats_request fsr;
    int error;

    error = ofputil_decode_flow_stats_request(&fsr, &osm->header);
    if (error) {
        ofp_print_error(string, error);
        return;
    }

    if (fsr.table_id != 0xff) {
        ds_put_format(string, " table=%"PRIu8, fsr.table_id);
    }

    if (fsr.out_port != OFPP_NONE) {
        ds_put_cstr(string, " out_port=");
        ofp_print_port_name(string, fsr.out_port);
    }

    /* A flow stats request doesn't include a priority, but cls_rule_format()
     * will print one unless it is OFP_DEFAULT_PRIORITY. */
    fsr.match.priority = OFP_DEFAULT_PRIORITY;

    ds_put_char(string, ' ');
    cls_rule_format(&fsr.match, string);
}

static void
ofp_print_flow_stats_reply(struct ds *string, const struct ofp_header *oh)
{
    struct ofpbuf b;

    ofpbuf_use_const(&b, oh, ntohs(oh->length));
    for (;;) {
        struct ofputil_flow_stats fs;
        int retval;

        retval = ofputil_decode_flow_stats_reply(&fs, &b);
        if (retval) {
            if (retval != EOF) {
                ds_put_cstr(string, " ***parse error***");
            }
            break;
        }

        ds_put_char(string, '\n');

        ds_put_format(string, " cookie=0x%"PRIx64", duration=",
                      ntohll(fs.cookie));
        ofp_print_duration(string, fs.duration_sec, fs.duration_nsec);
        ds_put_format(string, ", table=%"PRIu8", ", fs.table_id);
        ds_put_format(string, "n_packets=%"PRIu64", ", fs.packet_count);
        ds_put_format(string, "n_bytes=%"PRIu64", ", fs.byte_count);
        if (fs.idle_timeout != OFP_FLOW_PERMANENT) {
            ds_put_format(string, "idle_timeout=%"PRIu16",", fs.idle_timeout);
        }
        if (fs.hard_timeout != OFP_FLOW_PERMANENT) {
            ds_put_format(string, "hard_timeout=%"PRIu16",", fs.hard_timeout);
        }

        cls_rule_format(&fs.rule, string);
        ds_put_char(string, ' ');
        ofp_print_actions(string, fs.actions, fs.n_actions);
     }
}

static void
ofp_print_ofpst_aggregate_reply(struct ds *string,
                                const struct ofp_aggregate_stats_reply *asr)
{
    ds_put_format(string, " packet_count=%"PRIu64,
                  ntohll(get_32aligned_be64(&asr->packet_count)));
    ds_put_format(string, " byte_count=%"PRIu64,
                  ntohll(get_32aligned_be64(&asr->byte_count)));
    ds_put_format(string, " flow_count=%"PRIu32, ntohl(asr->flow_count));
}

static void
ofp_print_nxst_aggregate_reply(struct ds *string,
                               const struct nx_aggregate_stats_reply *nasr)
{
    ds_put_format(string, " packet_count=%"PRIu64, ntohll(nasr->packet_count));
    ds_put_format(string, " byte_count=%"PRIu64, ntohll(nasr->byte_count));
    ds_put_format(string, " flow_count=%"PRIu32, ntohl(nasr->flow_count));
}

static void print_port_stat(struct ds *string, const char *leader,
                            const ovs_32aligned_be64 *statp, int more)
{
    uint64_t stat = ntohll(get_32aligned_be64(statp));

    ds_put_cstr(string, leader);
    if (stat != UINT64_MAX) {
        ds_put_format(string, "%"PRIu64, stat);
    } else {
        ds_put_char(string, '?');
    }
    if (more) {
        ds_put_cstr(string, ", ");
    } else {
        ds_put_cstr(string, "\n");
    }
}

static void
ofp_print_ofpst_port_request(struct ds *string,
                             const struct ofp_port_stats_request *psr)
{
    ds_put_format(string, " port_no=%"PRIu16, ntohs(psr->port_no));
}

static void
ofp_print_ofpst_port_reply(struct ds *string, const struct ofp_header *oh,
                           int verbosity)
{
    const struct ofp_port_stats *ps = ofputil_stats_body(oh);
    size_t n = ofputil_stats_body_len(oh) / sizeof *ps;
    ds_put_format(string, " %zu ports\n", n);
    if (verbosity < 1) {
        return;
    }

    for (; n--; ps++) {
        ds_put_format(string, "  port %2"PRIu16": ", ntohs(ps->port_no));

        ds_put_cstr(string, "rx ");
        print_port_stat(string, "pkts=", &ps->rx_packets, 1);
        print_port_stat(string, "bytes=", &ps->rx_bytes, 1);
        print_port_stat(string, "drop=", &ps->rx_dropped, 1);
        print_port_stat(string, "errs=", &ps->rx_errors, 1);
        print_port_stat(string, "frame=", &ps->rx_frame_err, 1);
        print_port_stat(string, "over=", &ps->rx_over_err, 1);
        print_port_stat(string, "crc=", &ps->rx_crc_err, 0);

        ds_put_cstr(string, "           tx ");
        print_port_stat(string, "pkts=", &ps->tx_packets, 1);
        print_port_stat(string, "bytes=", &ps->tx_bytes, 1);
        print_port_stat(string, "drop=", &ps->tx_dropped, 1);
        print_port_stat(string, "errs=", &ps->tx_errors, 1);
        print_port_stat(string, "coll=", &ps->collisions, 0);
    }
}

static void
ofp_print_ofpst_table_reply(struct ds *string, const struct ofp_header *oh,
                            int verbosity)
{
    const struct ofp_table_stats *ts = ofputil_stats_body(oh);
    size_t n = ofputil_stats_body_len(oh) / sizeof *ts;
    ds_put_format(string, " %zu tables\n", n);
    if (verbosity < 1) {
        return;
    }

    for (; n--; ts++) {
        char name[OFP_MAX_TABLE_NAME_LEN + 1];
        ovs_strlcpy(name, ts->name, sizeof name);

        ds_put_format(string, "  %d: %-8s: ", ts->table_id, name);
        ds_put_format(string, "wild=0x%05"PRIx32", ", ntohl(ts->wildcards));
        ds_put_format(string, "max=%6"PRIu32", ", ntohl(ts->max_entries));
        ds_put_format(string, "active=%"PRIu32"\n", ntohl(ts->active_count));
        ds_put_cstr(string, "               ");
        ds_put_format(string, "lookup=%"PRIu64", ",
                      ntohll(get_32aligned_be64(&ts->lookup_count)));
        ds_put_format(string, "matched=%"PRIu64"\n",
                      ntohll(get_32aligned_be64(&ts->matched_count)));
     }
}

static void
ofp_print_queue_name(struct ds *string, uint32_t queue_id)
{
    if (queue_id == OFPQ_ALL) {
        ds_put_cstr(string, "ALL");
    } else {
        ds_put_format(string, "%"PRIu32, queue_id);
    }
}

static void
ofp_print_ofpst_queue_request(struct ds *string,
                              const struct ofp_queue_stats_request *qsr)
{
    ds_put_cstr(string, "port=");
    ofp_print_port_name(string, ntohs(qsr->port_no));

    ds_put_cstr(string, " queue=");
    ofp_print_queue_name(string, ntohl(qsr->queue_id));
}

static void
ofp_print_ofpst_queue_reply(struct ds *string, const struct ofp_header *oh,
                            int verbosity)
{
    const struct ofp_queue_stats *qs = ofputil_stats_body(oh);
    size_t n = ofputil_stats_body_len(oh) / sizeof *qs;
    ds_put_format(string, " %zu queues\n", n);
    if (verbosity < 1) {
        return;
    }

    for (; n--; qs++) {
        ds_put_cstr(string, "  port ");
        ofp_print_port_name(string, ntohs(qs->port_no));
        ds_put_cstr(string, " queue ");
        ofp_print_queue_name(string, ntohl(qs->queue_id));
        ds_put_cstr(string, ": ");

        print_port_stat(string, "bytes=", &qs->tx_bytes, 1);
        print_port_stat(string, "pkts=", &qs->tx_packets, 1);
        print_port_stat(string, "errors=", &qs->tx_errors, 0);
    }
}

static void
ofp_print_stats_request(struct ds *string, const struct ofp_header *oh)
{
    const struct ofp_stats_msg *srq = (const struct ofp_stats_msg *) oh;

    if (srq->flags) {
        ds_put_format(string, " ***unknown flags 0x%04"PRIx16"***",
                      ntohs(srq->flags));
    }
}

static void
ofp_print_stats_reply(struct ds *string, const struct ofp_header *oh)
{
    const struct ofp_stats_msg *srp = (const struct ofp_stats_msg *) oh;

    if (srp->flags) {
        uint16_t flags = ntohs(srp->flags);

        ds_put_cstr(string, " flags=");
        if (flags & OFPSF_REPLY_MORE) {
            ds_put_cstr(string, "[more]");
            flags &= ~OFPSF_REPLY_MORE;
        }
        if (flags) {
            ds_put_format(string, "[***unknown flags 0x%04"PRIx16"***]",
                          flags);
        }
    }
}

static void
ofp_print_echo(struct ds *string, const struct ofp_header *oh, int verbosity)
{
    size_t len = ntohs(oh->length);

    ds_put_format(string, " %zu bytes of payload\n", len - sizeof *oh);
    if (verbosity > 1) {
        ds_put_hex_dump(string, oh + 1, len - sizeof *oh, 0, true);
    }
}

static void
ofp_print_nxt_role_message(struct ds *string,
                           const struct nx_role_request *nrr)
{
    unsigned int role = ntohl(nrr->role);

    ds_put_cstr(string, " role=");
    if (role == NX_ROLE_OTHER) {
        ds_put_cstr(string, "other");
    } else if (role == NX_ROLE_MASTER) {
        ds_put_cstr(string, "master");
    } else if (role == NX_ROLE_SLAVE) {
        ds_put_cstr(string, "slave");
    } else {
        ds_put_format(string, "%u", role);
    }
}

static void
ofp_print_nxt_flow_mod_table_id(struct ds *string,
                                const struct nxt_flow_mod_table_id *nfmti)
{
    ds_put_format(string, " %s", nfmti->set ? "enable" : "disable");
}

static void
ofp_print_nxt_set_flow_format(struct ds *string,
                              const struct nxt_set_flow_format *nsff)
{
    uint32_t format = ntohl(nsff->format);

    ds_put_cstr(string, " format=");
    if (ofputil_flow_format_is_valid(format)) {
        ds_put_cstr(string, ofputil_flow_format_to_string(format));
    } else {
        ds_put_format(string, "%"PRIu32, format);
    }
}

static void
ofp_to_string__(const struct ofp_header *oh,
                const struct ofputil_msg_type *type, struct ds *string,
                int verbosity)
{
    enum ofputil_msg_code code;
    const void *msg = oh;

    ds_put_format(string, "%s (xid=0x%"PRIx32"):",
                  ofputil_msg_type_name(type), ntohl(oh->xid));

    code = ofputil_msg_type_code(type);
    switch (code) {
    case OFPUTIL_MSG_INVALID:
        break;

    case OFPUTIL_OFPT_HELLO:
        ds_put_char(string, '\n');
        ds_put_hex_dump(string, oh + 1, ntohs(oh->length) - sizeof *oh,
                        0, true);
        break;

    case OFPUTIL_OFPT_ERROR:
        ofp_print_error_msg(string, msg);
        break;

    case OFPUTIL_OFPT_ECHO_REQUEST:
    case OFPUTIL_OFPT_ECHO_REPLY:
        ofp_print_echo(string, oh, verbosity);
        break;

    case OFPUTIL_OFPT_FEATURES_REQUEST:
        break;

    case OFPUTIL_OFPT_FEATURES_REPLY:
        ofp_print_switch_features(string, msg);
        break;

    case OFPUTIL_OFPT_GET_CONFIG_REQUEST:
        break;

    case OFPUTIL_OFPT_GET_CONFIG_REPLY:
    case OFPUTIL_OFPT_SET_CONFIG:
        ofp_print_switch_config(string, msg);
        break;

    case OFPUTIL_OFPT_PACKET_IN:
        ofp_print_packet_in(string, msg, verbosity);
        break;

    case OFPUTIL_OFPT_FLOW_REMOVED:
    case OFPUTIL_NXT_FLOW_REMOVED:
        ofp_print_flow_removed(string, msg);
        break;

    case OFPUTIL_OFPT_PORT_STATUS:
        ofp_print_port_status(string, msg);
        break;

    case OFPUTIL_OFPT_PACKET_OUT:
        ofp_print_packet_out(string, msg, verbosity);
        break;

    case OFPUTIL_OFPT_FLOW_MOD:
        ofp_print_flow_mod(string, msg, code, verbosity);
        break;

    case OFPUTIL_OFPT_PORT_MOD:
        ofp_print_port_mod(string, msg);
        break;

    case OFPUTIL_OFPT_BARRIER_REQUEST:
    case OFPUTIL_OFPT_BARRIER_REPLY:
        break;

    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REQUEST:
    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REPLY:
        /* XXX */
        break;

    case OFPUTIL_OFPST_DESC_REQUEST:
        ofp_print_stats_request(string, oh);
        break;

    case OFPUTIL_OFPST_FLOW_REQUEST:
    case OFPUTIL_NXST_FLOW_REQUEST:
    case OFPUTIL_OFPST_AGGREGATE_REQUEST:
    case OFPUTIL_NXST_AGGREGATE_REQUEST:
        ofp_print_stats_request(string, oh);
        ofp_print_flow_stats_request(string, msg);
        break;

    case OFPUTIL_OFPST_TABLE_REQUEST:
        ofp_print_stats_request(string, oh);
        break;

    case OFPUTIL_OFPST_PORT_REQUEST:
        ofp_print_stats_request(string, oh);
        ofp_print_ofpst_port_request(string, msg);
        break;

    case OFPUTIL_OFPST_QUEUE_REQUEST:
        ofp_print_stats_request(string, oh);
        ofp_print_ofpst_queue_request(string, msg);
        break;

    case OFPUTIL_OFPST_DESC_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_desc_reply(string, msg);
        break;

    case OFPUTIL_OFPST_FLOW_REPLY:
    case OFPUTIL_NXST_FLOW_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_flow_stats_reply(string, oh);
        break;

    case OFPUTIL_OFPST_QUEUE_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_queue_reply(string, oh, verbosity);
        break;

    case OFPUTIL_OFPST_PORT_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_port_reply(string, oh, verbosity);
        break;

    case OFPUTIL_OFPST_TABLE_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_table_reply(string, oh, verbosity);
        break;

    case OFPUTIL_OFPST_AGGREGATE_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_ofpst_aggregate_reply(string, msg);
        break;

    case OFPUTIL_NXT_ROLE_REQUEST:
    case OFPUTIL_NXT_ROLE_REPLY:
        ofp_print_nxt_role_message(string, msg);
        break;

    case OFPUTIL_NXT_FLOW_MOD_TABLE_ID:
        ofp_print_nxt_flow_mod_table_id(string, msg);
        break;

    case OFPUTIL_NXT_SET_FLOW_FORMAT:
        ofp_print_nxt_set_flow_format(string, msg);
        break;

    case OFPUTIL_NXT_FLOW_MOD:
        ofp_print_flow_mod(string, msg, code, verbosity);
        break;

    case OFPUTIL_NXST_AGGREGATE_REPLY:
        ofp_print_stats_reply(string, oh);
        ofp_print_nxst_aggregate_reply(string, msg);
        break;
    }
}

/* Composes and returns a string representing the OpenFlow packet of 'len'
 * bytes at 'oh' at the given 'verbosity' level.  0 is a minimal amount of
 * verbosity and higher numbers increase verbosity.  The caller is responsible
 * for freeing the string. */
char *
ofp_to_string(const void *oh_, size_t len, int verbosity)
{
    struct ds string = DS_EMPTY_INITIALIZER;
    const struct ofp_header *oh = oh_;

    if (!len) {
        ds_put_cstr(&string, "OpenFlow message is empty\n");
    } else if (len < sizeof(struct ofp_header)) {
        ds_put_format(&string, "OpenFlow packet too short (only %zu bytes):\n",
                      len);
    } else if (oh->version != OFP_VERSION) {
        ds_put_format(&string, "Bad OpenFlow version %"PRIu8":\n",
                      oh->version);
    } else if (ntohs(oh->length) > len) {
        ds_put_format(&string,
                      "(***truncated to %zu bytes from %"PRIu16"***)\n",
                      len, ntohs(oh->length));
    } else if (ntohs(oh->length) < len) {
        ds_put_format(&string,
                      "(***only uses %"PRIu16" bytes out of %zu***)\n",
                      ntohs(oh->length), len);
    } else {
        const struct ofputil_msg_type *type;
        int error;

        error = ofputil_decode_msg_type(oh, &type);
        if (!error) {
            ofp_to_string__(oh, type, &string, verbosity);
            if (verbosity >= 5) {
                if (ds_last(&string) != '\n') {
                    ds_put_char(&string, '\n');
                }
                ds_put_hex_dump(&string, oh, len, 0, true);
            }
            if (ds_last(&string) != '\n') {
                ds_put_char(&string, '\n');
            }
            return ds_steal_cstr(&string);
        }

        ofp_print_error(&string, error);
    }
    ds_put_hex_dump(&string, oh, len, 0, true);
    return ds_steal_cstr(&string);
}

/* Returns the name for the specified OpenFlow message type as a string,
 * e.g. "OFPT_FEATURES_REPLY".  If no name is known, the string returned is a
 * hex number, e.g. "0x55".
 *
 * The caller must free the returned string when it is no longer needed. */
char *
ofp_message_type_to_string(uint8_t type)
{
    const char *name;

    switch (type) {
    case OFPT_HELLO:
        name = "HELLO";
        break;
    case OFPT_ERROR:
        name = "ERROR";
        break;
    case OFPT_ECHO_REQUEST:
        name = "ECHO_REQUEST";
        break;
    case OFPT_ECHO_REPLY:
        name = "ECHO_REPLY";
        break;
    case OFPT_VENDOR:
        name = "VENDOR";
        break;
    case OFPT_FEATURES_REQUEST:
        name = "FEATURES_REQUEST";
        break;
    case OFPT_FEATURES_REPLY:
        name = "FEATURES_REPLY";
        break;
    case OFPT_GET_CONFIG_REQUEST:
        name = "GET_CONFIG_REQUEST";
        break;
    case OFPT_GET_CONFIG_REPLY:
        name = "GET_CONFIG_REPLY";
        break;
    case OFPT_SET_CONFIG:
        name = "SET_CONFIG";
        break;
    case OFPT_PACKET_IN:
        name = "PACKET_IN";
        break;
    case OFPT_FLOW_REMOVED:
        name = "FLOW_REMOVED";
        break;
    case OFPT_PORT_STATUS:
        name = "PORT_STATUS";
        break;
    case OFPT_PACKET_OUT:
        name = "PACKET_OUT";
        break;
    case OFPT_FLOW_MOD:
        name = "FLOW_MOD";
        break;
    case OFPT_PORT_MOD:
        name = "PORT_MOD";
        break;
    case OFPT_STATS_REQUEST:
        name = "STATS_REQUEST";
        break;
    case OFPT_STATS_REPLY:
        name = "STATS_REPLY";
        break;
    case OFPT_BARRIER_REQUEST:
        name = "BARRIER_REQUEST";
        break;
    case OFPT_BARRIER_REPLY:
        name = "BARRIER_REPLY";
        break;
    case OFPT_QUEUE_GET_CONFIG_REQUEST:
        name = "QUEUE_GET_CONFIG_REQUEST";
        break;
    case OFPT_QUEUE_GET_CONFIG_REPLY:
        name = "QUEUE_GET_CONFIG_REPLY";
        break;
    default:
        name = NULL;
        break;
    }

    return name ? xasprintf("OFPT_%s", name) : xasprintf("0x%02"PRIx8, type);
}

static void
print_and_free(FILE *stream, char *string)
{
    fputs(string, stream);
    free(string);
}

/* Pretty-print the OpenFlow packet of 'len' bytes at 'oh' to 'stream' at the
 * given 'verbosity' level.  0 is a minimal amount of verbosity and higher
 * numbers increase verbosity. */
void
ofp_print(FILE *stream, const void *oh, size_t len, int verbosity)
{
    print_and_free(stream, ofp_to_string(oh, len, verbosity));
}

/* Dumps the contents of the Ethernet frame in the 'len' bytes starting at
 * 'data' to 'stream' using tcpdump.  'total_len' specifies the full length of
 * the Ethernet frame (of which 'len' bytes were captured).
 *
 * This starts and kills a tcpdump subprocess so it's quite expensive. */
void
ofp_print_packet(FILE *stream, const void *data, size_t len, size_t total_len)
{
    print_and_free(stream, ofp_packet_to_string(data, len, total_len));
}
