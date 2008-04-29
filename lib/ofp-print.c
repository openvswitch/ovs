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

#include "ofp-print.h"
#include "xtoxll.h"

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "compiler.h"
#include "dynamic-string.h"
#include "util.h"
#include "openflow.h"
#include "packets.h"

/* Returns a string that represents the contents of the Ethernet frame in the
 * 'len' bytes starting at 'data' to 'stream' as output by tcpdump.
 * 'total_len' specifies the full length of the Ethernet frame (of which 'len'
 * bytes were captured).
 *
 * The caller must free the returned string.
 *
 * This starts and kills a tcpdump subprocess so it's quite expensive. */
char *
ofp_packet_to_string(const void *data, size_t len, size_t total_len)
{
    struct pcap_hdr {
        uint32_t magic_number;   /* magic number */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t thiszone;        /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets */
        uint32_t network;        /* data link type */
    } PACKED;

    struct pcaprec_hdr {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
    } PACKED;

    struct pcap_hdr ph;
    struct pcaprec_hdr prh;

    struct ds ds = DS_EMPTY_INITIALIZER;

    char command[128];
    FILE *pcap;
    FILE *tcpdump;
    int status;
    int c;

    pcap = tmpfile();
    if (!pcap) {
        error(errno, "tmpfile");
        return xstrdup("<error>");
    }

    /* The pcap reader is responsible for figuring out endianness based on the
     * magic number, so the lack of htonX calls here is intentional. */
    ph.magic_number = 0xa1b2c3d4;
    ph.version_major = 2;
    ph.version_minor = 4;
    ph.thiszone = 0;
    ph.sigfigs = 0;
    ph.snaplen = 1518;
    ph.network = 1;             /* Ethernet */

    prh.ts_sec = 0;
    prh.ts_usec = 0;
    prh.incl_len = len;
    prh.orig_len = total_len;

    fwrite(&ph, 1, sizeof ph, pcap);
    fwrite(&prh, 1, sizeof prh, pcap);
    fwrite(data, 1, len, pcap);

    fflush(pcap);
    if (ferror(pcap)) {
        error(errno, "error writing temporary file");
    }
    rewind(pcap);

    snprintf(command, sizeof command, "tcpdump -n -r /dev/fd/%d 2>/dev/null",
             fileno(pcap));
    tcpdump = popen(command, "r");
    fclose(pcap);
    if (!tcpdump) {
        error(errno, "exec(\"%s\")", command);
        return xstrdup("<error>");
    }

    while ((c = getc(tcpdump)) != EOF) {
        ds_put_char(&ds, c);
    }

    status = pclose(tcpdump);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status))
            error(0, "tcpdump exited with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        error(0, "tcpdump exited with signal %d", WTERMSIG(status)); 
    }
    return ds_cstr(&ds);
}

/* Pretty-print the OFPT_PACKET_IN packet of 'len' bytes at 'oh' to 'stream'
 * at the given 'verbosity' level. */
static void
ofp_packet_in(struct ds *string, const void *oh, size_t len, int verbosity)
{
    const struct ofp_packet_in *op = oh;
    size_t data_len;

    ds_put_format(string, " total_len=%"PRIu16" in_port=%"PRIu8,
            ntohs(op->total_len), ntohs(op->in_port));

    if (op->reason == OFPR_ACTION)
        ds_put_cstr(string, " (via action)");
    else if (op->reason != OFPR_NO_MATCH)
        ds_put_format(string, " (***reason %"PRIu8"***)", op->reason);

    data_len = len - offsetof(struct ofp_packet_in, data);
    ds_put_format(string, " data_len=%zu", data_len);
    if (htonl(op->buffer_id) == UINT32_MAX) {
        ds_put_format(string, " (unbuffered)");
        if (ntohs(op->total_len) != data_len)
            ds_put_format(string, " (***total_len != data_len***)");
    } else {
        ds_put_format(string, " buffer=%08"PRIx32, ntohl(op->buffer_id));
        if (ntohs(op->total_len) < data_len)
            ds_put_format(string, " (***total_len < data_len***)");
    }
    ds_put_char(string, '\n');

    if (verbosity > 0) {
        char *packet = ofp_packet_to_string(op->data, data_len,
                                            ntohs(op->total_len)); 
        ds_put_cstr(string, packet);
        free(packet);
    }
}

static void ofp_print_port_name(struct ds *string, uint16_t port) 
{
    if (port == UINT16_MAX) {
        ds_put_cstr(string, "none");
    } else if (port == OFPP_FLOOD) {
        ds_put_cstr(string, "flood");
    } else if (port == OFPP_CONTROLLER) {
        ds_put_cstr(string, "controller");
    } else {
        ds_put_format(string, "%"PRIu16, port);
    }
}

static void
ofp_print_action(struct ds *string, const struct ofp_action *a) 
{
    switch (ntohs(a->type)) {
    case OFPAT_OUTPUT:
        ds_put_cstr(string, "output(");
        ofp_print_port_name(string, ntohs(a->arg.output.port));
        if (a->arg.output.port == htons(OFPP_CONTROLLER)) {
            ds_put_format(string, ", max %"PRIu16" bytes", ntohs(a->arg.output.max_len));
        }
        ds_put_cstr(string, ")");
        break;

    default:
        ds_put_format(string, "(decoder %"PRIu16" not implemented)", ntohs(a->type));
        break;
    }
}

static void ofp_print_actions(struct ds *string,
                              const struct ofp_action actions[],
                              size_t n_bytes) 
{
    size_t i;

    ds_put_cstr(string, " actions[");
    for (i = 0; i < n_bytes / sizeof *actions; i++) {
        if (i) {
            ds_put_cstr(string, "; ");
        }
        ofp_print_action(string, &actions[i]);
    }
    if (n_bytes % sizeof *actions) {
        if (i) {
            ds_put_cstr(string, "; ");
        }
        ds_put_cstr(string, "; ***trailing garbage***");
    }
    ds_put_cstr(string, "]");
}

/* Pretty-print the OFPT_PACKET_OUT packet of 'len' bytes at 'oh' to 'string'
 * at the given 'verbosity' level. */
static void ofp_packet_out(struct ds *string, const void *oh, size_t len,
                           int verbosity) 
{
    const struct ofp_packet_out *opo = oh;

    ds_put_cstr(string, " in_port=");
    ofp_print_port_name(string, ntohs(opo->in_port));

    if (ntohl(opo->buffer_id) == UINT32_MAX) {
        ds_put_cstr(string, " out_port=");
        ofp_print_port_name(string, ntohs(opo->out_port));
        if (verbosity > 0 && len > sizeof *opo) {
            char *packet = ofp_packet_to_string(opo->u.data, len - sizeof *opo,
                                                len - sizeof *opo);
            ds_put_cstr(string, packet);
            free(packet);
        }
    } else {
        ds_put_format(string, " buffer=%08"PRIx32, ntohl(opo->buffer_id));
        ofp_print_actions(string, opo->u.actions, len - sizeof *opo);
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

static void
ofp_print_phy_port(struct ds *string, const struct ofp_phy_port *port)
{
    uint8_t name[OFP_MAX_PORT_NAME_LEN];
    int j;

    memcpy(name, port->name, sizeof name);
    for (j = 0; j < sizeof name - 1; j++) {
        if (!isprint(name[j])) {
            break;
        }
    }
    name[j] = '\0';

    ds_put_format(string, " %2d(%s): addr:"ETH_ADDR_FMT", speed:%d, flags:%#x, "
            "feat:%#x\n", ntohs(port->port_no), name, 
            ETH_ADDR_ARGS(port->hw_addr), ntohl(port->speed),
            ntohl(port->flags), ntohl(port->features));
}

/* Pretty-print the struct ofp_switch_features of 'len' bytes at 'oh' to
 * 'string' at the given 'verbosity' level. */
static void
ofp_print_switch_features(struct ds *string, const void *oh, size_t len,
                          int verbosity)
{
    const struct ofp_switch_features *osf = oh;
    struct ofp_phy_port port_list[OFPP_MAX];
    int n_ports;
    int i;

    ds_put_format(string, "dp id:%"PRIx64"\n", ntohll(osf->datapath_id));
    ds_put_format(string, "tables: exact:%d, compressed:%d, general:%d\n",
           ntohl(osf->n_exact), 
           ntohl(osf->n_compression), ntohl(osf->n_general));
    ds_put_format(string, "buffers: size:%d, number:%d\n",
           ntohl(osf->buffer_mb), ntohl(osf->n_buffers));
    ds_put_format(string, "features: capabilities:%#x, actions:%#x\n",
           ntohl(osf->capabilities), ntohl(osf->actions));

    if (ntohs(osf->header.length) >= sizeof *osf) {
        len = MIN(len, ntohs(osf->header.length));
    }
    n_ports = (len - sizeof *osf) / sizeof *osf->ports;

    memcpy(port_list, osf->ports, (len - sizeof *osf));
    qsort(port_list, n_ports, sizeof port_list[0], compare_ports);
    for (i = 0; i < n_ports; i++) {
        ofp_print_phy_port(string, &port_list[i]);
    }
}

/* Pretty-print the struct ofp_switch_config of 'len' bytes at 'oh' to 'string'
 * at the given 'verbosity' level. */
static void
ofp_print_switch_config(struct ds *string, const void *oh, size_t len,
                        int verbosity)
{
    const struct ofp_switch_config *osc = oh;
    uint16_t flags;

    flags = ntohs(osc->flags);
    if (flags & OFPC_SEND_FLOW_EXP) {
        flags &= ~OFPC_SEND_FLOW_EXP;
        ds_put_format(string, " (sending flow expirations)");
    }
    if (flags) {
        ds_put_format(string, " ***unknown flags %04"PRIx16"***", flags);
    }

    ds_put_format(string, " miss_send_len=%"PRIu16"\n", ntohs(osc->miss_send_len));
}

static void print_wild(struct ds *string, const char *leader, int is_wild,
            const char *format, ...) __attribute__((format(printf, 4, 5)));

static void print_wild(struct ds *string, const char *leader, int is_wild,
                       const char *format, ...) 
{
    ds_put_cstr(string, leader);
    if (!is_wild) {
        va_list args;

        va_start(args, format);
        ds_put_format_valist(string, format, args);
        va_end(args);
    } else {
        ds_put_char(string, '?');
    }
}

/* Pretty-print the ofp_match structure */
static void ofp_print_match(struct ds *f, const struct ofp_match *om)
{
    uint16_t w = ntohs(om->wildcards);

    print_wild(f, "inport", w & OFPFW_IN_PORT, "%d", ntohs(om->in_port));
    print_wild(f, ":vlan", w & OFPFW_DL_VLAN, "%04x", ntohs(om->dl_vlan));
    print_wild(f, " mac[", w & OFPFW_DL_SRC,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_src));
    print_wild(f, "->", w & OFPFW_DL_DST,
               ETH_ADDR_FMT, ETH_ADDR_ARGS(om->dl_dst));
    print_wild(f, "] type", w & OFPFW_DL_TYPE, "%04x", ntohs(om->dl_type));
    print_wild(f, " ip[", w & OFPFW_NW_SRC, IP_FMT, IP_ARGS(&om->nw_src));
    print_wild(f, "->", w & OFPFW_NW_DST, IP_FMT, IP_ARGS(&om->nw_dst));
    print_wild(f, "] proto", w & OFPFW_NW_PROTO, "%u", om->nw_proto);
    print_wild(f, " tport[", w & OFPFW_TP_SRC, "%d", ntohs(om->tp_src));
    print_wild(f, "->", w & OFPFW_TP_DST, "%d", ntohs(om->tp_dst));
    ds_put_cstr(f, "]\n");
}

/* Pretty-print the OFPT_FLOW_MOD packet of 'len' bytes at 'oh' to 'string'
 * at the given 'verbosity' level. */
static void
ofp_print_flow_mod(struct ds *string, const void *oh, size_t len, 
                   int verbosity)
{
    const struct ofp_flow_mod *ofm = oh;

    ofp_print_match(string, &ofm->match);
    ds_put_format(string, " cmd:%d idle:%d pri:%d buf:%#x\n", 
            ntohs(ofm->command), ntohs(ofm->max_idle), 
            ofm->match.wildcards ? ntohs(ofm->priority) : (uint16_t)-1,
            ntohl(ofm->buffer_id));
}

/* Pretty-print the OFPT_FLOW_EXPIRED packet of 'len' bytes at 'oh' to 'string'
 * at the given 'verbosity' level. */
static void
ofp_print_flow_expired(struct ds *string, const void *oh, size_t len, 
                       int verbosity)
{
    const struct ofp_flow_expired *ofe = oh;

    ofp_print_match(string, &ofe->match);
    ds_put_format(string, 
         " secs%d pkts%lld bytes%lld\n", ntohl(ofe->duration),
         ntohll(ofe->packet_count), ntohll(ofe->byte_count));
}

/* Pretty-print the OFPT_PORT_STATUS packet of 'len' bytes at 'oh' to 'string'
 * at the given 'verbosity' level. */
static void
ofp_print_port_status(struct ds *string, const void *oh, size_t len, 
                      int verbosity)
{
    const struct ofp_port_status *ops = oh;

    if (ops->reason == OFPPR_ADD) {
        ds_put_format(string, "add:");
    } else if (ops->reason == OFPPR_DELETE) {
        ds_put_format(string, "del:");
    } else if (ops->reason == OFPPR_MOD) {
        ds_put_format(string, "mod:");
    } else {
        ds_put_format(string, "err:");
    }

    ofp_print_phy_port(string, &ops->desc);
}

static void
ofp_flow_stats_request(struct ds *string, const void *oh, size_t len,
                      int verbosity) 
{
    const struct ofp_flow_stats_request *fsr = oh;

    if (fsr->table_id == 0xff) {
        ds_put_format(string, " table_id=any, ");
    } else {
        ds_put_format(string, " table_id=%"PRIu8", ", fsr->table_id);
    }

    if (fsr->type == OFPFS_INDIV) {
        ds_put_cstr(string, " type=indiv, ");
    } else if (fsr->type == OFPFS_AGGREGATE) {
        ds_put_cstr(string, " type=aggregate, ");
    } else {
        ds_put_format(string, " ***type=%"PRIu8"***, ", fsr->type);
    }
    ofp_print_match(string, &fsr->match);
}

static void
ofp_flow_stats_reply(struct ds *string, const void *oh, size_t len,
                     int verbosity)
{
    const struct ofp_flow_stats_reply *fsr = oh;
    const struct ofp_flow_stats *fs;
    size_t n;

    n = (len - offsetof(struct ofp_flow_stats_reply, flows)) / sizeof *fs;
    ds_put_format(string, " %zu flows\n", n);
    if (verbosity < 1) {
        return;
    }

    for (fs = &fsr->flows[0]; fs < &fsr->flows[n]; fs++) {
        ds_put_format(string, "  duration=%"PRIu32" s, ", ntohs(fs->duration));
        ds_put_format(string, "table_id=%"PRIu8", ", fs->table_id);
        ds_put_format(string, "priority=%"PRIu16", ", fs->match.wildcards ? ntohs(fs->priority) : (uint16_t)-1);
        ds_put_format(string, "n_packets=%"PRIu64", ",
                      ntohll(fs->packet_count));
        ds_put_format(string, "n_bytes=%"PRIu64", ", ntohll(fs->byte_count));
        ofp_print_match(string, &fs->match);
     }
}

static void
ofp_port_stats_reply(struct ds *string, const void *oh, size_t len,
                    int verbosity)
{
    const struct ofp_port_stats_reply *psr = oh;
    const struct ofp_port_stats *ps;
    size_t n;

    n = (len - offsetof(struct ofp_port_stats_reply, ports)) / sizeof *ps;
    ds_put_format(string, " %zu ports\n", n);
    if (verbosity < 1) {
        return;
    }

    for (ps = &psr->ports[0]; ps < &psr->ports[n]; ps++) {
        ds_put_format(string, "  port %"PRIu16": ", ntohs(ps->port_no));
        ds_put_format(string, "rx %"PRIu64", ", ntohll(ps->rx_count));
        ds_put_format(string, "tx %"PRIu64", ", ntohll(ps->tx_count));
        ds_put_format(string, "dropped %"PRIu64"\n", ntohll(ps->drop_count));
    }
}

static void
ofp_table_stats_reply(struct ds *string, const void *oh, size_t len,
                     int verbosity)
{
    const struct ofp_table_stats_reply *tsr = oh;
    const struct ofp_table_stats *ts;
    size_t n;

    n = (len - offsetof(struct ofp_table_stats_reply, tables)) / sizeof *ts;
    ds_put_format(string, " %zu tables\n", n);
    if (verbosity < 1) {
        return;
    }

    for (ts = &tsr->tables[0]; ts < &tsr->tables[n]; ts++) {
        char name[OFP_MAX_TABLE_NAME_LEN + 1];
        strncpy(name, ts->name, sizeof name);
        name[OFP_MAX_TABLE_NAME_LEN] = '\0';

        ds_put_format(string, "  table %"PRIu8": ", ts->table_id);
        ds_put_format(string, "name %-8s, ", name);
        ds_put_format(string, "max %6"PRIu32", ", ntohl(ts->max_entries));
        ds_put_format(string, "active %6"PRIu32", ", ntohl(ts->active_count));
        ds_put_format(string, "matched %6"PRIu64"\n",
                      ntohll(ts->matched_count));
     }
}

struct openflow_packet {
    const char *name;
    size_t min_size;
    void (*printer)(struct ds *, const void *, size_t len, int verbosity);
};

static const struct openflow_packet packets[] = {
    [OFPT_FEATURES_REQUEST] = {
        "features_request",
        sizeof (struct ofp_header),
        NULL,
    },
    [OFPT_FEATURES_REPLY] = {
        "features_reply",
        sizeof (struct ofp_switch_features),
        ofp_print_switch_features,
    },
    [OFPT_GET_CONFIG_REQUEST] = {
        "get_config_request",
        sizeof (struct ofp_header),
        NULL,
    },
    [OFPT_GET_CONFIG_REPLY] = {
        "get_config_reply",
        sizeof (struct ofp_switch_config),
        ofp_print_switch_config,
    },
    [OFPT_SET_CONFIG] = {
        "set_config",
        sizeof (struct ofp_switch_config),
        ofp_print_switch_config,
    },
    [OFPT_PACKET_IN] = {
        "packet_in",
        offsetof(struct ofp_packet_in, data),
        ofp_packet_in,
    },
    [OFPT_PACKET_OUT] = {
        "packet_out",
        sizeof (struct ofp_packet_out),
        ofp_packet_out,
    },
    [OFPT_FLOW_MOD] = {
        "flow_mod",
        sizeof (struct ofp_flow_mod),
        ofp_print_flow_mod,
    },
    [OFPT_FLOW_EXPIRED] = {
        "flow_expired",
        sizeof (struct ofp_flow_expired),
        ofp_print_flow_expired,
    },
    [OFPT_PORT_MOD] = {
        "port_mod",
        sizeof (struct ofp_port_mod),
        NULL,
    },
    [OFPT_PORT_STATUS] = {
        "port_status",
        sizeof (struct ofp_port_status),
        ofp_print_port_status
    },
    [OFPT_FLOW_STATS_REQUEST] = {
        "flow_stats_request",
        sizeof (struct ofp_flow_stats_request),
        ofp_flow_stats_request,
    },
    [OFPT_FLOW_STATS_REPLY] = {
        "flow_stats_reply",
        sizeof (struct ofp_flow_stats_reply),
        ofp_flow_stats_reply,
    },
    [OFPT_PORT_STATS_REQUEST] = {
        "port_stats_request",
        sizeof (struct ofp_port_stats_request),
        NULL,
    },
    [OFPT_PORT_STATS_REPLY] = {
        "port_stats_reply",
        sizeof (struct ofp_port_stats_reply),
        ofp_port_stats_reply,
    },
    [OFPT_TABLE_STATS_REQUEST] = {
        "table_stats_request",
        sizeof (struct ofp_table_stats_request),
        NULL,
    },
    [OFPT_TABLE_STATS_REPLY] = {
        "table_stats_reply",
        sizeof (struct ofp_table_stats_reply),
        ofp_table_stats_reply,
    },
};

/* Composes and returns a string representing the OpenFlow packet of 'len'
 * bytes at 'oh' at the given 'verbosity' level.  0 is a minimal amount of
 * verbosity and higher numbers increase verbosity.  The caller is responsible
 * for freeing the string. */
char *
ofp_to_string(const void *oh_, size_t len, int verbosity)
{
    struct ds string = DS_EMPTY_INITIALIZER;
    const struct ofp_header *oh = oh_;
    const struct openflow_packet *pkt;

    if (len < sizeof(struct ofp_header)) {
        ds_put_cstr(&string, "OpenFlow packet too short:\n");
        ds_put_hex_dump(&string, oh, len, 0, true);
        return ds_cstr(&string);
    } else if (oh->version != OFP_VERSION) {
        ds_put_format(&string, "Bad OpenFlow version %"PRIu8":\n", oh->version);
        ds_put_hex_dump(&string, oh, len, 0, true);
        return ds_cstr(&string);
    } else if (oh->type >= ARRAY_SIZE(packets) || !packets[oh->type].name) {
        ds_put_format(&string, "Unknown OpenFlow packet type %"PRIu8":\n",
                oh->type);
        ds_put_hex_dump(&string, oh, len, 0, true);
        return ds_cstr(&string);
    }

    pkt = &packets[oh->type];
    ds_put_format(&string, "%s (xid=%"PRIx32"):", pkt->name, oh->xid);

    if (ntohs(oh->length) > len)
        ds_put_format(&string, " (***truncated to %zu bytes from %"PRIu16"***)",
                len, ntohs(oh->length));
    else if (ntohs(oh->length) < len) {
        ds_put_format(&string, " (***only uses %"PRIu16" bytes out of %zu***)\n",
                ntohs(oh->length), len);
        len = ntohs(oh->length);
    }

    if (len < pkt->min_size) {
        ds_put_format(&string, " (***length=%zu < min_size=%zu***)\n",
                len, pkt->min_size);
    } else if (!pkt->printer) {
        if (len > sizeof *oh) {
            ds_put_format(&string, " length=%zu (decoder not implemented)\n",
                          ntohs(oh->length)); 
        }
    } else {
        pkt->printer(&string, oh, len, verbosity);
    }
    if (verbosity >= 3) {
        ds_put_hex_dump(&string, oh, len, 0, true);
    }
    return ds_cstr(&string);
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
