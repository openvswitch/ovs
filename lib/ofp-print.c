/* Copyright (C) 2007 Board of Trustees, Leland Stanford Jr. University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
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

#include "ip.h"
#include "mac.h"
#include "compiler.h"
#include "util.h"
#include "openflow.h"

/* Dumps the contents of the Ethernet frame in the 'len' bytes starting at
 * 'data' to 'stream' using tcpdump.  'total_len' specifies the full length of
 * the Ethernet frame (of which 'len' bytes were captured).
 *
 * This starts and kills a tcpdump subprocess so it's quite expensive. */
void ofp_print_packet(FILE *stream, const void *data, size_t len,
                     size_t total_len)
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

    char command[128];
    FILE *tcpdump;
    int status;

    fflush(stream);
    snprintf(command, sizeof command, "tcpdump -n -r - %d>&1 2>/dev/null",
             fileno(stream));
    tcpdump = popen(command, "w");
    if (!tcpdump) {
        error(errno, "exec(\"%s\")", command);
        return;
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

    fwrite(&ph, 1, sizeof ph, tcpdump);
    fwrite(&prh, 1, sizeof prh, tcpdump);
    fwrite(data, 1, len, tcpdump);

    fflush(tcpdump);
    if (ferror(tcpdump))
        error(errno, "error writing \"%s\" subprocess", command);

    status = pclose(tcpdump);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status))
            error(0, "tcpdump exited with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        error(0, "tcpdump exited with signal %d", WTERMSIG(status)); 
    }
}

/* Pretty-print the OFPT_PACKET_IN packet of 'len' bytes at 'oh' to 'stream'
 * at the given 'verbosity' level. */
static void ofp_packet_in(FILE *stream, const void *oh, size_t len,
                            int verbosity)
{
    const struct ofp_packet_in *op = oh;
    size_t data_len;

    fprintf(stream, " total_len=%"PRIu16" in_port=%"PRIu8,
            ntohs(op->total_len), ntohs(op->in_port));

    if (op->reason == OFPR_ACTION)
        fputs(" (via action)", stream);
    else if (op->reason != OFPR_NO_MATCH)
        fprintf(stream, " (***reason %"PRIu8"***)", op->reason);

    data_len = len - offsetof(struct ofp_packet_in, data);
    fprintf(stream, " data_len=%zu", data_len);
    if (htonl(op->buffer_id) == UINT32_MAX) {
        fprintf(stream, " (unbuffered)");
        if (ntohs(op->total_len) != data_len)
            fprintf(stream, " (***total_len != data_len***)");
    } else {
        fprintf(stream, " buffer=%08"PRIx32, ntohl(op->buffer_id));
        if (ntohs(op->total_len) < data_len)
            fprintf(stream, " (***total_len < data_len***)");
    }
    putc('\n', stream);

    if (verbosity > 0)
        ofp_print_packet(stream, op->data, data_len, ntohs(op->total_len));
}

static void ofp_print_port_name(FILE *stream, uint16_t port) 
{
    if (port == UINT16_MAX) {
        fputs("none", stream);
    } else if (port == OFPP_FLOOD) {
        fputs("flood", stream);
    } else if (port == OFPP_CONTROLLER) {
        fputs("controller", stream);
    } else {
        fprintf(stream, "%"PRIu16, port);
    }
}

static void ofp_print_action(FILE *stream, const struct ofp_action *a) 
{
    switch (ntohs(a->type)) {
    case OFPAT_OUTPUT:
        fputs("output(", stream);
        ofp_print_port_name(stream, ntohs(a->arg.output.port));
        if (a->arg.output.port == htons(OFPP_CONTROLLER)) {
            fprintf(stream, ", max %"PRIu16" bytes", ntohs(a->arg.output.max_len));
        }
        fputs(")", stream);
        break;

    default:
        fprintf(stream, "(decoder %"PRIu16" not implemented)", ntohs(a->type));
        break;
    }
}

static void ofp_print_actions(FILE *stream,
                                const struct ofp_action actions[],
                                size_t n_bytes) 
{
    size_t i;

    fputs(" actions[", stream);
    for (i = 0; i < n_bytes / sizeof *actions; i++) {
        if (i) {
            fputs("; ", stream);
        }
        ofp_print_action(stream, &actions[i]);
    }
    if (n_bytes % sizeof *actions) {
        if (i) {
            fputs("; ", stream);
        }
        fputs("; ***trailing garbage***", stream);
    }
    fputs("]", stream);
}

/* Pretty-print the OFPT_PACKET_OUT packet of 'len' bytes at 'oh' to 'stream'
 * at the given 'verbosity' level. */
static void ofp_packet_out(FILE *stream, const void *oh, size_t len,
                            int verbosity) 
{
    const struct ofp_packet_out *opo = oh;

    fputs(" in_port=", stream);
    ofp_print_port_name(stream, ntohs(opo->in_port));

    if (ntohl(opo->buffer_id) == UINT32_MAX) {
        fputs(" out_port=", stream);
        ofp_print_port_name(stream, ntohs(opo->out_port));
        if (verbosity > 0 && len > sizeof *opo) {
            ofp_print_packet(stream, opo->u.data, len - sizeof *opo,
                               len - sizeof *opo);
        }
    } else {
        fprintf(stream, " buffer=%08"PRIx32, ntohl(opo->buffer_id));
        ofp_print_actions(stream, opo->u.actions, len - sizeof *opo);
    }
    putc('\n', stream);
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

static
void ofp_print_phy_port(FILE *stream, const struct ofp_phy_port *port)
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

    fprintf(stream, " %2d(%s): addr:"MAC_FMT", speed:%d, flags:%#x, "
            "feat:%#x\n", ntohs(port->port_no), name, 
            MAC_ARGS(port->hw_addr), ntohl(port->speed), ntohl(port->flags), 
            ntohl(port->features));
}

/* Pretty-print the OFPT_DATA_HELLO packet of 'len' bytes at 'oh' to 'stream'
 * at the given 'verbosity' level. */
void ofp_print_data_hello(FILE *stream, const void *oh, size_t len, 
        int verbosity)
{
    const struct ofp_data_hello *odh = oh;
    struct ofp_phy_port port_list[OFPP_MAX];
    int n_ports;
    int i;


    fprintf(stream, "dp id:%"PRIx64"\n", ntohll(odh->datapath_id));
    fprintf(stream, "tables: exact:%d, mac:%d, compressed:%d, general:%d\n",
           ntohl(odh->n_exact), ntohl(odh->n_mac_only),
           ntohl(odh->n_compression), ntohl(odh->n_general));
    fprintf(stream, "buffers: size:%d, number:%d, miss_len:%d\n",
           ntohl(odh->buffer_mb), ntohl(odh->n_buffers),
           ntohs(odh->miss_send_len));
    fprintf(stream, "features: capabilities:%#x, actions:%#x\n",
           ntohl(odh->capabilities), ntohl(odh->actions));

    if (ntohs(odh->header.length) >= sizeof *odh) {
        len = MIN(len, ntohs(odh->header.length));
    }
    n_ports = (len - sizeof *odh) / sizeof *odh->ports;

    memcpy(port_list, odh->ports, (len - sizeof *odh));
    qsort(port_list, n_ports, sizeof port_list[0], compare_ports);
    for (i = 0; i < n_ports; i++) {
        ofp_print_phy_port(stream, &port_list[i]);
    }
}

static void print_wild(FILE *stream, const char *leader, int is_wild,
            const char *format, ...) __attribute__((format(printf, 4, 5)));

static void print_wild(FILE *stream, const char *leader, int is_wild,
                       const char *format, ...) 
{
    fputs(leader, stream);
    if (!is_wild) {
        va_list args;

        va_start(args, format);
        vfprintf(stream, format, args);
        va_end(args);
    } else {
        putc('?', stream);
    }
}

/* Pretty-print the ofp_match structure */
static void ofp_print_match(FILE *f, const struct ofp_match *om)
{
    uint16_t w = ntohs(om->wildcards);

    print_wild(f, "inport", w & OFPFW_IN_PORT, "%04x", ntohs(om->in_port));
    print_wild(f, ":vlan", w & OFPFW_DL_VLAN, "%04x", ntohs(om->dl_vlan));
    print_wild(f, " mac[", w & OFPFW_DL_SRC, MAC_FMT, MAC_ARGS(om->dl_src));
    print_wild(f, "->", w & OFPFW_DL_DST, MAC_FMT, MAC_ARGS(om->dl_dst));
    print_wild(f, "] type", w & OFPFW_DL_TYPE, "%04x", ntohs(om->dl_type));
    print_wild(f, " ip[", w & OFPFW_NW_SRC, IP_FMT, IP_ARGS(&om->nw_src));
    print_wild(f, "->", w & OFPFW_NW_DST, IP_FMT, IP_ARGS(&om->nw_dst));
    print_wild(f, "] proto", w & OFPFW_NW_PROTO, "%u", om->nw_proto);
    print_wild(f, " tport[", w & OFPFW_TP_SRC, "%d", ntohs(om->tp_src));
    print_wild(f, "->", w & OFPFW_TP_DST, "%d", ntohs(om->tp_dst));
    fputs("]\n", f);
}

/* Pretty-print the OFPT_FLOW_MOD packet of 'len' bytes at 'oh' to 'stream'
 * at the given 'verbosity' level. */
void ofp_print_flow_mod(FILE *stream, const void *oh, size_t len, 
        int verbosity)
{
    const struct ofp_flow_mod *ofm = oh;

    ofp_print_match(stream, &ofm->match);
    fprintf(stream, " cmd:%d idle:%d buf:%#x grp:%d\n", ntohs(ofm->command),
         ntohs(ofm->max_idle), ntohl(ofm->buffer_id), ntohl(ofm->group_id));
}

/* Pretty-print the OFPT_FLOW_EXPIRED packet of 'len' bytes at 'oh' to 'stream'
 * at the given 'verbosity' level. */
void ofp_print_flow_expired(FILE *stream, const void *oh, size_t len, 
        int verbosity)
{
    const struct ofp_flow_expired *ofe = oh;

    ofp_print_match(stream, &ofe->match);
    fprintf(stream, 
         " secs%d pkts%lld bytes%lld\n", ntohl(ofe->duration),
         ntohll(ofe->packet_count), ntohll(ofe->byte_count));
}

/* Pretty-print the OFPT_PORT_STATUS packet of 'len' bytes at 'oh' to 'stream'
 * at the given 'verbosity' level. */
void ofp_print_port_status(FILE *stream, const void *oh, size_t len, 
        int verbosity)
{
    const struct ofp_port_status *ops = oh;

    if (ops->reason == OFPPR_ADD) {
        fprintf(stream, "add:");
    } else if (ops->reason == OFPPR_DELETE) {
        fprintf(stream, "del:");
    } else if (ops->reason == OFPPR_MOD) {
        fprintf(stream, "mod:");
    } else {
        fprintf(stream, "err:");
    }

    ofp_print_phy_port(stream, &ops->desc);
}

struct openflow_packet {
    const char *name;
    size_t min_size;
    void (*printer)(FILE *, const void *, size_t len, int verbosity);
};

static const struct openflow_packet packets[] = {
    [OFPT_CONTROL_HELLO] = {
        "ofp_control_hello",
        sizeof (struct ofp_control_hello),
        NULL,
    },
    [OFPT_DATA_HELLO] = {
        "ofp_data_hello",
        sizeof (struct ofp_data_hello),
        ofp_print_data_hello,
    },
    [OFPT_PACKET_IN] = {
        "ofp_packet_in",
        offsetof(struct ofp_packet_in, data),
        ofp_packet_in,
    },
    [OFPT_PACKET_OUT] = {
        "ofp_packet_out",
        sizeof (struct ofp_packet_out),
        ofp_packet_out,
    },
    [OFPT_FLOW_MOD] = {
        "ofp_flow_mod",
        sizeof (struct ofp_flow_mod),
        ofp_print_flow_mod,
    },
    [OFPT_FLOW_EXPIRED] = {
        "ofp_flow_expired",
        sizeof (struct ofp_flow_expired),
        ofp_print_flow_expired,
    },
    [OFPT_PORT_MOD] = {
        "ofp_port_mod",
        sizeof (struct ofp_port_mod),
        NULL,
    },
    [OFPT_PORT_STATUS] = {
        "ofp_port_status",
        sizeof (struct ofp_port_status),
        ofp_print_port_status
    },
};

/* Pretty-print the OpenFlow packet of 'len' bytes at 'oh' to 'stream' at the
 * given 'verbosity' level.  0 is a minimal amount of verbosity and higher
 * numbers increase verbosity. */
void ofp_print(FILE *stream, const void *oh_, size_t len, int verbosity)
{
    const struct ofp_header *oh = oh_;
    const struct openflow_packet *pkt;

    if (len < sizeof(struct ofp_header)) {
        fprintf(stream, "OpenFlow packet too short:\n");
        hex_dump(stream, oh, len, 0, true);
        return;
    } else if (oh->version != 1) {
        fprintf(stream, "Bad OpenFlow version %"PRIu8":\n", oh->version);
        hex_dump(stream, oh, len, 0, true);
        return;
    } else if (oh->type >= ARRAY_SIZE(packets) || !packets[oh->type].name) {
        fprintf(stream, "Unknown OpenFlow packet type %"PRIu8":\n",
                oh->type);
        hex_dump(stream, oh, len, 0, true);
        return;
    }

    pkt = &packets[oh->type];
    fprintf(stream, "%s (xid=%"PRIx32"):", pkt->name, oh->xid);

    if (ntohs(oh->length) > len)
        fprintf(stream, " (***truncated to %zu bytes from %"PRIu16"***)",
                len, ntohs(oh->length));
    else if (ntohs(oh->length) < len) {
        fprintf(stream, " (***only uses %"PRIu16" bytes out of %zu***)\n",
                ntohs(oh->length), len);
        len = ntohs(oh->length);
    }

    if (len < pkt->min_size) {
        fprintf(stream, " (***length=%zu < min_size=%zu***)\n",
                len, pkt->min_size);
    } else if (!pkt->printer) {
        fprintf(stream, " length=%zu (decoder not implemented)\n",
                ntohs(oh->length));
    } else {
        pkt->printer(stream, oh, len, verbosity);
    }
    if (verbosity >= 3)
        hex_dump(stream, oh, len, 0, true);
}

/* Pretty print a openflow table */
void ofp_print_table(FILE *stream, const struct ofp_table* ot)
{
    fprintf(stream, "id: %d name: %-8s n_flows: %6d max_flows: %6d",
            ntohs(ot->table_id), ot->name, ntohl(ot->n_flows),
            ntohl(ot->max_flows));
}
