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

#include <config.h>
#include "flow-end.h"
#include <errno.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "secchan.h"
#include "ofpbuf.h"
#include "vconn.h"
#include "rconn.h"
#include "socket-util.h"
#include "xtoxll.h"
#include "netflow.h"

#define THIS_MODULE VLM_flow_end
#include "vlog.h"

struct flow_end_data {
    struct rconn *remote_rconn;
    struct rconn *local_rconn;

    bool send_ofp_exp;         /* Send OpenFlow 'flow expired' messages? */

    int netflow_fd;            /* Socket for NetFlow collector. */
    uint32_t netflow_cnt;      /* Flow sequence number for NetFlow. */
};

static int
udp_open(char *dst)
{
    char *save_ptr;
    const char *host_name;
    const char *port_string;
    struct sockaddr_in sin;
    int retval;
    int fd;

    /* Glibc 2.7 has a bug in strtok_r when compiling with optimization that
     * can cause segfaults here:
     * http://sources.redhat.com/bugzilla/show_bug.cgi?id=5614.
     * Using "::" instead of the obvious ":" works around it. */
    host_name = strtok_r(dst, "::", &save_ptr);
    port_string = strtok_r(NULL, "::", &save_ptr);
    if (!host_name) {
        ofp_error(0, "%s: bad peer name format", dst);
        return -EAFNOSUPPORT;
    }
    if (!port_string) {
        ofp_error(0, "%s: bad port format", dst);
        return -EAFNOSUPPORT;
    }

    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    if (lookup_ip(host_name, &sin.sin_addr)) {
        return -ENOENT;
    }
    sin.sin_port = htons(atoi(port_string));

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        VLOG_ERR("%s: socket: %s", dst, strerror(errno));
        return -errno;
    }

    retval = set_nonblocking(fd);
    if (retval) {
        close(fd);
        return -retval;
    }

    retval = connect(fd, (struct sockaddr *) &sin, sizeof sin);
    if (retval < 0) {
        int error = errno;
        VLOG_ERR("%s: connect: %s", dst, strerror(error));
        close(fd);
        return -error;
    }

    return fd;
}

static void
send_netflow_msg(const struct nx_flow_end *nfe, struct flow_end_data *fe)
{
    struct netflow_v5_header *nf_hdr;
    struct netflow_v5_record *nf_rec;
    uint8_t buf[sizeof(*nf_hdr) + sizeof(*nf_rec)];
    uint8_t *p = buf;
    struct timeval now;

    /* We only send NetFlow messages for fully specified IP flows; any 
     * entry with a wildcard is ignored. */
    if ((nfe->match.wildcards != 0) 
            || (nfe->match.dl_type != htons(ETH_TYPE_IP))) {
        return;
    }

    memset(&buf, 0, sizeof(buf));
    gettimeofday(&now, NULL);

    nf_hdr = (struct netflow_v5_header *)p;
    p += sizeof(*nf_hdr);
    nf_rec = (struct netflow_v5_record *)p;

    nf_hdr->version = htons(NETFLOW_V5_VERSION);
    nf_hdr->count = htons(1);
    nf_hdr->sysuptime = htonl((uint32_t)ntohll(nfe->end_time));
    nf_hdr->unix_secs = htonl(now.tv_sec);
    nf_hdr->unix_nsecs = htonl(now.tv_usec * 1000);
    nf_hdr->flow_seq = htonl(fe->netflow_cnt);
    nf_hdr->engine_type = 0;
    nf_hdr->engine_id = 0;
    nf_hdr->sampling_interval = htons(0);

    nf_rec->src_addr = nfe->match.nw_src;
    nf_rec->dst_addr = nfe->match.nw_dst;
    nf_rec->nexthop = htons(0);
    nf_rec->input = nfe->match.in_port;
    nf_rec->output = htons(0);
    nf_rec->packet_count = htonl((uint32_t)ntohll(nfe->packet_count));
    nf_rec->byte_count = htonl((uint32_t)ntohll(nfe->byte_count));
    nf_rec->init_time = htonl((uint32_t)ntohll(nfe->init_time));
    nf_rec->used_time = htonl((uint32_t)ntohll(nfe->used_time));

    if (nfe->match.nw_proto == IP_TYPE_ICMP) {
        /* In NetFlow, the ICMP type and code are concatenated and
         * placed in the 'dst_port' field. */
        uint8_t type = (uint8_t)ntohs(nfe->match.tp_src);
        uint8_t code = (uint8_t)ntohs(nfe->match.tp_dst);
        nf_rec->src_port = htons(0);
        nf_rec->dst_port = htons((type << 8) | code);
    } else {
        nf_rec->src_port = nfe->match.tp_src;
        nf_rec->dst_port = nfe->match.tp_dst;
    }

    nf_rec->tcp_flags = nfe->tcp_flags;
    nf_rec->ip_proto = nfe->match.nw_proto;
    nf_rec->ip_tos = nfe->ip_tos;

    nf_rec->src_as = htons(0);
    nf_rec->dst_as = htons(0);
    nf_rec->src_mask = 0;
    nf_rec->dst_mask = 0;

    send(fe->netflow_fd, buf, sizeof(buf), 0);
    fe->netflow_cnt++;
}

static void 
send_ofp_expired(const struct nx_flow_end *nfe, const struct flow_end_data *fe)
{
    struct ofp_flow_expired *ofe;
    struct ofpbuf *b;

    if ((nfe->reason != NXFER_IDLE_TIMEOUT) 
            && (nfe->reason != NXFER_HARD_TIMEOUT)) {
        return;
    }

    ofe = make_openflow(sizeof(*ofe), OFPT_FLOW_EXPIRED, &b);
    ofe->match = nfe->match;
    ofe->priority = nfe->priority;
    if (nfe->reason == NXFER_IDLE_TIMEOUT) {
        ofe->reason = OFPER_IDLE_TIMEOUT;
    } else {
        ofe->reason = OFPER_HARD_TIMEOUT;
    }
    /* 'duration' is in seconds, but we keeping track of milliseconds. */
    ofe->duration = htonl((ntohll(nfe->end_time)-ntohll(nfe->init_time))/1000);
    ofe->packet_count = nfe->packet_count;
    ofe->byte_count = nfe->byte_count;

    rconn_send(fe->remote_rconn, b, NULL);
}

static void 
send_nx_flow_end_config(const struct flow_end_data *fe)
{
    struct nx_flow_end_config *nfec;
    struct ofpbuf *b;

    nfec = make_openflow(sizeof(*nfec), OFPT_VENDOR, &b);
    nfec->header.vendor  = htonl(NX_VENDOR_ID);
    nfec->header.subtype = htonl(NXT_FLOW_END_CONFIG);
    if ((fe->send_ofp_exp == false) && (fe->netflow_fd < 0)) {
        nfec->enable = 0;
    } else {
        nfec->enable = 1;
    }

    rconn_send(fe->local_rconn, b, NULL);
}

static bool
flow_end_local_packet_cb(struct relay *r, void *flow_end_)
{
    struct flow_end_data *fe = flow_end_;
    struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
    struct nicira_header *request = msg->data;
    struct nx_flow_end *nfe = msg->data;


    if (msg->size < sizeof(*nfe)) {
        return false;
    }
    request = msg->data;
    if (request->header.type != OFPT_VENDOR
        || request->vendor != htonl(NX_VENDOR_ID)
        || request->subtype != htonl(NXT_FLOW_END)) {
        return false;
    }

    if (fe->netflow_fd >= 0) {
        send_netflow_msg(nfe, fe);
    }

    if (fe->send_ofp_exp) {
        send_ofp_expired(nfe, fe);
    }

    /* We always consume these Flow End messages. */
    return true;
}

static bool
flow_end_remote_packet_cb(struct relay *r, void *flow_end_)
{
    struct flow_end_data *fe = flow_end_;
    struct ofpbuf *msg = r->halves[HALF_REMOTE].rxbuf;
    struct ofp_switch_config *osc = msg->data;

    /* Check for OFPT_SET_CONFIG messages to see if the controller wants
     * to receive 'flow expired' messages.  If so, we need to intercept
     * the datapath's 'flow end' meta-messages and convert. */

    if ((msg->size < sizeof(*osc)) 
            || (osc->header.type != OFPT_SET_CONFIG)) {
        return false;
    }

    if (osc->flags & htons(OFPC_SEND_FLOW_EXP)) {
        fe->send_ofp_exp = true;
    } else {
        fe->send_ofp_exp = false;
    }

    send_nx_flow_end_config(fe);

    return false;
}

static struct hook_class flow_end_hook_class = {
    flow_end_local_packet_cb,   /* local_packet_cb */
    flow_end_remote_packet_cb,  /* remote_packet_cb */
    NULL,                       /* periodic_cb */
    NULL,                       /* wait_cb */
    NULL,                       /* closing_cb */
};

void
flow_end_start(struct secchan *secchan, char *netflow_dst,
               struct rconn *local, struct rconn *remote)
{
    struct flow_end_data *fe;

    fe = xcalloc(1, sizeof *fe);

    fe->remote_rconn = remote;
    fe->local_rconn = local;

    if (netflow_dst) {
        fe->netflow_fd = udp_open(netflow_dst);
        if (fe->netflow_fd < 0) {
            ofp_fatal(0, "NetFlow setup failed");
        }
        fe->send_ofp_exp = true;
    } else {
        fe->netflow_fd = -1;
        fe->send_ofp_exp = false;
    }

    add_hook(secchan, &flow_end_hook_class, fe);

    send_nx_flow_end_config(fe);
}
