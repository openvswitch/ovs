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
#include "learning-switch.h"

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

#include "flow.h"
#include "mac-learning.h"
#include "ofpbuf.h"
#include "ofp-print.h"
#include "openflow.h"
#include "queue.h"
#include "rconn.h"
#include "timeval.h"
#include "vconn.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_learning_switch
#include "vlog.h"

struct lswitch {
    /* If nonnegative, the switch sets up flows that expire after the given
     * number of seconds (or never expire, if the value is OFP_FLOW_PERMANENT).
     * Otherwise, the switch processes every packet. */
    int max_idle;

    uint64_t datapath_id;
    uint32_t capabilities;
    time_t last_features_request;
    struct mac_learning *ml;    /* NULL to act as hub instead of switch. */

    /* Number of outgoing queued packets on the rconn. */
    int n_queued;
};

/* The log messages here could actually be useful in debugging, so keep the
 * rate limit relatively high. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

static void queue_tx(struct lswitch *, struct rconn *, struct ofpbuf *);
static void send_features_request(struct lswitch *, struct rconn *);
static void process_switch_features(struct lswitch *, struct rconn *,
                                    struct ofp_switch_features *);
static void process_packet_in(struct lswitch *, struct rconn *,
                              struct ofp_packet_in *);
static void process_echo_request(struct lswitch *, struct rconn *,
                                 struct ofp_header *);
static void process_port_status(struct lswitch *, struct rconn *,
                                struct ofp_port_status *);
static void process_phy_port(struct lswitch *, struct rconn *,
                             const struct ofp_phy_port *);

/* Creates and returns a new learning switch.
 *
 * If 'learn_macs' is true, the new switch will learn the ports on which MAC
 * addresses appear.  Otherwise, the new switch will flood all packets.
 *
 * If 'max_idle' is nonnegative, the new switch will set up flows that expire
 * after the given number of seconds (or never expire, if 'max_idle' is
 * OFP_FLOW_PERMANENT).  Otherwise, the new switch will process every packet.
 *
 * 'rconn' is used to send out an OpenFlow features request. */
struct lswitch *
lswitch_create(struct rconn *rconn, bool learn_macs, int max_idle)
{
    struct lswitch *sw = xcalloc(1, sizeof *sw);
    sw->max_idle = max_idle;
    sw->datapath_id = 0;
    sw->last_features_request = time_now() - 1;
    sw->ml = learn_macs ? mac_learning_create() : NULL;
    send_features_request(sw, rconn);
    return sw;
}

/* Destroys 'sw'. */
void
lswitch_destroy(struct lswitch *sw)
{
    if (sw) {
        mac_learning_destroy(sw->ml);
        free(sw);
    }
}

static size_t
min_size(uint8_t type)
{
    return (type == OFPT_FEATURES_REPLY ? sizeof(struct ofp_switch_features)
            : type == OFPT_PACKET_IN ? offsetof (struct ofp_packet_in, data)
            : type == OFPT_PORT_STATUS ? sizeof(struct ofp_port_status)
            : sizeof(struct ofp_header));
}

/* Processes 'msg', which should be an OpenFlow received on 'rconn', according
 * to the learning switch state in 'sw'.  The most likely result of processing
 * is that flow-setup and packet-out OpenFlow messages will be sent out on
 * 'rconn'.  */
void
lswitch_process_packet(struct lswitch *sw, struct rconn *rconn,
                       const struct ofpbuf *msg)
{
    struct ofp_header *oh;

    oh = msg->data;
    if (msg->size < min_size(oh->type)) {
        VLOG_WARN_RL(&rl,
                     "%s: too short (%zu bytes) for type %"PRIu8" (min %zu)",
                     rconn_get_name(rconn),
                     msg->size, oh->type, min_size(oh->type));
        return;
    }

    if (oh->type == OFPT_ECHO_REQUEST) {
        process_echo_request(sw, rconn, msg->data);
    } else if (oh->type == OFPT_FEATURES_REPLY) {
        process_switch_features(sw, rconn, msg->data);
    } else if (sw->datapath_id == 0) {
        send_features_request(sw, rconn);
    } else if (oh->type == OFPT_PACKET_IN) {
        process_packet_in(sw, rconn, msg->data);
    } else if (oh->type == OFPT_PORT_STATUS) {
        process_port_status(sw, rconn, msg->data);
    } else {
        if (VLOG_IS_DBG_ENABLED()) {
            char *p = ofp_to_string(msg->data, msg->size, 2);
            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", p);
            free(p);
        }
    }
}

static void
send_features_request(struct lswitch *sw, struct rconn *rconn)
{
    time_t now = time_now();
    if (now >= sw->last_features_request + 1) {
        struct ofpbuf *b;
        struct ofp_switch_config *osc;

        /* Send OFPT_FEATURES_REQUEST. */
        make_openflow(sizeof(struct ofp_header), OFPT_FEATURES_REQUEST, &b);
        queue_tx(sw, rconn, b);

        /* Send OFPT_SET_CONFIG. */
        osc = make_openflow(sizeof *osc, OFPT_SET_CONFIG, &b);
        osc->flags = htons(OFPC_SEND_FLOW_EXP);
        osc->miss_send_len = htons(OFP_DEFAULT_MISS_SEND_LEN);
        queue_tx(sw, rconn, b);

        sw->last_features_request = now;
    }
}

static void
queue_tx(struct lswitch *sw, struct rconn *rconn, struct ofpbuf *b)
{
    int retval = rconn_send_with_limit(rconn, b, &sw->n_queued, 10);
    if (retval && retval != ENOTCONN) {
        if (retval == EAGAIN) {
            VLOG_WARN_RL(&rl, "%s: tx queue overflow", rconn_get_name(rconn));
        } else {
            VLOG_WARN_RL(&rl, "%s: send: %s",
                         rconn_get_name(rconn), strerror(retval));
        }
    }
}

static void
process_switch_features(struct lswitch *sw, struct rconn *rconn,
                        struct ofp_switch_features *osf)
{
    size_t n_ports = ((ntohs(osf->header.length)
                       - offsetof(struct ofp_switch_features, ports))
                      / sizeof *osf->ports);
    size_t i;

    sw->datapath_id = osf->datapath_id;
    sw->capabilities = ntohl(osf->capabilities);
    for (i = 0; i < n_ports; i++) {
        process_phy_port(sw, rconn, &osf->ports[i]);
    }
}

static void
process_packet_in(struct lswitch *sw, struct rconn *rconn,
                  struct ofp_packet_in *opi)
{
    uint16_t in_port = ntohs(opi->in_port);
    uint16_t out_port = OFPP_FLOOD;

    size_t pkt_ofs, pkt_len;
    struct ofpbuf pkt;
    struct flow flow;

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, in_port, &flow);

    if (sw->ml) {
        if (mac_learning_learn(sw->ml, flow.dl_src, in_port)) {
            VLOG_DBG_RL(&rl, "learned that "ETH_ADDR_FMT" is on datapath %"
                        PRIx64" port %"PRIu16, ETH_ADDR_ARGS(flow.dl_src),
                        ntohll(sw->datapath_id), in_port);
        }
        out_port = mac_learning_lookup(sw->ml, flow.dl_dst);
    }

    if (in_port == out_port) {
        /* The input and output port match.  Set up a flow to drop packets. */
        queue_tx(sw, rconn, make_add_flow(&flow, ntohl(opi->buffer_id),
                                          sw->max_idle, 0));
    } else if (sw->max_idle >= 0 && (!sw->ml || out_port != OFPP_FLOOD)) {
        /* The output port is known, or we always flood everything, so add a
         * new flow. */
        queue_tx(sw, rconn, make_add_simple_flow(&flow, ntohl(opi->buffer_id),
                                                 out_port, sw->max_idle));

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            queue_tx(sw, rconn,
                     make_unbuffered_packet_out(&pkt, in_port, out_port));
        }
    } else {
        /* We don't know that MAC, or we don't set up flows.  Send along the
         * packet without setting up a flow. */
        struct ofpbuf *b;
        if (ntohl(opi->buffer_id) == UINT32_MAX) {
            b = make_unbuffered_packet_out(&pkt, in_port, out_port);
        } else {
            b = make_buffered_packet_out(ntohl(opi->buffer_id),
                                         in_port, out_port);
        }
        queue_tx(sw, rconn, b);
    }
}

static void
process_echo_request(struct lswitch *sw, struct rconn *rconn,
                     struct ofp_header *rq)
{
    queue_tx(sw, rconn, make_echo_reply(rq));
}

static void
process_port_status(struct lswitch *sw, struct rconn *rconn,
                    struct ofp_port_status *ops)
{
    process_phy_port(sw, rconn, &ops->desc);
}

static void
process_phy_port(struct lswitch *sw, struct rconn *rconn,
                 const struct ofp_phy_port *opp)
{
    if (sw->capabilities & OFPC_STP && ntohs(opp->port_no) < OFPP_MAX) {
        uint32_t config = ntohl(opp->config);
        uint32_t state = ntohl(opp->state);
        uint32_t new_config = config & ~(OFPPC_NO_RECV | OFPPC_NO_RECV_STP
                                         | OFPPC_NO_FWD | OFPPC_NO_PACKET_IN);
        if (!(config & (OFPPC_NO_STP | OFPPC_PORT_DOWN))
                    && !(state & OFPPS_LINK_DOWN)) {
            bool forward = false;
            bool learn = false;
            switch (state & OFPPS_STP_MASK) {
            case OFPPS_STP_LISTEN:
            case OFPPS_STP_BLOCK:
                break;
            case OFPPS_STP_LEARN:
                learn = true;
                break;
            case OFPPS_STP_FORWARD:
                forward = learn = true;
                break;
            }
            if (!forward) {
                new_config |= OFPPC_NO_RECV | OFPPC_NO_FWD;
            }
            if (!learn) {
                new_config |= OFPPC_NO_PACKET_IN;
            }
        }
        if (config != new_config) {
            struct ofp_port_mod *opm;
            struct ofpbuf *b;
            int retval;

            VLOG_WARN("port %d: config=%x new_config=%x",
                      ntohs(opp->port_no), config, new_config);
            opm = make_openflow(sizeof *opm, OFPT_PORT_MOD, &b);
            opm->port_no = opp->port_no;
            memcpy(opm->hw_addr, opp->hw_addr, OFP_ETH_ALEN);
            opm->config = htonl(new_config);
            opm->mask = htonl(config ^ new_config);
            opm->advertise = htonl(0);
            retval = rconn_send(rconn, b, NULL);
            if (retval) {
                if (retval != ENOTCONN) {
                    VLOG_WARN_RL(&rl, "%s: send: %s",
                                 rconn_get_name(rconn), strerror(retval));
                }
                ofpbuf_delete(b);
            }
        }
    }
}
