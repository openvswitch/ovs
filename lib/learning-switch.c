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

#include "buffer.h"
#include "flow.h"
#include "mac-learning.h"
#include "ofp-print.h"
#include "openflow.h"
#include "queue.h"
#include "rconn.h"
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
    time_t last_features_request;
    struct mac_learning *ml;    /* NULL to act as hub instead of switch. */
};

static void queue_tx(struct lswitch *, struct rconn *, struct buffer *);
static void send_features_request(struct lswitch *, struct rconn *);
static void process_packet_in(struct lswitch *, struct rconn *,
                              struct ofp_packet_in *);
static void process_echo_request(struct lswitch *, struct rconn *,
                                 struct ofp_header *);

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
    struct lswitch *sw = xmalloc(sizeof *sw);
    memset(sw, 0, sizeof *sw);
    sw->max_idle = max_idle;
    sw->datapath_id = 0;
    sw->last_features_request = time(0) - 1;
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

/* Processes 'msg', which should be an OpenFlow received on 'rconn', according
 * to the learning switch state in 'sw'.  The most likely result of processing
 * is that flow-setup and packet-out OpenFlow messages will be sent out on
 * 'rconn'.  */
void
lswitch_process_packet(struct lswitch *sw, struct rconn *rconn,
                       const struct buffer *msg)
{
    static const size_t min_size[UINT8_MAX + 1] = {
        [0 ... UINT8_MAX] = sizeof (struct ofp_header),
        [OFPT_FEATURES_REPLY] = sizeof (struct ofp_switch_features),
        [OFPT_PACKET_IN] = offsetof (struct ofp_packet_in, data),
    };
    struct ofp_header *oh;

    oh = msg->data;
    if (msg->size < min_size[oh->type]) {
        VLOG_WARN("%s: too short (%zu bytes) for type %"PRIu8" (min %zu)",
                  rconn_get_name(rconn),
                  msg->size, oh->type, min_size[oh->type]);
        return;
    }

    if (oh->type == OFPT_ECHO_REQUEST) {
        process_echo_request(sw, rconn, msg->data);
    } else if (oh->type == OFPT_FEATURES_REPLY) {
        struct ofp_switch_features *osf = msg->data;
        sw->datapath_id = osf->datapath_id;
    } else if (sw->datapath_id == 0) {
        send_features_request(sw, rconn);
    } else if (oh->type == OFPT_PACKET_IN) {
        process_packet_in(sw, rconn, msg->data);
    } else {
        if (VLOG_IS_DBG_ENABLED()) {
            char *p = ofp_to_string(msg->data, msg->size, 2);
            VLOG_DBG("OpenFlow packet ignored: %s", p);
            free(p);
        }
    }
}

static void
send_features_request(struct lswitch *sw, struct rconn *rconn)
{
    time_t now = time(0);
    if (now >= sw->last_features_request + 1) {
        struct buffer *b;
        struct ofp_header *ofr;
        struct ofp_switch_config *osc;

        /* Send OFPT_FEATURES_REQUEST. */
        b = buffer_new(0);
        ofr = buffer_put_uninit(b, sizeof *ofr);
        memset(ofr, 0, sizeof *ofr);
        ofr->type = OFPT_FEATURES_REQUEST;
        ofr->version = OFP_VERSION;
        ofr->length = htons(sizeof *ofr);
        queue_tx(sw, rconn, b);

        /* Send OFPT_SET_CONFIG. */
        b = buffer_new(0);
        osc = buffer_put_uninit(b, sizeof *osc);
        memset(osc, 0, sizeof *osc);
        osc->header.type = OFPT_SET_CONFIG;
        osc->header.version = OFP_VERSION;
        osc->header.length = htons(sizeof *osc);
        osc->flags = htons(OFPC_SEND_FLOW_EXP);
        osc->miss_send_len = htons(OFP_DEFAULT_MISS_SEND_LEN);
        queue_tx(sw, rconn, b);

        sw->last_features_request = now;
    }
}

static void
queue_tx(struct lswitch *sw, struct rconn *rconn, struct buffer *b)
{
    int retval = rconn_send(rconn, b);
    if (retval) {
        if (retval == EAGAIN) {
            /* FIXME: ratelimit. */
            VLOG_WARN("%s: tx queue overflow", rconn_get_name(rconn));
        } else if (retval == ENOTCONN) {
            /* Ignore. */
        } else {
            /* FIXME: ratelimit. */
            VLOG_WARN("%s: send: %s", rconn_get_name(rconn), strerror(retval));
        }
        buffer_delete(b);
    }
}

static void
process_packet_in(struct lswitch *sw, struct rconn *rconn,
                  struct ofp_packet_in *opi)
{
    uint16_t in_port = ntohs(opi->in_port);
    uint16_t out_port = OFPP_FLOOD;

    size_t pkt_ofs, pkt_len;
    struct buffer pkt;
    struct flow flow;

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, in_port, &flow);

    if (sw->ml) {
        if (mac_learning_learn(sw->ml, flow.dl_src, in_port)) {
            VLOG_DBG("learned that "ETH_ADDR_FMT" is on datapath %"
                     PRIx64" port %"PRIu16, ETH_ADDR_ARGS(flow.dl_src),
                     ntohll(sw->datapath_id), in_port);
        }
        out_port = mac_learning_lookup(sw->ml, flow.dl_dst);
    }

    if (in_port == out_port) {
        /* The input port and output port match, so just drop the packet 
         * by returning. */
        return;
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
        struct buffer *b;
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
