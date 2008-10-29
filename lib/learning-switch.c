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
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "queue.h"
#include "rconn.h"
#include "stp.h"
#include "timeval.h"
#include "vconn.h"
#include "xtoxll.h"

#define THIS_MODULE VLM_learning_switch
#include "vlog.h"

enum port_state {
    P_DISABLED = 1 << 0,
    P_LISTENING = 1 << 1,
    P_LEARNING = 1 << 2,
    P_FORWARDING = 1 << 3,
    P_BLOCKING = 1 << 4
};

struct lswitch {
    /* If nonnegative, the switch sets up flows that expire after the given
     * number of seconds (or never expire, if the value is OFP_FLOW_PERMANENT).
     * Otherwise, the switch processes every packet. */
    int max_idle;

    unsigned long long int datapath_id;
    uint32_t capabilities;
    time_t last_features_request;
    struct mac_learning *ml;    /* NULL to act as hub instead of switch. */

    /* Number of outgoing queued packets on the rconn. */
    int n_queued;

    /* Spanning tree protocol implementation.
     *
     * We implement STP states by, whenever a port's STP state changes,
     * querying all the flows on the switch and then deleting any of them that
     * are inappropriate for a port's STP state. */
    long long int next_query;   /* Next time at which to query all flows. */
    long long int last_query;   /* Last time we sent a query. */
    long long int last_reply;   /* Last time we received a query reply. */
    unsigned int port_states[STP_MAX_PORTS];
    uint32_t query_xid;         /* XID used for query. */
    int n_flows, n_no_recv, n_no_send;
};

/* The log messages here could actually be useful in debugging, so keep the
 * rate limit relatively high. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

static void queue_tx(struct lswitch *, struct rconn *, struct ofpbuf *);
static void send_features_request(struct lswitch *, struct rconn *);
static void schedule_query(struct lswitch *, long long int delay);
static bool may_learn(const struct lswitch *, uint16_t port_no);
static bool may_recv(const struct lswitch *, uint16_t port_no,
                     bool any_actions);
static bool may_send(const struct lswitch *, uint16_t port_no);

typedef void packet_handler_func(struct lswitch *, struct rconn *, void *);
static packet_handler_func process_switch_features;
static packet_handler_func process_packet_in;
static packet_handler_func process_echo_request;
static packet_handler_func process_port_status;
static packet_handler_func process_phy_port;
static packet_handler_func process_stats_reply;

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
    struct lswitch *sw;
    size_t i;

    sw = xcalloc(1, sizeof *sw);
    sw->max_idle = max_idle;
    sw->datapath_id = 0;
    sw->last_features_request = time_now() - 1;
    sw->ml = learn_macs ? mac_learning_create() : NULL;
    sw->next_query = LLONG_MIN;
    sw->last_query = LLONG_MIN;
    sw->last_reply = LLONG_MIN;
    for (i = 0; i < STP_MAX_PORTS; i++) {
        sw->port_states[i] = P_DISABLED;
    }
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

/* Takes care of necessary 'sw' activity, except for receiving packets (which
 * the caller must do). */
void
lswitch_run(struct lswitch *sw, struct rconn *rconn)
{
    long long int now = time_msec();

    /* If we're waiting for more replies, keeping waiting for up to 10 s. */
    if (sw->last_reply != LLONG_MIN) {
        if (now - sw->last_reply > 10000) {
            VLOG_ERR_RL(&rl, "%012llx: No more flow stat replies last 10 s",
                        sw->datapath_id);
            sw->last_reply = LLONG_MIN;
            sw->last_query = LLONG_MIN;
            schedule_query(sw, 0);
        } else {
            return;
        }
    }

    /* If we're waiting for any reply at all, keep waiting for up to 10 s. */
    if (sw->last_query != LLONG_MIN) {
        if (now - sw->last_query > 10000) {
            VLOG_ERR_RL(&rl, "%012llx: No flow stat replies in last 10 s",
                        sw->datapath_id);
            sw->last_query = LLONG_MIN;
            schedule_query(sw, 0);
        } else {
            return;
        }
    }

    /* If it's time to send another query, do so. */
    if (sw->next_query != LLONG_MIN && now >= sw->next_query) {
        sw->next_query = LLONG_MIN;
        if (!rconn_is_connected(rconn)) {
            schedule_query(sw, 1000);
        } else {
            struct ofp_stats_request *osr;
            struct ofp_flow_stats_request *ofsr;
            struct ofpbuf *b;
            int error;

            VLOG_DBG("%012llx: Sending flow stats request to implement STP",
                     sw->datapath_id);

            sw->last_query = now;
            sw->query_xid = random_uint32();
            sw->n_flows = 0;
            sw->n_no_recv = 0;
            sw->n_no_send = 0;
            osr = make_openflow_xid(sizeof *osr + sizeof *ofsr,
                                    OFPT_STATS_REQUEST, sw->query_xid, &b);
            osr->type = htons(OFPST_FLOW);
            osr->flags = htons(0);
            ofsr = (struct ofp_flow_stats_request *) osr->body;
            ofsr->match.wildcards = htonl(OFPFW_ALL);
            ofsr->table_id = 0xff;

            error = rconn_send(rconn, b, NULL);
            if (error) {
                VLOG_WARN_RL(&rl, "%012llx: sending flow stats request "
                             "failed: %s", sw->datapath_id, strerror(error));
                ofpbuf_delete(b);
                schedule_query(sw, 1000);
            }
        }
    }
}

static void
wait_timeout(long long int started)
{
    long long int now = time_msec();
    long long int timeout = 10000 - (now - started);
    if (timeout <= 0) {
        poll_immediate_wake();
    } else {
        poll_timer_wait(timeout);
    }
}

void
lswitch_wait(struct lswitch *sw)
{
    if (sw->last_reply != LLONG_MIN) {
        wait_timeout(sw->last_reply);
    } else if (sw->last_query != LLONG_MIN) {
        wait_timeout(sw->last_query);
    }
}

/* Processes 'msg', which should be an OpenFlow received on 'rconn', according
 * to the learning switch state in 'sw'.  The most likely result of processing
 * is that flow-setup and packet-out OpenFlow messages will be sent out on
 * 'rconn'.  */
void
lswitch_process_packet(struct lswitch *sw, struct rconn *rconn,
                       const struct ofpbuf *msg)
{
    struct processor {
        uint8_t type;
        size_t min_size;
        packet_handler_func *handler;
    };
    static const struct processor processors[] = {
        {
            OFPT_ECHO_REQUEST,
            sizeof(struct ofp_header),
            process_echo_request
        },
        {
            OFPT_FEATURES_REPLY,
            sizeof(struct ofp_switch_features),
            process_switch_features
        },
        {
            OFPT_PACKET_IN,
            offsetof(struct ofp_packet_in, data),
            process_packet_in
        },
        {
            OFPT_PORT_STATUS,
            sizeof(struct ofp_port_status),
            process_port_status
        },
        {
            OFPT_STATS_REPLY,
            offsetof(struct ofp_stats_reply, body),
            process_stats_reply
        },
        {
            OFPT_FLOW_EXPIRED,
            sizeof(struct ofp_flow_expired),
            NULL
        },
    };
    const size_t n_processors = ARRAY_SIZE(processors);
    const struct processor *p;
    struct ofp_header *oh;

    oh = msg->data;
    if (sw->datapath_id == 0
        && oh->type != OFPT_ECHO_REQUEST
        && oh->type != OFPT_FEATURES_REPLY) {
        send_features_request(sw, rconn);
        return;
    }

    for (p = processors; p < &processors[n_processors]; p++) {
        if (oh->type == p->type) {
            if (msg->size < p->min_size) {
                VLOG_WARN_RL(&rl, "%012llx: %s: too short (%zu bytes) for "
                             "type %"PRIu8" (min %zu)", sw->datapath_id,
                             rconn_get_name(rconn), msg->size, oh->type,
                             p->min_size);
                return;
            }
            if (p->handler) {
                (p->handler)(sw, rconn, msg->data);
            }
            return;
        }
    }
    if (VLOG_IS_DBG_ENABLED()) {
        char *p = ofp_to_string(msg->data, msg->size, 2);
        VLOG_DBG_RL(&rl, "%012llx: OpenFlow packet ignored: %s",
                    sw->datapath_id, p);
        free(p);
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
            VLOG_WARN_RL(&rl, "%012llx: %s: tx queue overflow",
                         sw->datapath_id, rconn_get_name(rconn));
        } else {
            VLOG_WARN_RL(&rl, "%012llx: %s: send: %s",
                         sw->datapath_id, rconn_get_name(rconn),
                         strerror(retval));
        }
    }
}

static void
schedule_query(struct lswitch *sw, long long int delay)
{
    long long int now = time_msec();
    if (sw->next_query == LLONG_MIN || sw->next_query > now + delay) {
        sw->next_query = now + delay;
    }
}

static void
process_switch_features(struct lswitch *sw, struct rconn *rconn, void *osf_)
{
    struct ofp_switch_features *osf = osf_;
    size_t n_ports = ((ntohs(osf->header.length)
                       - offsetof(struct ofp_switch_features, ports))
                      / sizeof *osf->ports);
    size_t i;

    sw->datapath_id = ntohll(osf->datapath_id);
    sw->capabilities = ntohl(osf->capabilities);
    for (i = 0; i < n_ports; i++) {
        process_phy_port(sw, rconn, &osf->ports[i]);
    }
    if (sw->capabilities & OFPC_STP) {
        schedule_query(sw, 1000);
    }
}

static void
process_packet_in(struct lswitch *sw, struct rconn *rconn, void *opi_)
{
    struct ofp_packet_in *opi = opi_;
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

    if (may_learn(sw, in_port) && sw->ml) {
        if (mac_learning_learn(sw->ml, flow.dl_src, in_port)) {
            VLOG_DBG_RL(&rl, "%012llx: learned that "ETH_ADDR_FMT" is on "
                        "port %"PRIu16, sw->datapath_id,
                        ETH_ADDR_ARGS(flow.dl_src), in_port);
        }
    }

    if (!may_recv(sw, in_port, false)) {
        /* STP prevents receiving anything on this port. */
        goto drop_it;
    }

    if (sw->ml) {
        uint16_t learned_port = mac_learning_lookup(sw->ml, flow.dl_dst);
        if (may_send(sw, learned_port)) {
            out_port = learned_port;
        }
    }

    if (in_port == out_port) {
        /* Don't send out packets on their input ports. */
        goto drop_it;
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
    return;

drop_it:
    /* Set up a flow to drop packets, or just drop the packet if we don't set
     * up flows at all. */
    if (sw->max_idle >= 0) {
        queue_tx(sw, rconn, make_add_flow(&flow, ntohl(opi->buffer_id),
                                          sw->max_idle, 0));
    }
    return;
}

static void
process_echo_request(struct lswitch *sw, struct rconn *rconn, void *rq_)
{
    struct ofp_header *rq = rq_;
    queue_tx(sw, rconn, make_echo_reply(rq));
}

static void
process_port_status(struct lswitch *sw, struct rconn *rconn, void *ops_)
{
    struct ofp_port_status *ops = ops_;
    process_phy_port(sw, rconn, &ops->desc);
}

static void
process_phy_port(struct lswitch *sw, struct rconn *rconn, void *opp_)
{
    const struct ofp_phy_port *opp = opp_;
    uint16_t port_no = ntohs(opp->port_no);
    if (sw->capabilities & OFPC_STP && port_no < STP_MAX_PORTS) {
        uint32_t config = ntohl(opp->config);
        uint32_t state = ntohl(opp->state);
        unsigned int *port_state = &sw->port_states[port_no];
        unsigned int new_port_state;

        if (!(config & (OFPPC_NO_STP | OFPPC_PORT_DOWN))
            && !(state & OFPPS_LINK_DOWN))
        {
            switch (state & OFPPS_STP_MASK) {
            case OFPPS_STP_LISTEN:
                new_port_state = P_LISTENING;
                break;
            case OFPPS_STP_LEARN:
                new_port_state = P_LEARNING;
                break;
            case OFPPS_STP_FORWARD:
                new_port_state = P_FORWARDING;
                break;
            case OFPPS_STP_BLOCK:
                new_port_state = P_BLOCKING;
                break;
            default:
                new_port_state = P_DISABLED;
                break;
            }
        } else {
            new_port_state = P_FORWARDING;
        }
        if (*port_state != new_port_state) {
            *port_state = new_port_state;
            schedule_query(sw, 1000);
        }
    }
}

static unsigned int
get_port_state(const struct lswitch *sw, uint16_t port_no)
{
    return (port_no >= STP_MAX_PORTS || !(sw->capabilities & OFPC_STP)
            ? P_FORWARDING
            : sw->port_states[port_no]);
}

static bool
may_learn(const struct lswitch *sw, uint16_t port_no)
{
    return get_port_state(sw, port_no) & (P_LEARNING | P_FORWARDING);
}

static bool
may_recv(const struct lswitch *sw, uint16_t port_no, bool any_actions)
{
    unsigned int state = get_port_state(sw, port_no);
    return !(any_actions
             ? state & (P_DISABLED | P_LISTENING | P_BLOCKING)
             : state & (P_DISABLED | P_LISTENING | P_BLOCKING | P_LEARNING));
}

static bool
may_send(const struct lswitch *sw, uint16_t port_no)
{
    return get_port_state(sw, port_no) & P_FORWARDING;
}

static void
process_flow_stats(struct lswitch *sw, struct rconn *rconn,
                   const struct ofp_flow_stats *ofs)
{
    const char *end = (char *) ofs + ntohs(ofs->length);
    bool delete = false;

    /* Decide to delete the flow if it matches on an STP-disabled physical
     * port.  But don't delete it if the flow just drops all received packets,
     * because that's a perfectly reasonable thing to do for disabled physical
     * ports. */
    if (!(ofs->match.wildcards & htonl(OFPFW_IN_PORT))) {
        if (!may_recv(sw, ntohs(ofs->match.in_port),
                      end > (char *) ofs->actions)) {
            delete = true;
            sw->n_no_recv++;
        }
    }

    /* Decide to delete the flow if it forwards to an STP-disabled physical
     * port. */
    if (!delete) {
        const struct ofp_action_header *a;
        size_t len;

        for (a = ofs->actions; (char *) a < end; a += len / 8) {
            uint16_t type;

            len = ntohs(a->len);
            if (len > end - (char *) a) {
                VLOG_DBG_RL(&rl, "%012llx: action exceeds available space "
                            "(%zu > %td)",
                            sw->datapath_id, len, end - (char *) a);
                break;
            } else if (len % 8) {
                VLOG_DBG_RL(&rl, "%012llx: action length (%zu) not multiple "
                            "of 8 bytes", sw->datapath_id, len);
                break;
            }

            type = ntohs(a->type);
            if (a->type == htons(OFPAT_OUTPUT)) {
                struct ofp_action_output *oao = (struct ofp_action_output *) a;
                if (!may_send(sw, ntohs(oao->port))) {
                    delete = true;
                    sw->n_no_send++;
                    break;
                }
            }
        }
    }

    /* Delete the flow. */
    if (delete) {
        struct ofp_flow_mod *ofm;
        struct ofpbuf *b;

        ofm = make_openflow(offsetof(struct ofp_flow_mod, actions),
                            OFPT_FLOW_MOD, &b);
        ofm->match = ofs->match;
        ofm->command = OFPFC_DELETE_STRICT;
        rconn_send(rconn, b, NULL);
    }
}

static void
process_stats_reply(struct lswitch *sw, struct rconn *rconn, void *osr_)
{
    struct ofp_stats_reply *osr = osr_;
    const uint8_t *body = osr->body;
    const uint8_t *pos = body;
    size_t body_len;

    if (sw->last_query == LLONG_MIN
        || osr->type != htons(OFPST_FLOW)
        || osr->header.xid != sw->query_xid) {
        return;
    }
    body_len = (ntohs(osr->header.length)
                - offsetof(struct ofp_stats_reply, body));
    for (;;) {
        const struct ofp_flow_stats *fs;
        ptrdiff_t bytes_left = body + body_len - pos;
        size_t length;

        if (bytes_left < sizeof *fs) {
            if (bytes_left != 0) {
                VLOG_WARN_RL(&rl, "%012llx: %td leftover bytes in flow "
                             "stats reply", sw->datapath_id, bytes_left);
            }
            break;
        }

        fs = (const void *) pos;
        length = ntohs(fs->length);
        if (length < sizeof *fs) {
            VLOG_WARN_RL(&rl, "%012llx: flow stats length %zu is shorter than "
                         "min %zu", sw->datapath_id, length, sizeof *fs);
            break;
        } else if (length > bytes_left) {
            VLOG_WARN_RL(&rl, "%012llx: flow stats length %zu but only %td "
                         "bytes left", sw->datapath_id, length, bytes_left);
            break;
        } else if ((length - sizeof *fs) % sizeof fs->actions[0]) {
            VLOG_WARN_RL(&rl, "%012llx: flow stats length %zu has %zu bytes "
                         "left over in final action", sw->datapath_id, length,
                         (length - sizeof *fs) % sizeof fs->actions[0]);
            break;
        }

        sw->n_flows++;
        process_flow_stats(sw, rconn, fs);

        pos += length;
     }
    if (!(osr->flags & htons(OFPSF_REPLY_MORE))) {
        VLOG_DBG("%012llx: Deleted %d of %d received flows to "
                 "implement STP, %d because of no-recv, %d because of "
                 "no-send", sw->datapath_id,
                 sw->n_no_recv + sw->n_no_send, sw->n_flows,
                 sw->n_no_recv, sw->n_no_send);
        sw->last_query = LLONG_MIN;
        sw->last_reply = LLONG_MIN;
    } else {
        sw->last_reply = time_msec();
    }
}

