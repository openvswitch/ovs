/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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
#include "learning-switch.h"

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

#include "byte-order.h"
#include "classifier.h"
#include "flow.h"
#include "hmap.h"
#include "mac-learning.h"
#include "ofpbuf.h"
#include "ofp-actions.h"
#include "ofp-errors.h"
#include "ofp-msgs.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "rconn.h"
#include "shash.h"
#include "simap.h"
#include "timeval.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(learning_switch);

struct lswitch_port {
    struct hmap_node hmap_node; /* Hash node for port number. */
    uint16_t port_no;           /* OpenFlow port number, in host byte order. */
    uint32_t queue_id;          /* OpenFlow queue number. */
};

enum lswitch_state {
    S_CONNECTING,               /* Waiting for connection to complete. */
    S_FEATURES_REPLY,           /* Waiting for features reply. */
    S_SWITCHING,                /* Switching flows. */
};

struct lswitch {
    struct rconn *rconn;
    enum lswitch_state state;

    /* If nonnegative, the switch sets up flows that expire after the given
     * number of seconds (or never expire, if the value is OFP_FLOW_PERMANENT).
     * Otherwise, the switch processes every packet. */
    int max_idle;

    enum ofputil_protocol protocol;
    unsigned long long int datapath_id;
    struct mac_learning *ml;    /* NULL to act as hub instead of switch. */
    struct flow_wildcards wc;   /* Wildcards to apply to flows. */
    bool action_normal;         /* Use OFPP_NORMAL? */

    /* Queue distribution. */
    uint32_t default_queue;     /* Default OpenFlow queue, or UINT32_MAX. */
    struct hmap queue_numbers;  /* Map from port number to lswitch_port. */
    struct shash queue_names;   /* Map from port name to lswitch_port. */

    /* Number of outgoing queued packets on the rconn. */
    struct rconn_packet_counter *queued;

    /* If true, do not reply to any messages from the switch (for debugging
     * fail-open mode). */
    bool mute;

    /* Optional "flow mod" requests to send to the switch at connection time,
     * to set up the flow table. */
    const struct ofputil_flow_mod *default_flows;
    size_t n_default_flows;
};

/* The log messages here could actually be useful in debugging, so keep the
 * rate limit relatively high. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

static void queue_tx(struct lswitch *, struct ofpbuf *);
static void send_features_request(struct lswitch *);

static void lswitch_process_packet(struct lswitch *, const struct ofpbuf *);
static enum ofperr process_switch_features(struct lswitch *,
                                           struct ofp_header *);
static void process_packet_in(struct lswitch *, const struct ofp_header *);
static void process_echo_request(struct lswitch *, const struct ofp_header *);

/* Creates and returns a new learning switch whose configuration is given by
 * 'cfg'.
 *
 * 'rconn' is used to send out an OpenFlow features request. */
struct lswitch *
lswitch_create(struct rconn *rconn, const struct lswitch_config *cfg)
{
    struct lswitch *sw;
    uint32_t ofpfw;

    sw = xzalloc(sizeof *sw);
    sw->rconn = rconn;
    sw->state = S_CONNECTING;
    sw->max_idle = cfg->max_idle;
    sw->datapath_id = 0;
    sw->ml = (cfg->mode == LSW_LEARN
              ? mac_learning_create(MAC_ENTRY_DEFAULT_IDLE_TIME)
              : NULL);
    sw->action_normal = cfg->mode == LSW_NORMAL;

    switch (cfg->wildcards) {
    case 0:
        ofpfw = 0;
        break;

    case UINT32_MAX:
        /* Try to wildcard as many fields as possible, but we cannot
         * wildcard all fields.  We need in_port to detect moves.  We need
         * Ethernet source and dest and VLAN VID to do L2 learning. */
        ofpfw = (OFPFW10_DL_TYPE | OFPFW10_DL_VLAN_PCP
                 | OFPFW10_NW_SRC_ALL | OFPFW10_NW_DST_ALL
                 | OFPFW10_NW_TOS | OFPFW10_NW_PROTO
                 | OFPFW10_TP_SRC | OFPFW10_TP_DST);
        break;

    default:
        ofpfw = cfg->wildcards;
        break;
    }
    ofputil_wildcard_from_ofpfw10(ofpfw, &sw->wc);

    sw->default_queue = cfg->default_queue;
    hmap_init(&sw->queue_numbers);
    shash_init(&sw->queue_names);
    if (cfg->port_queues) {
        struct simap_node *node;

        SIMAP_FOR_EACH (node, cfg->port_queues) {
            struct lswitch_port *port = xmalloc(sizeof *port);
            hmap_node_nullify(&port->hmap_node);
            port->queue_id = node->data;
            shash_add(&sw->queue_names, node->name, port);
        }
    }

    sw->default_flows = cfg->default_flows;
    sw->n_default_flows = cfg->n_default_flows;

    sw->queued = rconn_packet_counter_create();

    return sw;
}

static void
lswitch_handshake(struct lswitch *sw)
{
    enum ofputil_protocol protocol;

    send_features_request(sw);

    protocol = ofputil_protocol_from_ofp_version(rconn_get_version(sw->rconn));
    if (sw->default_flows) {
        enum ofputil_protocol usable_protocols;
        struct ofpbuf *msg = NULL;
        int error = 0;
        size_t i;

        /* If the initial protocol isn't good enough for default_flows, then
         * pick one that will work and encode messages to set up that
         * protocol.
         *
         * This could be improved by actually negotiating a mutually acceptable
         * flow format with the switch, but that would require an asynchronous
         * state machine.  This version ought to work fine in practice. */
        usable_protocols = ofputil_flow_mod_usable_protocols(
            sw->default_flows, sw->n_default_flows);
        if (!(protocol & usable_protocols)) {
            enum ofputil_protocol want = rightmost_1bit(usable_protocols);
            while (!error) {
                msg = ofputil_encode_set_protocol(protocol, want, &protocol);
                if (!msg) {
                    break;
                }
                error = rconn_send(sw->rconn, msg, NULL);
            }
        }

        for (i = 0; !error && i < sw->n_default_flows; i++) {
            msg = ofputil_encode_flow_mod(&sw->default_flows[i], protocol);
            error = rconn_send(sw->rconn, msg, NULL);
        }

        if (error) {
            VLOG_INFO_RL(&rl, "%s: failed to queue default flows (%s)",
                         rconn_get_name(sw->rconn), strerror(error));
        }
    }
    sw->protocol = protocol;
}

bool
lswitch_is_alive(const struct lswitch *sw)
{
    return rconn_is_alive(sw->rconn);
}

/* Destroys 'sw'. */
void
lswitch_destroy(struct lswitch *sw)
{
    if (sw) {
        struct lswitch_port *node, *next;

        rconn_destroy(sw->rconn);
        HMAP_FOR_EACH_SAFE (node, next, hmap_node, &sw->queue_numbers) {
            hmap_remove(&sw->queue_numbers, &node->hmap_node);
            free(node);
        }
        shash_destroy(&sw->queue_names);
        mac_learning_destroy(sw->ml);
        rconn_packet_counter_destroy(sw->queued);
        free(sw);
    }
}

/* Takes care of necessary 'sw' activity, except for receiving packets (which
 * the caller must do). */
void
lswitch_run(struct lswitch *sw)
{
    int i;

    if (sw->ml) {
        mac_learning_run(sw->ml, NULL);
    }

    rconn_run(sw->rconn);

    if (sw->state == S_CONNECTING) {
        if (rconn_get_version(sw->rconn) != -1) {
            lswitch_handshake(sw);
            sw->state = S_FEATURES_REPLY;
        }
        return;
    }

    for (i = 0; i < 50; i++) {
        struct ofpbuf *msg;

        msg = rconn_recv(sw->rconn);
        if (!msg) {
            break;
        }

        if (!sw->mute) {
            lswitch_process_packet(sw, msg);
        }
        ofpbuf_delete(msg);
    }
}

void
lswitch_wait(struct lswitch *sw)
{
    if (sw->ml) {
        mac_learning_wait(sw->ml);
    }
    rconn_run_wait(sw->rconn);
    rconn_recv_wait(sw->rconn);
}

/* Processes 'msg', which should be an OpenFlow received on 'rconn', according
 * to the learning switch state in 'sw'.  The most likely result of processing
 * is that flow-setup and packet-out OpenFlow messages will be sent out on
 * 'rconn'.  */
static void
lswitch_process_packet(struct lswitch *sw, const struct ofpbuf *msg)
{
    enum ofptype type;
    struct ofpbuf b;

    b = *msg;
    if (ofptype_pull(&type, &b)) {
        return;
    }

    if (sw->state == S_FEATURES_REPLY
        && type != OFPTYPE_ECHO_REQUEST
        && type != OFPTYPE_FEATURES_REPLY) {
        return;
    }

    switch (type) {
    case OFPTYPE_ECHO_REQUEST:
        process_echo_request(sw, msg->data);
        break;

    case OFPTYPE_FEATURES_REPLY:
        if (sw->state == S_FEATURES_REPLY) {
            if (!process_switch_features(sw, msg->data)) {
                sw->state = S_SWITCHING;
            } else {
                rconn_disconnect(sw->rconn);
            }
        }
        break;

    case OFPTYPE_PACKET_IN:
        process_packet_in(sw, msg->data);
        break;

    case OFPTYPE_FLOW_REMOVED:
        /* Nothing to do. */
        break;

    case OFPTYPE_HELLO:
    case OFPTYPE_ERROR:
    case OFPTYPE_ECHO_REPLY:
    case OFPTYPE_FEATURES_REQUEST:
    case OFPTYPE_GET_CONFIG_REQUEST:
    case OFPTYPE_GET_CONFIG_REPLY:
    case OFPTYPE_SET_CONFIG:
    case OFPTYPE_PORT_STATUS:
    case OFPTYPE_PACKET_OUT:
    case OFPTYPE_FLOW_MOD:
    case OFPTYPE_PORT_MOD:
    case OFPTYPE_BARRIER_REQUEST:
    case OFPTYPE_BARRIER_REPLY:
    case OFPTYPE_DESC_STATS_REQUEST:
    case OFPTYPE_DESC_STATS_REPLY:
    case OFPTYPE_FLOW_STATS_REQUEST:
    case OFPTYPE_FLOW_STATS_REPLY:
    case OFPTYPE_AGGREGATE_STATS_REQUEST:
    case OFPTYPE_AGGREGATE_STATS_REPLY:
    case OFPTYPE_TABLE_STATS_REQUEST:
    case OFPTYPE_TABLE_STATS_REPLY:
    case OFPTYPE_PORT_STATS_REQUEST:
    case OFPTYPE_PORT_STATS_REPLY:
    case OFPTYPE_QUEUE_STATS_REQUEST:
    case OFPTYPE_QUEUE_STATS_REPLY:
    case OFPTYPE_PORT_DESC_STATS_REQUEST:
    case OFPTYPE_PORT_DESC_STATS_REPLY:
    case OFPTYPE_ROLE_REQUEST:
    case OFPTYPE_ROLE_REPLY:
    case OFPTYPE_SET_FLOW_FORMAT:
    case OFPTYPE_FLOW_MOD_TABLE_ID:
    case OFPTYPE_SET_PACKET_IN_FORMAT:
    case OFPTYPE_FLOW_AGE:
    case OFPTYPE_SET_ASYNC_CONFIG:
    case OFPTYPE_SET_CONTROLLER_ID:
    case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
    case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
    case OFPTYPE_FLOW_MONITOR_CANCEL:
    case OFPTYPE_FLOW_MONITOR_PAUSED:
    case OFPTYPE_FLOW_MONITOR_RESUMED:
    default:
        if (VLOG_IS_DBG_ENABLED()) {
            char *s = ofp_to_string(msg->data, msg->size, 2);
            VLOG_DBG_RL(&rl, "%016llx: OpenFlow packet ignored: %s",
                        sw->datapath_id, s);
            free(s);
        }
    }
}

static void
send_features_request(struct lswitch *sw)
{
    struct ofpbuf *b;
    struct ofp_switch_config *osc;
    int ofp_version = rconn_get_version(sw->rconn);

    assert(ofp_version > 0 && ofp_version < 0xff);

    /* Send OFPT_FEATURES_REQUEST. */
    b = ofpraw_alloc(OFPRAW_OFPT_FEATURES_REQUEST, ofp_version, 0);
    queue_tx(sw, b);

    /* Send OFPT_SET_CONFIG. */
    b = ofpraw_alloc(OFPRAW_OFPT_SET_CONFIG, ofp_version, sizeof *osc);
    osc = ofpbuf_put_zeros(b, sizeof *osc);
    osc->miss_send_len = htons(OFP_DEFAULT_MISS_SEND_LEN);
    queue_tx(sw, b);
}

static void
queue_tx(struct lswitch *sw, struct ofpbuf *b)
{
    int retval = rconn_send_with_limit(sw->rconn, b, sw->queued, 10);
    if (retval && retval != ENOTCONN) {
        if (retval == EAGAIN) {
            VLOG_INFO_RL(&rl, "%016llx: %s: tx queue overflow",
                         sw->datapath_id, rconn_get_name(sw->rconn));
        } else {
            VLOG_WARN_RL(&rl, "%016llx: %s: send: %s",
                         sw->datapath_id, rconn_get_name(sw->rconn),
                         strerror(retval));
        }
    }
}

static enum ofperr
process_switch_features(struct lswitch *sw, struct ofp_header *oh)
{
    struct ofputil_switch_features features;
    struct ofputil_phy_port port;
    enum ofperr error;
    struct ofpbuf b;

    error = ofputil_decode_switch_features(oh, &features, &b);
    if (error) {
        VLOG_ERR("received invalid switch feature reply (%s)",
                 ofperr_to_string(error));
        return error;
    }

    sw->datapath_id = features.datapath_id;

    while (!ofputil_pull_phy_port(oh->version, &b, &port)) {
        struct lswitch_port *lp = shash_find_data(&sw->queue_names, port.name);
        if (lp && hmap_node_is_null(&lp->hmap_node)) {
            lp->port_no = port.port_no;
            hmap_insert(&sw->queue_numbers, &lp->hmap_node,
                        hash_int(lp->port_no, 0));
        }
    }
    return 0;
}

static uint16_t
lswitch_choose_destination(struct lswitch *sw, const struct flow *flow)
{
    uint16_t out_port;

    /* Learn the source MAC. */
    if (sw->ml && mac_learning_may_learn(sw->ml, flow->dl_src, 0)) {
        struct mac_entry *mac = mac_learning_insert(sw->ml, flow->dl_src, 0);
        if (mac_entry_is_new(mac) || mac->port.i != flow->in_port) {
            VLOG_DBG_RL(&rl, "%016llx: learned that "ETH_ADDR_FMT" is on "
                        "port %"PRIu16, sw->datapath_id,
                        ETH_ADDR_ARGS(flow->dl_src), flow->in_port);

            mac->port.i = flow->in_port;
            mac_learning_changed(sw->ml, mac);
        }
    }

    /* Drop frames for reserved multicast addresses. */
    if (eth_addr_is_reserved(flow->dl_dst)) {
        return OFPP_NONE;
    }

    out_port = OFPP_FLOOD;
    if (sw->ml) {
        struct mac_entry *mac;

        mac = mac_learning_lookup(sw->ml, flow->dl_dst, 0, NULL);
        if (mac) {
            out_port = mac->port.i;
            if (out_port == flow->in_port) {
                /* Don't send a packet back out its input port. */
                return OFPP_NONE;
            }
        }
    }

    /* Check if we need to use "NORMAL" action. */
    if (sw->action_normal && out_port != OFPP_FLOOD) {
        return OFPP_NORMAL;
    }

    return out_port;
}

static uint32_t
get_queue_id(const struct lswitch *sw, uint16_t in_port)
{
    const struct lswitch_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, hmap_node, hash_int(in_port, 0),
                             &sw->queue_numbers) {
        if (port->port_no == in_port) {
            return port->queue_id;
        }
    }

    return sw->default_queue;
}

static void
process_packet_in(struct lswitch *sw, const struct ofp_header *oh)
{
    struct ofputil_packet_in pi;
    uint32_t queue_id;
    uint16_t out_port;

    uint64_t ofpacts_stub[64 / 8];
    struct ofpbuf ofpacts;

    struct ofputil_packet_out po;
    enum ofperr error;

    struct ofpbuf pkt;
    struct flow flow;

    error = ofputil_decode_packet_in(&pi, oh);
    if (error) {
        VLOG_WARN_RL(&rl, "failed to decode packet-in: %s",
                     ofperr_to_string(error));
        return;
    }

    /* Ignore packets sent via output to OFPP_CONTROLLER.  This library never
     * uses such an action.  You never know what experiments might be going on,
     * though, and it seems best not to interfere with them. */
    if (pi.reason != OFPR_NO_MATCH) {
        return;
    }

    /* Extract flow data from 'opi' into 'flow'. */
    ofpbuf_use_const(&pkt, pi.packet, pi.packet_len);
    flow_extract(&pkt, 0, 0, NULL, pi.fmd.in_port, &flow);
    flow.tunnel.tun_id = pi.fmd.tun_id;

    /* Choose output port. */
    out_port = lswitch_choose_destination(sw, &flow);

    /* Make actions. */
    queue_id = get_queue_id(sw, pi.fmd.in_port);
    ofpbuf_use_stack(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    if (out_port == OFPP_NONE) {
        /* No actions. */
    } else if (queue_id == UINT32_MAX || out_port >= OFPP_MAX) {
        ofpact_put_OUTPUT(&ofpacts)->port = out_port;
    } else {
        struct ofpact_enqueue *enqueue = ofpact_put_ENQUEUE(&ofpacts);
        enqueue->port = out_port;
        enqueue->queue = queue_id;
    }
    ofpact_pad(&ofpacts);

    /* Prepare packet_out in case we need one. */
    po.buffer_id = pi.buffer_id;
    if (po.buffer_id == UINT32_MAX) {
        po.packet = pkt.data;
        po.packet_len = pkt.size;
    } else {
        po.packet = NULL;
        po.packet_len = 0;
    }
    po.in_port = pi.fmd.in_port;
    po.ofpacts = ofpacts.data;
    po.ofpacts_len = ofpacts.size;

    /* Send the packet, and possibly the whole flow, to the output port. */
    if (sw->max_idle >= 0 && (!sw->ml || out_port != OFPP_FLOOD)) {
        struct ofputil_flow_mod fm;
        struct ofpbuf *buffer;

        /* The output port is known, or we always flood everything, so add a
         * new flow. */
        memset(&fm, 0, sizeof fm);
        match_init(&fm.match, &flow, &sw->wc);
        ofputil_normalize_match_quiet(&fm.match);
        fm.priority = 0;
        fm.table_id = 0xff;
        fm.command = OFPFC_ADD;
        fm.idle_timeout = sw->max_idle;
        fm.buffer_id = pi.buffer_id;
        fm.out_port = OFPP_NONE;
        fm.ofpacts = ofpacts.data;
        fm.ofpacts_len = ofpacts.size;
        buffer = ofputil_encode_flow_mod(&fm, sw->protocol);

        queue_tx(sw, buffer);

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (pi.buffer_id == UINT32_MAX && out_port != OFPP_NONE) {
            queue_tx(sw, ofputil_encode_packet_out(&po, sw->protocol));
        }
    } else {
        /* We don't know that MAC, or we don't set up flows.  Send along the
         * packet without setting up a flow. */
        if (pi.buffer_id != UINT32_MAX || out_port != OFPP_NONE) {
            queue_tx(sw, ofputil_encode_packet_out(&po, sw->protocol));
        }
    }
}

static void
process_echo_request(struct lswitch *sw, const struct ofp_header *rq)
{
    queue_tx(sw, make_echo_reply(rq));
}
