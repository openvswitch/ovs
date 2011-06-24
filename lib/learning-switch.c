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
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "rconn.h"
#include "shash.h"
#include "timeval.h"
#include "vconn.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(learning_switch);

struct lswitch_port {
    struct hmap_node hmap_node; /* Hash node for port number. */
    uint16_t port_no;           /* OpenFlow port number, in host byte order. */
    uint32_t queue_id;          /* OpenFlow queue number. */
};

struct lswitch {
    /* If nonnegative, the switch sets up flows that expire after the given
     * number of seconds (or never expire, if the value is OFP_FLOW_PERMANENT).
     * Otherwise, the switch processes every packet. */
    int max_idle;

    unsigned long long int datapath_id;
    time_t last_features_request;
    struct mac_learning *ml;    /* NULL to act as hub instead of switch. */
    struct flow_wildcards wc;   /* Wildcards to apply to flows. */
    bool action_normal;         /* Use OFPP_NORMAL? */

    /* Queue distribution. */
    uint32_t default_queue;     /* Default OpenFlow queue, or UINT32_MAX. */
    struct hmap queue_numbers;  /* Map from port number to lswitch_port. */
    struct shash queue_names;   /* Map from port name to lswitch_port. */

    /* Number of outgoing queued packets on the rconn. */
    struct rconn_packet_counter *queued;
};

/* The log messages here could actually be useful in debugging, so keep the
 * rate limit relatively high. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

static void queue_tx(struct lswitch *, struct rconn *, struct ofpbuf *);
static void send_features_request(struct lswitch *, struct rconn *);

static void process_switch_features(struct lswitch *,
                                    struct ofp_switch_features *);
static void process_packet_in(struct lswitch *, struct rconn *,
                              const struct ofp_packet_in *);
static void process_echo_request(struct lswitch *, struct rconn *,
                                 const struct ofp_header *);

/* Creates and returns a new learning switch whose configuration is given by
 * 'cfg'.
 *
 * 'rconn' is used to send out an OpenFlow features request. */
struct lswitch *
lswitch_create(struct rconn *rconn, const struct lswitch_config *cfg)
{
    struct lswitch *sw;

    sw = xzalloc(sizeof *sw);
    sw->max_idle = cfg->max_idle;
    sw->datapath_id = 0;
    sw->last_features_request = time_now() - 1;
    sw->ml = cfg->mode == LSW_LEARN ? mac_learning_create() : NULL;
    sw->action_normal = cfg->mode == LSW_NORMAL;

    flow_wildcards_init_exact(&sw->wc);
    if (cfg->wildcards) {
        uint32_t ofpfw;

        if (cfg->wildcards == UINT32_MAX) {
            /* Try to wildcard as many fields as possible, but we cannot
             * wildcard all fields.  We need in_port to detect moves.  We need
             * Ethernet source and dest and VLAN VID to do L2 learning. */
            ofpfw = (OFPFW_DL_TYPE | OFPFW_DL_VLAN_PCP
                     | OFPFW_NW_SRC_ALL | OFPFW_NW_DST_ALL
                     | OFPFW_NW_TOS | OFPFW_NW_PROTO
                     | OFPFW_TP_SRC | OFPFW_TP_DST);
        } else {
            ofpfw = cfg->wildcards;
        }

        ofputil_wildcard_from_openflow(ofpfw, &sw->wc);
    }

    sw->default_queue = cfg->default_queue;
    hmap_init(&sw->queue_numbers);
    shash_init(&sw->queue_names);
    if (cfg->port_queues) {
        struct shash_node *node;

        SHASH_FOR_EACH (node, cfg->port_queues) {
            struct lswitch_port *port = xmalloc(sizeof *port);
            hmap_node_nullify(&port->hmap_node);
            port->queue_id = (uintptr_t) node->data;
            shash_add(&sw->queue_names, node->name, port);
        }
    }

    sw->queued = rconn_packet_counter_create();
    send_features_request(sw, rconn);

    if (cfg->default_flows) {
        const struct ofpbuf *b;

        LIST_FOR_EACH (b, list_node, cfg->default_flows) {
            struct ofpbuf *copy = ofpbuf_clone(b);
            int error = rconn_send(rconn, copy, NULL);
            if (error) {
                VLOG_INFO_RL(&rl, "%s: failed to queue default flows (%s)",
                             rconn_get_name(rconn), strerror(error));
                ofpbuf_delete(copy);
                break;
            }
        }
    }
    
    return sw;
}

/* Destroys 'sw'. */
void
lswitch_destroy(struct lswitch *sw)
{
    if (sw) {
        struct lswitch_port *node, *next;

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
    if (sw->ml) {
        mac_learning_run(sw->ml, NULL);
    }
}

void
lswitch_wait(struct lswitch *sw)
{
    if (sw->ml) {
        mac_learning_wait(sw->ml);
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
    const struct ofp_header *oh = msg->data;
    const struct ofputil_msg_type *type;

    if (sw->datapath_id == 0
        && oh->type != OFPT_ECHO_REQUEST
        && oh->type != OFPT_FEATURES_REPLY) {
        send_features_request(sw, rconn);
        return;
    }

    ofputil_decode_msg_type(oh, &type);
    switch (ofputil_msg_type_code(type)) {
    case OFPUTIL_OFPT_ECHO_REQUEST:
        process_echo_request(sw, rconn, msg->data);
        break;

    case OFPUTIL_OFPT_FEATURES_REPLY:
        process_switch_features(sw, msg->data);
        break;

    case OFPUTIL_OFPT_PACKET_IN:
        process_packet_in(sw, rconn, msg->data);
        break;

    case OFPUTIL_OFPT_FLOW_REMOVED:
        /* Nothing to do. */
        break;

    case OFPUTIL_MSG_INVALID:
    case OFPUTIL_OFPT_HELLO:
    case OFPUTIL_OFPT_ERROR:
    case OFPUTIL_OFPT_ECHO_REPLY:
    case OFPUTIL_OFPT_FEATURES_REQUEST:
    case OFPUTIL_OFPT_GET_CONFIG_REQUEST:
    case OFPUTIL_OFPT_GET_CONFIG_REPLY:
    case OFPUTIL_OFPT_SET_CONFIG:
    case OFPUTIL_OFPT_PORT_STATUS:
    case OFPUTIL_OFPT_PACKET_OUT:
    case OFPUTIL_OFPT_FLOW_MOD:
    case OFPUTIL_OFPT_PORT_MOD:
    case OFPUTIL_OFPT_BARRIER_REQUEST:
    case OFPUTIL_OFPT_BARRIER_REPLY:
    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REQUEST:
    case OFPUTIL_OFPT_QUEUE_GET_CONFIG_REPLY:
    case OFPUTIL_OFPST_DESC_REQUEST:
    case OFPUTIL_OFPST_FLOW_REQUEST:
    case OFPUTIL_OFPST_AGGREGATE_REQUEST:
    case OFPUTIL_OFPST_TABLE_REQUEST:
    case OFPUTIL_OFPST_PORT_REQUEST:
    case OFPUTIL_OFPST_QUEUE_REQUEST:
    case OFPUTIL_OFPST_DESC_REPLY:
    case OFPUTIL_OFPST_FLOW_REPLY:
    case OFPUTIL_OFPST_QUEUE_REPLY:
    case OFPUTIL_OFPST_PORT_REPLY:
    case OFPUTIL_OFPST_TABLE_REPLY:
    case OFPUTIL_OFPST_AGGREGATE_REPLY:
    case OFPUTIL_NXT_ROLE_REQUEST:
    case OFPUTIL_NXT_ROLE_REPLY:
    case OFPUTIL_NXT_FLOW_MOD_TABLE_ID:
    case OFPUTIL_NXT_SET_FLOW_FORMAT:
    case OFPUTIL_NXT_FLOW_MOD:
    case OFPUTIL_NXT_FLOW_REMOVED:
    case OFPUTIL_NXST_FLOW_REQUEST:
    case OFPUTIL_NXST_AGGREGATE_REQUEST:
    case OFPUTIL_NXST_FLOW_REPLY:
    case OFPUTIL_NXST_AGGREGATE_REPLY:
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
        osc->miss_send_len = htons(OFP_DEFAULT_MISS_SEND_LEN);
        queue_tx(sw, rconn, b);

        sw->last_features_request = now;
    }
}

static void
queue_tx(struct lswitch *sw, struct rconn *rconn, struct ofpbuf *b)
{
    int retval = rconn_send_with_limit(rconn, b, sw->queued, 10);
    if (retval && retval != ENOTCONN) {
        if (retval == EAGAIN) {
            VLOG_INFO_RL(&rl, "%016llx: %s: tx queue overflow",
                         sw->datapath_id, rconn_get_name(rconn));
        } else {
            VLOG_WARN_RL(&rl, "%016llx: %s: send: %s",
                         sw->datapath_id, rconn_get_name(rconn),
                         strerror(retval));
        }
    }
}

static void
process_switch_features(struct lswitch *sw, struct ofp_switch_features *osf)
{
    size_t n_ports;
    size_t i;

    sw->datapath_id = ntohll(osf->datapath_id);

    n_ports = (ntohs(osf->header.length) - sizeof *osf) / sizeof *osf->ports;
    for (i = 0; i < n_ports; i++) {
        struct ofp_phy_port *opp = &osf->ports[i];
        struct lswitch_port *lp;

        opp->name[OFP_MAX_PORT_NAME_LEN - 1] = '\0';
        lp = shash_find_data(&sw->queue_names, opp->name);
        if (lp && hmap_node_is_null(&lp->hmap_node)) {
            lp->port_no = ntohs(opp->port_no);
            hmap_insert(&sw->queue_numbers, &lp->hmap_node,
                        hash_int(lp->port_no, 0));
        }
    }
}

static uint16_t
lswitch_choose_destination(struct lswitch *sw, const struct flow *flow)
{
    uint16_t out_port;

    /* Learn the source MAC. */
    if (mac_learning_may_learn(sw->ml, flow->dl_src, 0)) {
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
process_packet_in(struct lswitch *sw, struct rconn *rconn,
                  const struct ofp_packet_in *opi)
{
    uint16_t in_port = ntohs(opi->in_port);
    uint32_t queue_id;
    uint16_t out_port;

    struct ofp_action_header actions[2];
    size_t actions_len;

    size_t pkt_ofs, pkt_len;
    struct ofpbuf pkt;
    struct flow flow;

    /* Ignore packets sent via output to OFPP_CONTROLLER.  This library never
     * uses such an action.  You never know what experiments might be going on,
     * though, and it seems best not to interfere with them. */
    if (opi->reason != OFPR_NO_MATCH) {
        return;
    }

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    ofpbuf_use_const(&pkt, opi->data, pkt_len);
    flow_extract(&pkt, 0, in_port, &flow);

    /* Choose output port. */
    out_port = lswitch_choose_destination(sw, &flow);

    /* Make actions. */
    queue_id = get_queue_id(sw, in_port);
    if (out_port == OFPP_NONE) {
        actions_len = 0;
    } else if (queue_id == UINT32_MAX || out_port >= OFPP_MAX) {
        struct ofp_action_output oao;

        memset(&oao, 0, sizeof oao);
        oao.type = htons(OFPAT_OUTPUT);
        oao.len = htons(sizeof oao);
        oao.port = htons(out_port);

        memcpy(actions, &oao, sizeof oao);
        actions_len = sizeof oao;
    } else {
        struct ofp_action_enqueue oae;

        memset(&oae, 0, sizeof oae);
        oae.type = htons(OFPAT_ENQUEUE);
        oae.len = htons(sizeof oae);
        oae.port = htons(out_port);
        oae.queue_id = htonl(queue_id);

        memcpy(actions, &oae, sizeof oae);
        actions_len = sizeof oae;
    }
    assert(actions_len <= sizeof actions);

    /* Send the packet, and possibly the whole flow, to the output port. */
    if (sw->max_idle >= 0 && (!sw->ml || out_port != OFPP_FLOOD)) {
        struct ofpbuf *buffer;
        struct cls_rule rule;

        /* The output port is known, or we always flood everything, so add a
         * new flow. */
        cls_rule_init(&flow, &sw->wc, 0, &rule);
        buffer = make_add_flow(&rule, ntohl(opi->buffer_id),
                               sw->max_idle, actions_len);
        ofpbuf_put(buffer, actions, actions_len);
        queue_tx(sw, rconn, buffer);

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (ntohl(opi->buffer_id) == UINT32_MAX && actions_len > 0) {
            queue_tx(sw, rconn,
                     make_packet_out(&pkt, UINT32_MAX, in_port,
                                     actions, actions_len / sizeof *actions));
        }
    } else {
        /* We don't know that MAC, or we don't set up flows.  Send along the
         * packet without setting up a flow. */
        if (ntohl(opi->buffer_id) != UINT32_MAX || actions_len > 0) {
            queue_tx(sw, rconn,
                     make_packet_out(&pkt, ntohl(opi->buffer_id), in_port,
                                     actions, actions_len / sizeof *actions));
        }
    }
}

static void
process_echo_request(struct lswitch *sw, struct rconn *rconn,
                     const struct ofp_header *rq)
{
    queue_tx(sw, rconn, make_echo_reply(rq));
}
