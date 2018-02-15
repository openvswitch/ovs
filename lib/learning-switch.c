/*
 * Copyright (c) 2008-2017 Nicira, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

#include "byte-order.h"
#include "classifier.h"
#include "dp-packet.h"
#include "flow.h"
#include "openvswitch/hmap.h"
#include "mac-learning.h"
#include "openflow/openflow.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-connection.h"
#include "openvswitch/ofp-errors.h"
#include "openvswitch/ofp-flow.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-port.h"
#include "openvswitch/ofp-switch.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vconn.h"
#include "openvswitch/vlog.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "openvswitch/shash.h"
#include "simap.h"
#include "timeval.h"

VLOG_DEFINE_THIS_MODULE(learning_switch);

struct lswitch_port {
    struct hmap_node hmap_node; /* Hash node for port number. */
    ofp_port_t port_no;         /* OpenFlow port number. */
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
    enum ofputil_protocol usable_protocols;
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

static ofp_port_t get_mac_entry_ofp_port(const struct mac_learning *ml,
                                         const struct mac_entry *)
    OVS_REQ_RDLOCK(ml->rwlock);
static void set_mac_entry_ofp_port(struct mac_learning *ml,
                                   struct mac_entry *, ofp_port_t)
    OVS_REQ_WRLOCK(ml->rwlock);

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
    sw->usable_protocols = cfg->usable_protocols;

    sw->queued = rconn_packet_counter_create();

    return sw;
}

static void
lswitch_handshake(struct lswitch *sw)
{
    enum ofputil_protocol protocol;
    enum ofp_version version;

    send_features_request(sw);

    version = rconn_get_version(sw->rconn);
    protocol = ofputil_protocol_from_ofp_version(version);
    if (version >= OFP13_VERSION) {
        /* OpenFlow 1.3 and later by default drop packets that miss in the flow
         * table.  Set up a flow to send packets to the controller by
         * default. */
        struct ofpact_output output;
        struct ofpbuf *msg;
        int error;

        ofpact_init_OUTPUT(&output);
        output.port = OFPP_CONTROLLER;
        output.max_len = OFP_DEFAULT_MISS_SEND_LEN;

        struct ofputil_flow_mod fm = {
            .match = MATCH_CATCHALL_INITIALIZER,
            .priority = 0,
            .table_id = 0,
            .command = OFPFC_ADD,
            .buffer_id = UINT32_MAX,
            .out_port = OFPP_NONE,
            .out_group = OFPG_ANY,
            .ofpacts = &output.ofpact,
            .ofpacts_len = sizeof output,
        };

        msg = ofputil_encode_flow_mod(&fm, protocol);
        error = rconn_send(sw->rconn, msg, NULL);
        if (error) {
            VLOG_INFO_RL(&rl, "%s: failed to add default flow (%s)",
                         rconn_get_name(sw->rconn), ovs_strerror(error));
        }
    }
    if (sw->default_flows) {
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
        if (!(protocol & sw->usable_protocols)) {
            enum ofputil_protocol want = rightmost_1bit(sw->usable_protocols);
            while (!error) {
                msg = ofputil_encode_set_protocol(protocol, want, &protocol);
                if (!msg) {
                    break;
                }
                error = rconn_send(sw->rconn, msg, NULL);
            }
        }
        if (protocol & sw->usable_protocols) {
            for (i = 0; !error && i < sw->n_default_flows; i++) {
                msg = ofputil_encode_flow_mod(&sw->default_flows[i], protocol);
                error = rconn_send(sw->rconn, msg, NULL);
            }

            if (error) {
                VLOG_INFO_RL(&rl, "%s: failed to queue default flows (%s)",
                             rconn_get_name(sw->rconn), ovs_strerror(error));
            }
        } else {
            VLOG_INFO_RL(&rl, "%s: failed to set usable protocol",
                         rconn_get_name(sw->rconn));
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
        struct lswitch_port *node;

        rconn_destroy(sw->rconn);
        HMAP_FOR_EACH_POP (node, hmap_node, &sw->queue_numbers) {
            free(node);
        }
        shash_destroy(&sw->queue_names);
        mac_learning_unref(sw->ml);
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
        ovs_rwlock_wrlock(&sw->ml->rwlock);
        mac_learning_run(sw->ml);
        ovs_rwlock_unlock(&sw->ml->rwlock);
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
        ovs_rwlock_rdlock(&sw->ml->rwlock);
        mac_learning_wait(sw->ml);
        ovs_rwlock_unlock(&sw->ml->rwlock);
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

    if (type == OFPTYPE_ECHO_REQUEST) {
        process_echo_request(sw, msg->data);
    } else if (type == OFPTYPE_FEATURES_REPLY) {
        if (sw->state == S_FEATURES_REPLY) {
            if (!process_switch_features(sw, msg->data)) {
                sw->state = S_SWITCHING;
            } else {
                rconn_disconnect(sw->rconn);
            }
        }
    } else if (type == OFPTYPE_PACKET_IN) {
        process_packet_in(sw, msg->data);
    } else if (type == OFPTYPE_FLOW_REMOVED) {
        /* Nothing to do. */
    } else if (VLOG_IS_DBG_ENABLED()) {
        char *s = ofp_to_string(msg->data, msg->size, NULL, NULL, 2);
        VLOG_DBG_RL(&rl, "%016llx: OpenFlow packet ignored: %s",
                    sw->datapath_id, s);
        free(s);
    }
}

static void
send_features_request(struct lswitch *sw)
{
    struct ofpbuf *b;
    int ofp_version = rconn_get_version(sw->rconn);

    ovs_assert(ofp_version > 0 && ofp_version < 0xff);

    /* Send OFPT_FEATURES_REQUEST. */
    b = ofpraw_alloc(OFPRAW_OFPT_FEATURES_REQUEST, ofp_version, 0);
    queue_tx(sw, b);

    /* Send OFPT_SET_CONFIG. */
    struct ofputil_switch_config config = {
        .miss_send_len = OFP_DEFAULT_MISS_SEND_LEN
    };
    queue_tx(sw, ofputil_encode_set_config(&config, ofp_version));
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
                         ovs_strerror(retval));
        }
    }
}

static enum ofperr
process_switch_features(struct lswitch *sw, struct ofp_header *oh)
{
    struct ofputil_switch_features features;
    struct ofputil_phy_port port;

    struct ofpbuf b = ofpbuf_const_initializer(oh, ntohs(oh->length));
    enum ofperr error = ofputil_pull_switch_features(&b, &features);
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
                        hash_ofp_port(lp->port_no));
        }
    }
    return 0;
}

static ofp_port_t
lswitch_choose_destination(struct lswitch *sw, const struct flow *flow)
{
    ofp_port_t out_port;

    /* Learn the source MAC. */
    if (sw->ml) {
        ovs_rwlock_wrlock(&sw->ml->rwlock);
        if (mac_learning_may_learn(sw->ml, flow->dl_src, 0)) {
            struct mac_entry *mac = mac_learning_insert(sw->ml, flow->dl_src,
                                                        0);
            if (get_mac_entry_ofp_port(sw->ml, mac)
                != flow->in_port.ofp_port) {
                VLOG_DBG_RL(&rl, "%016llx: learned that "ETH_ADDR_FMT" is on "
                            "port %"PRIu32, sw->datapath_id,
                            ETH_ADDR_ARGS(flow->dl_src),
                            flow->in_port.ofp_port);

                set_mac_entry_ofp_port(sw->ml, mac, flow->in_port.ofp_port);
            }
        }
        ovs_rwlock_unlock(&sw->ml->rwlock);
    }

    /* Drop frames for reserved multicast addresses. */
    if (eth_addr_is_reserved(flow->dl_dst)) {
        return OFPP_NONE;
    }

    out_port = OFPP_FLOOD;
    if (sw->ml) {
        struct mac_entry *mac;

        ovs_rwlock_rdlock(&sw->ml->rwlock);
        mac = mac_learning_lookup(sw->ml, flow->dl_dst, 0);
        if (mac) {
            out_port = get_mac_entry_ofp_port(sw->ml, mac);
            if (out_port == flow->in_port.ofp_port) {
                /* Don't send a packet back out its input port. */
                ovs_rwlock_unlock(&sw->ml->rwlock);
                return OFPP_NONE;
            }
        }
        ovs_rwlock_unlock(&sw->ml->rwlock);
    }

    /* Check if we need to use "NORMAL" action. */
    if (sw->action_normal && out_port != OFPP_FLOOD) {
        return OFPP_NORMAL;
    }

    return out_port;
}

static uint32_t
get_queue_id(const struct lswitch *sw, ofp_port_t in_port)
{
    const struct lswitch_port *port;

    HMAP_FOR_EACH_WITH_HASH (port, hmap_node, hash_ofp_port(in_port),
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
    uint32_t buffer_id;
    uint32_t queue_id;
    ofp_port_t out_port;

    uint64_t ofpacts_stub[64 / 8];
    struct ofpbuf ofpacts;

    struct ofputil_packet_out po;
    enum ofperr error;

    struct dp_packet pkt;
    struct flow flow;

    error = ofputil_decode_packet_in(oh, true, NULL, NULL, &pi, NULL,
                                     &buffer_id, NULL);
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

    /* Extract flow data from 'pi' into 'flow'. */
    dp_packet_use_const(&pkt, pi.packet, pi.packet_len);
    flow_extract(&pkt, &flow);
    flow.in_port.ofp_port = pi.flow_metadata.flow.in_port.ofp_port;
    flow.tunnel.tun_id = pi.flow_metadata.flow.tunnel.tun_id;

    /* Choose output port. */
    out_port = lswitch_choose_destination(sw, &flow);

    /* Make actions. */
    queue_id = get_queue_id(sw, pi.flow_metadata.flow.in_port.ofp_port);
    ofpbuf_use_stack(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);
    if (out_port == OFPP_NONE) {
        /* No actions. */
    } else if (queue_id == UINT32_MAX
               || ofp_to_u16(out_port) >= ofp_to_u16(OFPP_MAX)) {
        ofpact_put_OUTPUT(&ofpacts)->port = out_port;
    } else {
        struct ofpact_enqueue *enqueue = ofpact_put_ENQUEUE(&ofpacts);
        enqueue->port = out_port;
        enqueue->queue = queue_id;
    }

    /* Prepare packet_out in case we need one. */
    po.buffer_id = buffer_id;
    if (buffer_id == UINT32_MAX) {
        po.packet = dp_packet_data(&pkt);
        po.packet_len = dp_packet_size(&pkt);
    } else {
        po.packet = NULL;
        po.packet_len = 0;
    }
    match_set_in_port(&po.flow_metadata,
                      pi.flow_metadata.flow.in_port.ofp_port);
    po.ofpacts = ofpacts.data;
    po.ofpacts_len = ofpacts.size;

    /* Send the packet, and possibly the whole flow, to the output port. */
    if (sw->max_idle >= 0 && (!sw->ml || out_port != OFPP_FLOOD)) {
        /* The output port is known, or we always flood everything, so add a
         * new flow. */
        struct ofputil_flow_mod fm = {
            .priority = 1, /* Must be > 0 because of table-miss flow entry. */
            .table_id = 0xff,
            .command = OFPFC_ADD,
            .idle_timeout = sw->max_idle,
            .buffer_id = buffer_id,
            .out_port = OFPP_NONE,
            .ofpacts = ofpacts.data,
            .ofpacts_len = ofpacts.size,
        };
        match_init(&fm.match, &flow, &sw->wc);
        ofputil_normalize_match_quiet(&fm.match);

        struct ofpbuf *buffer = ofputil_encode_flow_mod(&fm, sw->protocol);

        queue_tx(sw, buffer);

        /* If the switch didn't buffer the packet, we need to send a copy. */
        if (buffer_id == UINT32_MAX && out_port != OFPP_NONE) {
            queue_tx(sw, ofputil_encode_packet_out(&po, sw->protocol));
        }
    } else {
        /* We don't know that MAC, or we don't set up flows.  Send along the
         * packet without setting up a flow. */
        if (buffer_id != UINT32_MAX || out_port != OFPP_NONE) {
            queue_tx(sw, ofputil_encode_packet_out(&po, sw->protocol));
        }
    }
}

static void
process_echo_request(struct lswitch *sw, const struct ofp_header *rq)
{
    queue_tx(sw, ofputil_encode_echo_reply(rq));
}

static ofp_port_t
get_mac_entry_ofp_port(const struct mac_learning *ml,
                       const struct mac_entry *e)
    OVS_REQ_RDLOCK(ml->rwlock)
{
    void *port = mac_entry_get_port(ml, e);
    return (OVS_FORCE ofp_port_t) (uintptr_t) port;
}

static void
set_mac_entry_ofp_port(struct mac_learning *ml,
                       struct mac_entry *e, ofp_port_t ofp_port)
    OVS_REQ_WRLOCK(ml->rwlock)
{
    mac_entry_set_port(ml, e, (void *) (OVS_FORCE uintptr_t) ofp_port);
}
