/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

#include "flow.h"
#include "mac-learning.h"
#include "ofpbuf.h"
#include "ofp-parse.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "queue.h"
#include "rconn.h"
#include "timeval.h"
#include "vconn.h"
#include "vlog.h"
#include "xtoxll.h"

VLOG_DEFINE_THIS_MODULE(learning_switch)

struct lswitch {
    /* If nonnegative, the switch sets up flows that expire after the given
     * number of seconds (or never expire, if the value is OFP_FLOW_PERMANENT).
     * Otherwise, the switch processes every packet. */
    int max_idle;

    unsigned long long int datapath_id;
    time_t last_features_request;
    struct mac_learning *ml;    /* NULL to act as hub instead of switch. */
    uint32_t wildcards;         /* Wildcards to apply to flows. */
    bool action_normal;         /* Use OFPP_NORMAL? */
    uint32_t queue;             /* OpenFlow queue to use, or UINT32_MAX. */

    /* Number of outgoing queued packets on the rconn. */
    struct rconn_packet_counter *queued;
};

/* The log messages here could actually be useful in debugging, so keep the
 * rate limit relatively high. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

static void queue_tx(struct lswitch *, struct rconn *, struct ofpbuf *);
static void send_features_request(struct lswitch *, struct rconn *);
static void send_default_flows(struct lswitch *sw, struct rconn *rconn,
                               FILE *default_flows);

typedef void packet_handler_func(struct lswitch *, struct rconn *, void *);
static packet_handler_func process_switch_features;
static packet_handler_func process_packet_in;
static packet_handler_func process_echo_request;

/* Creates and returns a new learning switch.
 *
 * If 'learn_macs' is true, the new switch will learn the ports on which MAC
 * addresses appear.  Otherwise, the new switch will flood all packets.
 *
 * If 'max_idle' is nonnegative, the new switch will set up flows that expire
 * after the given number of seconds (or never expire, if 'max_idle' is
 * OFP_FLOW_PERMANENT).  Otherwise, the new switch will process every packet.
 *
 * The caller may provide the file stream 'default_flows' that defines
 * default flows that should be pushed when a switch connects.  Each
 * line is a flow entry in the format described for "add-flows" command
 * in the Flow Syntax section of the ovs-ofct(8) man page.  The caller
 * is responsible for closing the stream.
 *
 * 'rconn' is used to send out an OpenFlow features request. */
struct lswitch *
lswitch_create(struct rconn *rconn, bool learn_macs,
               bool exact_flows, int max_idle, bool action_normal,
               FILE *default_flows)
{
    struct lswitch *sw;

    sw = xzalloc(sizeof *sw);
    sw->max_idle = max_idle;
    sw->datapath_id = 0;
    sw->last_features_request = time_now() - 1;
    sw->ml = learn_macs ? mac_learning_create() : NULL;
    sw->action_normal = action_normal;
    if (exact_flows) {
        /* Exact match. */
        sw->wildcards = 0;
    } else {
        /* We cannot wildcard all fields.
         * We need in_port to detect moves.
         * We need both SA and DA to do learning. */
        sw->wildcards = (OFPFW_DL_TYPE | OFPFW_NW_SRC_MASK | OFPFW_NW_DST_MASK
                         | OFPFW_NW_PROTO | OFPFW_TP_SRC | OFPFW_TP_DST);
    }
    sw->queue = UINT32_MAX;
    sw->queued = rconn_packet_counter_create();
    send_features_request(sw, rconn);
    if (default_flows) {
        send_default_flows(sw, rconn, default_flows);
    }
    return sw;
}

/* Destroys 'sw'. */
void
lswitch_destroy(struct lswitch *sw)
{
    if (sw) {
        mac_learning_destroy(sw->ml);
        rconn_packet_counter_destroy(sw->queued);
        free(sw);
    }
}

/* Sets 'queue' as the OpenFlow queue used by packets and flows set up by 'sw'.
 * Specify UINT32_MAX to avoid specifying a particular queue, which is also the
 * default if this function is never called for 'sw'.  */
void
lswitch_set_queue(struct lswitch *sw, uint32_t queue)
{
    sw->queue = queue;
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
            OFPT_FLOW_REMOVED,
            sizeof(struct ofp_flow_removed),
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
                VLOG_WARN_RL(&rl, "%016llx: %s: too short (%zu bytes) for "
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
        VLOG_DBG_RL(&rl, "%016llx: OpenFlow packet ignored: %s",
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
        osc->miss_send_len = htons(OFP_DEFAULT_MISS_SEND_LEN);
        queue_tx(sw, rconn, b);

        sw->last_features_request = now;
    }
}

static void
send_default_flows(struct lswitch *sw, struct rconn *rconn,
                   FILE *default_flows)
{
    char line[1024];

    while (fgets(line, sizeof line, default_flows)) {
        struct ofpbuf *b;
        struct ofp_flow_mod *ofm;
        uint16_t priority, idle_timeout, hard_timeout;
        uint64_t cookie;
        struct ofp_match match;

        char *comment;

        /* Delete comments. */
        comment = strchr(line, '#');
        if (comment) {
            *comment = '\0';
        }

        /* Drop empty lines. */
        if (line[strspn(line, " \t\n")] == '\0') {
            continue;
        }

        /* Parse and send.  str_to_flow() will expand and reallocate the data
         * in 'buffer', so we can't keep pointers to across the str_to_flow()
         * call. */
        make_openflow(sizeof *ofm, OFPT_FLOW_MOD, &b);
        parse_ofp_str(line, &match, b,
                      NULL, NULL, &priority, &idle_timeout, &hard_timeout,
                      &cookie);
        ofm = b->data;
        ofm->match = match;
        ofm->command = htons(OFPFC_ADD);
        ofm->cookie = htonll(cookie);
        ofm->idle_timeout = htons(idle_timeout);
        ofm->hard_timeout = htons(hard_timeout);
        ofm->buffer_id = htonl(UINT32_MAX);
        ofm->priority = htons(priority);

        update_openflow_length(b);
        queue_tx(sw, rconn, b);
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
process_switch_features(struct lswitch *sw, struct rconn *rconn OVS_UNUSED,
                        void *osf_)
{
    struct ofp_switch_features *osf = osf_;

    sw->datapath_id = ntohll(osf->datapath_id);
}

static uint16_t
lswitch_choose_destination(struct lswitch *sw, const flow_t *flow)
{
    uint16_t out_port;

    /* Learn the source MAC. */
    if (sw->ml) {
        if (mac_learning_learn(sw->ml, flow->dl_src, 0, flow->in_port,
                               GRAT_ARP_LOCK_NONE)) {
            VLOG_DBG_RL(&rl, "%016llx: learned that "ETH_ADDR_FMT" is on "
                        "port %"PRIu16, sw->datapath_id,
                        ETH_ADDR_ARGS(flow->dl_src), flow->in_port);
        }
    }

    /* Drop frames for reserved multicast addresses. */
    if (eth_addr_is_reserved(flow->dl_dst)) {
        return OFPP_NONE;
    }

    out_port = OFPP_FLOOD;
    if (sw->ml) {
        int learned_port = mac_learning_lookup(sw->ml, flow->dl_dst, 0, NULL);
        if (learned_port >= 0) {
            out_port = learned_port;
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

static void
process_packet_in(struct lswitch *sw, struct rconn *rconn, void *opi_)
{
    struct ofp_packet_in *opi = opi_;
    uint16_t in_port = ntohs(opi->in_port);
    uint16_t out_port;

    struct ofp_action_header actions[2];
    size_t actions_len;

    size_t pkt_ofs, pkt_len;
    struct ofpbuf pkt;
    flow_t flow;

    /* Ignore packets sent via output to OFPP_CONTROLLER.  This library never
     * uses such an action.  You never know what experiments might be going on,
     * though, and it seems best not to interfere with them. */
    if (opi->reason != OFPR_NO_MATCH) {
        return;
    }

    /* Extract flow data from 'opi' into 'flow'. */
    pkt_ofs = offsetof(struct ofp_packet_in, data);
    pkt_len = ntohs(opi->header.length) - pkt_ofs;
    pkt.data = opi->data;
    pkt.size = pkt_len;
    flow_extract(&pkt, 0, in_port, &flow);

    /* Choose output port. */
    out_port = lswitch_choose_destination(sw, &flow);

    /* Make actions. */
    if (out_port == OFPP_NONE) {
        actions_len = 0;
    } else if (sw->queue == UINT32_MAX || out_port >= OFPP_MAX) {
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
        oae.queue_id = htonl(sw->queue);

        memcpy(actions, &oae, sizeof oae);
        actions_len = sizeof oae;
    }
    assert(actions_len <= sizeof actions);

    /* Send the packet, and possibly the whole flow, to the output port. */
    if (sw->max_idle >= 0 && (!sw->ml || out_port != OFPP_FLOOD)) {
        struct ofpbuf *buffer;
        struct ofp_flow_mod *ofm;

        /* The output port is known, or we always flood everything, so add a
         * new flow. */
        buffer = make_add_flow(&flow, ntohl(opi->buffer_id),
                               sw->max_idle, actions_len);
        ofpbuf_put(buffer, actions, actions_len);
        ofm = buffer->data;
        ofm->match.wildcards = htonl(sw->wildcards);
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
process_echo_request(struct lswitch *sw, struct rconn *rconn, void *rq_)
{
    struct ofp_header *rq = rq_;
    queue_tx(sw, rconn, make_echo_reply(rq));
}
