/* Copyright (c) 2015 Nicira, Inc.
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
#include "ofctrl.h"
#include "dirs.h"
#include "dynamic-string.h"
#include "hmap.h"
#include "match.h"
#include "ofp-actions.h"
#include "ofp-msgs.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "rconn.h"
#include "socket-util.h"

VLOG_DEFINE_THIS_MODULE(ofctrl);

/* An OpenFlow flow. */
struct ovn_flow {
    /* Key. */
    struct hmap_node hmap_node; /* In 'desired_flows' or 'installed_flows'. */
    uint8_t table_id;
    uint16_t priority;
    struct match match;

    /* Data. */
    struct ofpact *ofpacts;
    size_t ofpacts_len;
};

static uint32_t ovn_flow_hash(const struct ovn_flow *);
static struct ovn_flow *ovn_flow_lookup(struct hmap *flow_table,
                                        const struct ovn_flow *target);
static char *ovn_flow_to_string(const struct ovn_flow *);
static void ovn_flow_log(const struct ovn_flow *, const char *action);
static void ovn_flow_destroy(struct ovn_flow *);

/* OpenFlow connection to the switch. */
static struct rconn *swconn;

/* Last seen sequence number for 'swconn'.  When this differs from
 * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
static unsigned int seqno;

/* Counter for in-flight OpenFlow messages on 'swconn'.  We only send a new
 * round of flow table modifications to the switch when the counter falls to
 * zero, to avoid unbounded buffering. */
static struct rconn_packet_counter *tx_counter;

/* Flow tables.  Each holds "struct ovn_flow"s.
 *
 * 'desired_flows' is the flow table that we want the switch to have.
 * 'installed_flows' is the flow table currently installed in the switch. */
static struct hmap desired_flows;
static struct hmap installed_flows;

static void ovn_flow_table_clear(struct hmap *flow_table);
static void ovn_flow_table_destroy(struct hmap *flow_table);

static void ofctrl_update_flows(void);
static void ofctrl_recv(const struct ofpbuf *msg);

void
ofctrl_init(void)
{
    swconn = rconn_create(5, 0, DSCP_DEFAULT, 1 << OFP13_VERSION);
    tx_counter = rconn_packet_counter_create();
    hmap_init(&desired_flows);
    hmap_init(&installed_flows);
}

/* This function should be called in the main loop after anything that updates
 * the flow table (e.g. after calls to ofctrl_clear_flows() and
 * ofctrl_add_flow()). */
void
ofctrl_run(struct controller_ctx *ctx)
{
    char *target;
    target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), ctx->br_int_name);
    if (strcmp(target, rconn_get_target(swconn))) {
        rconn_connect(swconn, target, target);
    }
    free(target);

    rconn_run(swconn);

    if (!rconn_is_connected(swconn)) {
        return;
    }
    if (!rconn_packet_counter_n_packets(tx_counter)) {
        ofctrl_update_flows();
    }

    for (int i = 0; i < 50; i++) {
        struct ofpbuf *msg = rconn_recv(swconn);
        if (!msg) {
            break;
        }

        ofctrl_recv(msg);
        ofpbuf_delete(msg);
    }
}

void
ofctrl_wait(void)
{
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);
}

void
ofctrl_destroy(void)
{
    rconn_destroy(swconn);
    ovn_flow_table_destroy(&installed_flows);
    ovn_flow_table_destroy(&desired_flows);
    rconn_packet_counter_destroy(tx_counter);
}

static void
queue_msg(struct ofpbuf *msg)
{
    rconn_send(swconn, msg, tx_counter);
}

static void
ofctrl_recv(const struct ofpbuf *msg)
{
    enum ofptype type;
    struct ofpbuf b;

    b = *msg;
    if (ofptype_pull(&type, &b)) {
        return;
    }

    switch (type) {
    case OFPTYPE_ECHO_REQUEST:
        queue_msg(make_echo_reply(msg->data));
        break;

    case OFPTYPE_ECHO_REPLY:
    case OFPTYPE_PACKET_IN:
    case OFPTYPE_PORT_STATUS:
    case OFPTYPE_FLOW_REMOVED:
        /* Nothing to do. */
        break;

    case OFPTYPE_HELLO:
    case OFPTYPE_ERROR:
    case OFPTYPE_FEATURES_REQUEST:
    case OFPTYPE_FEATURES_REPLY:
    case OFPTYPE_GET_CONFIG_REQUEST:
    case OFPTYPE_GET_CONFIG_REPLY:
    case OFPTYPE_SET_CONFIG:
    case OFPTYPE_PACKET_OUT:
    case OFPTYPE_FLOW_MOD:
    case OFPTYPE_GROUP_MOD:
    case OFPTYPE_PORT_MOD:
    case OFPTYPE_TABLE_MOD:
    case OFPTYPE_BARRIER_REQUEST:
    case OFPTYPE_BARRIER_REPLY:
    case OFPTYPE_QUEUE_GET_CONFIG_REQUEST:
    case OFPTYPE_QUEUE_GET_CONFIG_REPLY:
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
    case OFPTYPE_ROLE_STATUS:
    case OFPTYPE_SET_FLOW_FORMAT:
    case OFPTYPE_FLOW_MOD_TABLE_ID:
    case OFPTYPE_SET_PACKET_IN_FORMAT:
    case OFPTYPE_FLOW_AGE:
    case OFPTYPE_SET_CONTROLLER_ID:
    case OFPTYPE_FLOW_MONITOR_STATS_REQUEST:
    case OFPTYPE_FLOW_MONITOR_STATS_REPLY:
    case OFPTYPE_FLOW_MONITOR_CANCEL:
    case OFPTYPE_FLOW_MONITOR_PAUSED:
    case OFPTYPE_FLOW_MONITOR_RESUMED:
    case OFPTYPE_GET_ASYNC_REQUEST:
    case OFPTYPE_GET_ASYNC_REPLY:
    case OFPTYPE_SET_ASYNC_CONFIG:
    case OFPTYPE_METER_MOD:
    case OFPTYPE_GROUP_STATS_REQUEST:
    case OFPTYPE_GROUP_STATS_REPLY:
    case OFPTYPE_GROUP_DESC_STATS_REQUEST:
    case OFPTYPE_GROUP_DESC_STATS_REPLY:
    case OFPTYPE_GROUP_FEATURES_STATS_REQUEST:
    case OFPTYPE_GROUP_FEATURES_STATS_REPLY:
    case OFPTYPE_METER_STATS_REQUEST:
    case OFPTYPE_METER_STATS_REPLY:
    case OFPTYPE_METER_CONFIG_STATS_REQUEST:
    case OFPTYPE_METER_CONFIG_STATS_REPLY:
    case OFPTYPE_METER_FEATURES_STATS_REQUEST:
    case OFPTYPE_METER_FEATURES_STATS_REPLY:
    case OFPTYPE_TABLE_FEATURES_STATS_REQUEST:
    case OFPTYPE_TABLE_FEATURES_STATS_REPLY:
    case OFPTYPE_BUNDLE_CONTROL:
    case OFPTYPE_BUNDLE_ADD_MESSAGE:
    default:
        /* Messages that are generally unexpected. */
        if (VLOG_IS_DBG_ENABLED()) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

            char *s = ofp_to_string(msg->data, msg->size, 2);
            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
            free(s);
        }
    }
}

/* Flow table interface to the rest of ovn-controller. */

/* Clears the table of flows desired to be in the switch.  Call this before
 * adding the desired flows (with ofctrl_add_flow()). */
void
ofctrl_clear_flows(void)
{
    ovn_flow_table_clear(&desired_flows);
}

/* Adds a flow with the specified 'match' and 'actions' to the OpenFlow table
 * numbered 'table_id' with the given 'priority'.  The caller retains ownership
 * of 'match' and 'actions'.
 *
 * This just assembles the desired flow table in memory.  Nothing is actually
 * sent to the switch until a later call to ofctrl_run(). */
void
ofctrl_add_flow(uint8_t table_id, uint16_t priority,
                const struct match *match, const struct ofpbuf *actions)
{
    struct ovn_flow *f = xmalloc(sizeof *f);
    f->table_id = table_id;
    f->priority = priority;
    f->match = *match;
    f->ofpacts = xmemdup(actions->data, actions->size);
    f->ofpacts_len = actions->size;

    if (ovn_flow_lookup(&desired_flows, f)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        if (!VLOG_DROP_INFO(&rl)) {
            char *s = ovn_flow_to_string(f);
            VLOG_INFO("dropping duplicate flow: %s", s);
            free(s);
        }

        ovn_flow_destroy(f);
        return;
    }

    hmap_insert(&desired_flows, &f->hmap_node, ovn_flow_hash(f));
}

/* ovn_flow. */

/* Returns a hash of the key in 'f'. */
static uint32_t
ovn_flow_hash(const struct ovn_flow *f)
{
    return hash_2words((f->table_id << 16) | f->priority,
                       match_hash(&f->match, 0));

}

/* Finds and returns an ovn_flow in 'flow_table' whose key is identical to
 * 'target''s key, or NULL if there is none. */
static struct ovn_flow *
ovn_flow_lookup(struct hmap *flow_table, const struct ovn_flow *target)
{
    struct ovn_flow *f;

    HMAP_FOR_EACH_WITH_HASH (f, hmap_node, target->hmap_node.hash,
                             flow_table) {
        if (f->table_id == target->table_id
            && f->priority == target->priority
            && match_equal(&f->match, &target->match)) {
            return f;
        }
    }
    return NULL;
}

static char *
ovn_flow_to_string(const struct ovn_flow *f)
{
    struct ds s = DS_EMPTY_INITIALIZER;
    ds_put_format(&s, "table_id=%"PRIu8", ", f->table_id);
    ds_put_format(&s, "priority=%"PRIu16", ", f->priority);
    match_format(&f->match, &s, OFP_DEFAULT_PRIORITY);
    ds_put_cstr(&s, ", actions=");
    ofpacts_format(f->ofpacts, f->ofpacts_len, &s);
    return ds_steal_cstr(&s);
}

static void
ovn_flow_log(const struct ovn_flow *f, const char *action)
{
    if (VLOG_IS_DBG_ENABLED()) {
        char *s = ovn_flow_to_string(f);
        VLOG_DBG("%s flow: %s", action, s);
        free(s);
    }
}

static void
ovn_flow_destroy(struct ovn_flow *f)
{
    if (f) {
        free(f->ofpacts);
        free(f);
    }
}

/* Flow tables of struct ovn_flow. */

static void
ovn_flow_table_clear(struct hmap *flow_table)
{
    struct ovn_flow *f, *next;
    HMAP_FOR_EACH_SAFE (f, next, hmap_node, flow_table) {
        hmap_remove(flow_table, &f->hmap_node);
        ovn_flow_destroy(f);
    }
}
static void
ovn_flow_table_destroy(struct hmap *flow_table)
{
    ovn_flow_table_clear(flow_table);
    hmap_destroy(flow_table);
}

/* Flow table update. */

static void
queue_flow_mod(struct ofputil_flow_mod *fm)
{
    fm->buffer_id = UINT32_MAX;
    fm->out_port = OFPP_ANY;
    fm->out_group = OFPG_ANY;
    queue_msg(ofputil_encode_flow_mod(fm, OFPUTIL_P_OF13_OXM));
}

static void
ofctrl_update_flows(void)
{
    /* If we've (re)connected, don't make any assumptions about the flows in
     * the switch: delete all of them.  (We'll immediately repopulate it
     * below.) */
    if (seqno != rconn_get_connection_seqno(swconn)) {
        seqno = rconn_get_connection_seqno(swconn);

        /* Send a flow_mod to delete all flows. */
        struct ofputil_flow_mod fm = {
            .match = MATCH_CATCHALL_INITIALIZER,
            .table_id = OFPTT_ALL,
            .command = OFPFC_DELETE,
        };
        queue_flow_mod(&fm);
        VLOG_DBG("clearing all flows");

        /* Clear installed_flows, to match the state of the switch. */
        ovn_flow_table_clear(&installed_flows);
    }

    /* Iterate through all of the installed flows.  If any of them are no
     * longer desired, delete them; if any of them should have different
     * actions, update them. */
    struct ovn_flow *i, *next;
    HMAP_FOR_EACH_SAFE (i, next, hmap_node, &installed_flows) {
        struct ovn_flow *d = ovn_flow_lookup(&desired_flows, i);
        if (!d) {
            /* Installed flow is no longer desirable.  Delete it from the
             * switch and from installed_flows. */
            struct ofputil_flow_mod fm;
            memset(&fm, 0, sizeof fm);
            fm.match = i->match;
            fm.priority = i->priority;
            fm.table_id = i->table_id;
            fm.command = OFPFC_DELETE_STRICT;
            queue_flow_mod(&fm);
            ovn_flow_log(i, "removing");

            hmap_remove(&installed_flows, &i->hmap_node);
            ovn_flow_destroy(i);
        } else {
            if (!ofpacts_equal(i->ofpacts, i->ofpacts_len,
                               d->ofpacts, d->ofpacts_len)) {
                /* Update actions in installed flow. */
                struct ofputil_flow_mod fm;
                memset(&fm, 0, sizeof fm);
                fm.match = i->match;
                fm.priority = i->priority;
                fm.table_id = i->table_id;
                fm.ofpacts = d->ofpacts;
                fm.ofpacts_len = d->ofpacts_len;
                fm.command = OFPFC_MODIFY_STRICT;
                queue_flow_mod(&fm);
                ovn_flow_log(i, "updating");

                /* Replace 'i''s actions by 'd''s. */
                free(i->ofpacts);
                i->ofpacts = d->ofpacts;
                i->ofpacts_len = d->ofpacts_len;
                d->ofpacts = NULL;
                d->ofpacts_len = 0;
            }

            hmap_remove(&desired_flows, &d->hmap_node);
            ovn_flow_destroy(d);
        }
    }

    /* The previous loop removed from desired_flows all of the flows that are
     * already installed.  Thus, any flows remaining in desired_flows need to
     * be added to the flow table. */
    struct ovn_flow *d;
    HMAP_FOR_EACH_SAFE (d, next, hmap_node, &desired_flows) {
        /* Send flow_mod to add flow. */
        struct ofputil_flow_mod fm;
        memset(&fm, 0, sizeof fm);
        fm.match = d->match;
        fm.priority = d->priority;
        fm.table_id = d->table_id;
        fm.ofpacts = d->ofpacts;
        fm.ofpacts_len = d->ofpacts_len;
        fm.command = OFPFC_ADD;
        queue_flow_mod(&fm);
        ovn_flow_log(d, "adding");

        /* Move 'd' from desired_flows to installed_flows. */
        hmap_remove(&desired_flows, &d->hmap_node);
        hmap_insert(&installed_flows, &d->hmap_node, d->hmap_node.hash);
    }
}
