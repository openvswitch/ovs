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
#include "byte-order.h"
#include "dirs.h"
#include "hash.h"
#include "hmap.h"
#include "ofctrl.h"
#include "openflow/openflow.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "physical.h"
#include "rconn.h"
#include "socket-util.h"
#include "util.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(ofctrl);

/* An OpenFlow flow. */
struct ovn_flow {
    /* Key. */
    struct hmap_node hmap_node;
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

static ovs_be32 queue_msg(struct ofpbuf *);
static void queue_flow_mod(struct ofputil_flow_mod *);

/* OpenFlow connection to the switch. */
static struct rconn *swconn;

/* Last seen sequence number for 'swconn'.  When this differs from
 * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
static unsigned int seqno;

/* Connection state machine. */
#define STATES                                  \
    STATE(S_NEW)                                \
    STATE(S_TLV_TABLE_REQUESTED)                \
    STATE(S_TLV_TABLE_MOD_SENT)                 \
    STATE(S_CLEAR_FLOWS)                        \
    STATE(S_UPDATE_FLOWS)
enum ofctrl_state {
#define STATE(NAME) NAME,
    STATES
#undef STATE
};

/* Current state. */
static enum ofctrl_state state;

/* Transaction IDs for messages in flight to the switch. */
static ovs_be32 xid, xid2;

/* Counter for in-flight OpenFlow messages on 'swconn'.  We only send a new
 * round of flow table modifications to the switch when the counter falls to
 * zero, to avoid unbounded buffering. */
static struct rconn_packet_counter *tx_counter;

/* Flow table of "struct ovn_flow"s, that holds the flow table currently
 * installed in the switch. */
static struct hmap installed_flows;

/* MFF_* field ID for our Geneve option.  In S_TLV_TABLE_MOD_SENT, this is
 * the option we requested (we don't know whether we obtained it yet).  In
 * S_CLEAR_FLOWS or S_UPDATE_FLOWS, this is really the option we have. */
static enum mf_field_id mff_ovn_geneve;

static void ovn_flow_table_clear(struct hmap *flow_table);
static void ovn_flow_table_destroy(struct hmap *flow_table);

static void ofctrl_recv(const struct ofp_header *, enum ofptype);

void
ofctrl_init(void)
{
    swconn = rconn_create(5, 0, DSCP_DEFAULT, 1 << OFP13_VERSION);
    tx_counter = rconn_packet_counter_create();
    hmap_init(&installed_flows);
}

/* S_NEW, for a new connection.
 *
 * Sends NXT_TLV_TABLE_REQUEST and transitions to
 * S_TLV_TABLE_REQUESTED. */

static void
run_S_NEW(void)
{
    struct ofpbuf *buf = ofpraw_alloc(OFPRAW_NXT_TLV_TABLE_REQUEST,
                                      rconn_get_version(swconn), 0);
    xid = queue_msg(buf);
    state = S_TLV_TABLE_REQUESTED;
}

static void
recv_S_NEW(const struct ofp_header *oh OVS_UNUSED,
           enum ofptype type OVS_UNUSED)
{
    OVS_NOT_REACHED();
}

/* S_TLV_TABLE_REQUESTED, when NXT_TLV_TABLE_REQUEST has been sent
 * and we're waiting for a reply.
 *
 * If we receive an NXT_TLV_TABLE_REPLY:
 *
 *     - If it contains our tunnel metadata option, assign its field ID to
 *       mff_ovn_geneve and transition to S_CLEAR_FLOWS.
 *
 *     - Otherwise, if there is an unused tunnel metadata field ID, send
 *       NXT_TLV_TABLE_MOD and OFPT_BARRIER_REQUEST, and transition to
 *       S_TLV_TABLE_MOD_SENT.
 *
 *     - Otherwise, log an error, disable Geneve, and transition to
 *       S_CLEAR_FLOWS.
 *
 * If we receive an OFPT_ERROR:
 *
 *     - Log an error, disable Geneve, and transition to S_CLEAR_FLOWS. */

static void
run_S_TLV_TABLE_REQUESTED(void)
{
}

static void
recv_S_TLV_TABLE_REQUESTED(const struct ofp_header *oh, enum ofptype type)
{
    if (oh->xid != xid) {
        ofctrl_recv(oh, type);
    } else if (type == OFPTYPE_NXT_TLV_TABLE_REPLY) {
        struct ofputil_tlv_table_reply reply;
        enum ofperr error = ofputil_decode_tlv_table_reply(oh, &reply);
        if (error) {
            VLOG_ERR("failed to decode TLV table request (%s)",
                     ofperr_to_string(error));
            goto error;
        }

        const struct ofputil_tlv_map *map;
        uint64_t md_free = UINT64_MAX;
        BUILD_ASSERT(TUN_METADATA_NUM_OPTS == 64);

        LIST_FOR_EACH (map, list_node, &reply.mappings) {
            if (map->option_class == OVN_GENEVE_CLASS
                && map->option_type == OVN_GENEVE_TYPE
                && map->option_len == OVN_GENEVE_LEN) {
                if (map->index >= TUN_METADATA_NUM_OPTS) {
                    VLOG_ERR("desired Geneve tunnel option 0x%"PRIx16","
                             "%"PRIu8",%"PRIu8" already in use with "
                             "unsupported index %"PRIu16,
                             map->option_class, map->option_type,
                             map->option_len, map->index);
                    goto error;
                } else {
                    mff_ovn_geneve = MFF_TUN_METADATA0 + map->index;
                    state = S_CLEAR_FLOWS;
                    return;
                }
            }

            if (map->index < TUN_METADATA_NUM_OPTS) {
                md_free &= ~(UINT64_C(1) << map->index);
            }
        }

        VLOG_DBG("OVN Geneve option not found");
        if (!md_free) {
            VLOG_ERR("no Geneve options free for use by OVN");
            goto error;
        }

        unsigned int index = rightmost_1bit_idx(md_free);
        mff_ovn_geneve = MFF_TUN_METADATA0 + index;
        struct ofputil_tlv_map tm;
        tm.option_class = OVN_GENEVE_CLASS;
        tm.option_type = OVN_GENEVE_TYPE;
        tm.option_len = OVN_GENEVE_LEN;
        tm.index = index;

        struct ofputil_tlv_table_mod ttm;
        ttm.command = NXTTMC_ADD;
        ovs_list_init(&ttm.mappings);
        ovs_list_push_back(&ttm.mappings, &tm.list_node);

        xid = queue_msg(ofputil_encode_tlv_table_mod(OFP13_VERSION, &ttm));
        xid2 = queue_msg(ofputil_encode_barrier_request(OFP13_VERSION));
        state = S_TLV_TABLE_MOD_SENT;
    } else if (type == OFPTYPE_ERROR) {
        VLOG_ERR("switch refused to allocate Geneve option (%s)",
                 ofperr_to_string(ofperr_decode_msg(oh, NULL)));
        goto error;
    } else {
        char *s = ofp_to_string(oh, ntohs(oh->length), 1);
        VLOG_ERR("unexpected reply to TLV table request (%s)",
                 s);
        free(s);
        goto error;
    }
    return;

error:
    mff_ovn_geneve = 0;
    state = S_CLEAR_FLOWS;
}

/* S_TLV_TABLE_MOD_SENT, when NXT_TLV_TABLE_MOD and OFPT_BARRIER_REQUEST
 * have been sent and we're waiting for a reply to one or the other.
 *
 * If we receive an OFPT_ERROR:
 *
 *     - If the error is NXTTMFC_ALREADY_MAPPED or NXTTMFC_DUP_ENTRY, we
 *       raced with some other controller.  Transition to S_NEW.
 *
 *     - Otherwise, log an error, disable Geneve, and transition to
 *       S_CLEAR_FLOWS.
 *
 * If we receive OFPT_BARRIER_REPLY:
 *
 *     - Set the tunnel metadata field ID to the one that we requested.
 *       Transition to S_CLEAR_FLOWS.
 */

static void
run_S_TLV_TABLE_MOD_SENT(void)
{
}

static void
recv_S_TLV_TABLE_MOD_SENT(const struct ofp_header *oh, enum ofptype type)
{
    if (oh->xid != xid && oh->xid != xid2) {
        ofctrl_recv(oh, type);
    } else if (oh->xid == xid2 && type == OFPTYPE_BARRIER_REPLY) {
        state = S_CLEAR_FLOWS;
    } else if (oh->xid == xid && type == OFPTYPE_ERROR) {
        enum ofperr error = ofperr_decode_msg(oh, NULL);
        if (error == OFPERR_NXTTMFC_ALREADY_MAPPED ||
            error == OFPERR_NXTTMFC_DUP_ENTRY) {
            VLOG_INFO("raced with another controller adding "
                      "Geneve option (%s); trying again",
                      ofperr_to_string(error));
            state = S_NEW;
        } else {
            VLOG_ERR("error adding Geneve option (%s)",
                     ofperr_to_string(error));
            goto error;
        }
    } else {
        char *s = ofp_to_string(oh, ntohs(oh->length), 1);
        VLOG_ERR("unexpected reply to Geneve option allocation request (%s)",
                 s);
        free(s);
        goto error;
    }
    return;

error:
    state = S_CLEAR_FLOWS;
}

/* S_CLEAR_FLOWS, after we've established a Geneve metadata field ID and it's
 * time to set up some flows.
 *
 * Sends an OFPT_TABLE_MOD to clear all flows, then transitions to
 * S_UPDATE_FLOWS. */

static void
run_S_CLEAR_FLOWS(void)
{
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

    state = S_UPDATE_FLOWS;
}

static void
recv_S_CLEAR_FLOWS(const struct ofp_header *oh, enum ofptype type)
{
    ofctrl_recv(oh, type);
}

/* S_UPDATE_FLOWS, for maintaining the flow table over time.
 *
 * Compare the installed flows to the ones we want.  Send OFPT_FLOW_MOD as
 * necessary.
 *
 * This is a terminal state.  We only transition out of it if the connection
 * drops. */

static void
run_S_UPDATE_FLOWS(void)
{
    /* Nothing to do here.
     *
     * Being in this state enables ofctrl_put() to work, however. */
}

static void
recv_S_UPDATE_FLOWS(const struct ofp_header *oh, enum ofptype type)
{
    ofctrl_recv(oh, type);
}

/* Runs the OpenFlow state machine against 'br_int', which is local to the
 * hypervisor on which we are running.  Attempts to negotiate a Geneve option
 * field for class OVN_GENEVE_CLASS, type OVN_GENEVE_TYPE.  If successful,
 * returns the MFF_* field ID for the option, otherwise returns 0. */
enum mf_field_id
ofctrl_run(const struct ovsrec_bridge *br_int)
{
    if (br_int) {
        char *target;
        target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_int->name);
        if (strcmp(target, rconn_get_target(swconn))) {
            VLOG_INFO("%s: connecting to switch", target);
            rconn_connect(swconn, target, target);
        }
        free(target);
    } else {
        rconn_disconnect(swconn);
    }

    rconn_run(swconn);

    if (!rconn_is_connected(swconn)) {
        return 0;
    }
    if (seqno != rconn_get_connection_seqno(swconn)) {
        seqno = rconn_get_connection_seqno(swconn);
        state = S_NEW;
    }

    enum ofctrl_state old_state;
    do {
        old_state = state;
        switch (state) {
#define STATE(NAME) case NAME: run_##NAME(); break;
            STATES
#undef STATE
        default:
            OVS_NOT_REACHED();
        }
    } while (state != old_state);

    for (int i = 0; state == old_state && i < 50; i++) {
        struct ofpbuf *msg = rconn_recv(swconn);
        if (!msg) {
            break;
        }

        const struct ofp_header *oh = msg->data;
        enum ofptype type;
        enum ofperr error;

        error = ofptype_decode(&type, oh);
        if (!error) {
            switch (state) {
#define STATE(NAME) case NAME: recv_##NAME(oh, type); break;
                STATES
#undef STATE
            default:
                OVS_NOT_REACHED();
            }
        } else {
            char *s = ofp_to_string(oh, ntohs(oh->length), 1);
            VLOG_WARN("could not decode OpenFlow message (%s): %s",
                      ofperr_to_string(error), s);
            free(s);
        }

        ofpbuf_delete(msg);
    }

    return (state == S_CLEAR_FLOWS || state == S_UPDATE_FLOWS
            ? mff_ovn_geneve : 0);
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
    rconn_packet_counter_destroy(tx_counter);
}

static ovs_be32
queue_msg(struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid = oh->xid;
    rconn_send(swconn, msg, tx_counter);
    return xid;
}

static void
ofctrl_recv(const struct ofp_header *oh, enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(make_echo_reply(oh));
    } else if (type != OFPTYPE_ECHO_REPLY &&
               type != OFPTYPE_BARRIER_REPLY &&
               type != OFPTYPE_PACKET_IN &&
               type != OFPTYPE_PORT_STATUS &&
               type != OFPTYPE_FLOW_REMOVED) {
        if (VLOG_IS_DBG_ENABLED()) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

            char *s = ofp_to_string(oh, ntohs(oh->length), 2);
            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
            free(s);
        }
    }
}

/* Flow table interface to the rest of ovn-controller. */

/* Adds a flow to 'desired_flows' with the specified 'match' and 'actions' to
 * the OpenFlow table numbered 'table_id' with the given 'priority'.  The
 * caller retains ownership of 'match' and 'actions'.
 *
 * This just assembles the desired flow table in memory.  Nothing is actually
 * sent to the switch until a later call to ofctrl_run().
 *
 * The caller should initialize its own hmap to hold the flows. */
void
ofctrl_add_flow(struct hmap *desired_flows,
                uint8_t table_id, uint16_t priority,
                const struct match *match, const struct ofpbuf *actions)
{
    struct ovn_flow *f = xmalloc(sizeof *f);
    f->table_id = table_id;
    f->priority = priority;
    f->match = *match;
    f->ofpacts = xmemdup(actions->data, actions->size);
    f->ofpacts_len = actions->size;
    f->hmap_node.hash = ovn_flow_hash(f);

    if (ovn_flow_lookup(desired_flows, f)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 5);
        if (!VLOG_DROP_INFO(&rl)) {
            char *s = ovn_flow_to_string(f);
            VLOG_INFO("dropping duplicate flow: %s", s);
            free(s);
        }

        ovn_flow_destroy(f);
        return;
    }

    hmap_insert(desired_flows, &f->hmap_node, f->hmap_node.hash);
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
    struct ovn_flow *f;
    HMAP_FOR_EACH_POP (f, hmap_node, flow_table) {
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

/* Replaces the flow table on the switch, if possible, by the flows in
 * 'flow_table', which should have been added with ofctrl_add_flow().
 * Regardless of whether the flow table is updated, this deletes all of the
 * flows from 'flow_table' and frees them.  (The hmap itself isn't
 * destroyed.)
 *
 * This called be called be ofctrl_run() within the main loop. */
void
ofctrl_put(struct hmap *flow_table)
{
    /* The flow table can be updated if the connection to the switch is up and
     * in the correct state and not backlogged with existing flow_mods.  (Our
     * criteria for being backlogged appear very conservative, but the socket
     * between ovn-controller and OVS provides some buffering.)  Otherwise,
     * discard the flows.  A solution to either of those problems will cause us
     * to wake up and retry. */
    if (state != S_UPDATE_FLOWS
        || rconn_packet_counter_n_packets(tx_counter)) {
        ovn_flow_table_clear(flow_table);
        return;
    }

    /* Iterate through all of the installed flows.  If any of them are no
     * longer desired, delete them; if any of them should have different
     * actions, update them. */
    struct ovn_flow *i, *next;
    HMAP_FOR_EACH_SAFE (i, next, hmap_node, &installed_flows) {
        struct ovn_flow *d = ovn_flow_lookup(flow_table, i);
        if (!d) {
            /* Installed flow is no longer desirable.  Delete it from the
             * switch and from installed_flows. */
            struct ofputil_flow_mod fm = {
                .match = i->match,
                .priority = i->priority,
                .table_id = i->table_id,
                .command = OFPFC_DELETE_STRICT,
            };
            queue_flow_mod(&fm);
            ovn_flow_log(i, "removing");

            hmap_remove(&installed_flows, &i->hmap_node);
            ovn_flow_destroy(i);
        } else {
            if (!ofpacts_equal(i->ofpacts, i->ofpacts_len,
                               d->ofpacts, d->ofpacts_len)) {
                /* Update actions in installed flow. */
                struct ofputil_flow_mod fm = {
                    .match = i->match,
                    .priority = i->priority,
                    .table_id = i->table_id,
                    .ofpacts = d->ofpacts,
                    .ofpacts_len = d->ofpacts_len,
                    .command = OFPFC_MODIFY_STRICT,
                };
                queue_flow_mod(&fm);
                ovn_flow_log(i, "updating");

                /* Replace 'i''s actions by 'd''s. */
                free(i->ofpacts);
                i->ofpacts = d->ofpacts;
                i->ofpacts_len = d->ofpacts_len;
                d->ofpacts = NULL;
                d->ofpacts_len = 0;
            }

            hmap_remove(flow_table, &d->hmap_node);
            ovn_flow_destroy(d);
        }
    }

    /* The previous loop removed from 'flow_table' all of the flows that are
     * already installed.  Thus, any flows remaining in 'flow_table' need to
     * be added to the flow table. */
    struct ovn_flow *d;
    HMAP_FOR_EACH_SAFE (d, next, hmap_node, flow_table) {
        /* Send flow_mod to add flow. */
        struct ofputil_flow_mod fm = {
            .match = d->match,
            .priority = d->priority,
            .table_id = d->table_id,
            .ofpacts = d->ofpacts,
            .ofpacts_len = d->ofpacts_len,
            .command = OFPFC_ADD,
        };
        queue_flow_mod(&fm);
        ovn_flow_log(d, "adding");

        /* Move 'd' from 'flow_table' to installed_flows. */
        hmap_remove(flow_table, &d->hmap_node);
        hmap_insert(&installed_flows, &d->hmap_node, d->hmap_node.hash);
    }
}
