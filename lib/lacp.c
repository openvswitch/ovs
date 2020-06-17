/* Copyright (c) 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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
#include "lacp.h"

#include <stdlib.h>

#include "connectivity.h"
#include "openvswitch/dynamic-string.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "dp-packet.h"
#include "ovs-atomic.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "timer.h"
#include "timeval.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(lacp);

/* Masks for lacp_info state member. */
#define LACP_STATE_ACT  0x01 /* Activity. Active or passive? */
#define LACP_STATE_TIME 0x02 /* Timeout. Short or long timeout? */
#define LACP_STATE_AGG  0x04 /* Aggregation. Is the link is bondable? */
#define LACP_STATE_SYNC 0x08 /* Synchronization. Is the link in up to date? */
#define LACP_STATE_COL  0x10 /* Collecting. Is the link receiving frames? */
#define LACP_STATE_DIST 0x20 /* Distributing. Is the link sending frames? */
#define LACP_STATE_DEF  0x40 /* Defaulted. Using default partner info? */
#define LACP_STATE_EXP  0x80 /* Expired. Using expired partner info? */

#define LACP_FAST_TIME_TX 1000  /* Fast transmission rate. */
#define LACP_SLOW_TIME_TX 30000 /* Slow transmission rate. */
#define LACP_RX_MULTIPLIER 3    /* Multiply by TX rate to get RX rate. */

#define LACP_INFO_LEN 15
OVS_PACKED(
struct lacp_info {
    ovs_be16 sys_priority;            /* System priority. */
    struct eth_addr sys_id;           /* System ID. */
    ovs_be16 key;                     /* Operational key. */
    ovs_be16 port_priority;           /* Port priority. */
    ovs_be16 port_id;                 /* Port ID. */
    uint8_t state;                    /* State mask.  See LACP_STATE macros. */
});
BUILD_ASSERT_DECL(LACP_INFO_LEN == sizeof(struct lacp_info));

#define LACP_PDU_LEN 110
struct lacp_pdu {
    uint8_t subtype;          /* Always 1. */
    uint8_t version;          /* Always 1. */

    uint8_t actor_type;       /* Always 1. */
    uint8_t actor_len;        /* Always 20. */
    struct lacp_info actor;   /* LACP actor information. */
    uint8_t z1[3];            /* Reserved.  Always 0. */

    uint8_t partner_type;     /* Always 2. */
    uint8_t partner_len;      /* Always 20. */
    struct lacp_info partner; /* LACP partner information. */
    uint8_t z2[3];            /* Reserved.  Always 0. */

    uint8_t collector_type;   /* Always 3. */
    uint8_t collector_len;    /* Always 16. */
    ovs_be16 collector_delay; /* Maximum collector delay. Set to UINT16_MAX. */
    uint8_t z3[64];           /* Combination of several fields.  Always 0. */
};
BUILD_ASSERT_DECL(LACP_PDU_LEN == sizeof(struct lacp_pdu));

/* Implementation. */

enum pdu_subtype {
    SUBTYPE_UNUSED = 0,
    SUBTYPE_LACP,       /* Link Aggregation Control Protocol. */
    SUBTYPE_MARKER,     /* Link Aggregation Marker Protocol. */
};

enum member_status {
    LACP_CURRENT,   /* Current State.  Partner up to date. */
    LACP_EXPIRED,   /* Expired State.  Partner out of date. */
    LACP_DEFAULTED, /* Defaulted State.  No partner. */
};

/* A LACP primary interface. */
struct lacp {
    struct ovs_list node;         /* Node in all_lacps list. */
    char *name;                   /* Name of this lacp object. */
    struct eth_addr sys_id;       /* System ID. */
    uint16_t sys_priority;        /* System Priority. */
    bool active;                  /* Active or Passive. */

    struct hmap members;        /* Members this LACP object controls. */
    struct member *key_member;  /* Member whose ID will be aggregation key. */

    bool fast;               /* True if using fast probe interval. */
    bool negotiated;         /* True if LACP negotiations were successful. */
    bool update;             /* True if lacp_update() needs to be called. */
    bool fallback_ab; /* True if fallback to active-backup on LACP failure. */

    struct ovs_refcount ref_cnt;
};

/* A LACP member interface. */
struct member {
    void *aux;                    /* Handle used to identify this member. */
    struct hmap_node node;        /* Node in primary's members map. */

    struct lacp *lacp;            /* LACP object containing this member. */
    uint16_t port_id;             /* Port ID. */
    uint16_t port_priority;       /* Port Priority. */
    uint16_t key;                 /* Aggregation Key. 0 if default. */
    char *name;                   /* Name of this member. */

    enum member_status status;    /* Member status. */
    bool attached;                /* Attached. Traffic may flow. */
    bool carrier_up;              /* Carrier state of link. */
    struct lacp_info partner;     /* Partner information. */
    struct lacp_info ntt_actor;   /* Used to decide if we Need To Transmit. */
    struct timer tx;              /* Next message transmission timer. */
    struct timer rx;              /* Expected message receive timer. */

    uint32_t count_rx_pdus;         /* dot3adAggPortStatsLACPDUsRx */
    uint32_t count_rx_pdus_bad;     /* dot3adAggPortStatsIllegalRx */
    uint32_t count_rx_pdus_marker;  /* dot3adAggPortStatsMarkerPDUsRx */
    uint32_t count_tx_pdus;         /* dot3adAggPortStatsLACPDUsTx */
    uint32_t count_link_expired;    /* Num of times link expired */
    uint32_t count_link_defaulted;  /* Num of times link defaulted */
    uint32_t count_carrier_changed; /* Num of times link status changed */
};

static struct ovs_mutex mutex;
static struct ovs_list all_lacps__ = OVS_LIST_INITIALIZER(&all_lacps__);
static struct ovs_list *const all_lacps OVS_GUARDED_BY(mutex) = &all_lacps__;

static void lacp_update_attached(struct lacp *) OVS_REQUIRES(mutex);

static void member_destroy(struct member *) OVS_REQUIRES(mutex);
static void member_set_defaulted(struct member *) OVS_REQUIRES(mutex);
static void member_set_expired(struct member *) OVS_REQUIRES(mutex);
static void member_get_actor(struct member *, struct lacp_info *actor)
    OVS_REQUIRES(mutex);
static void member_get_priority(struct member *, struct lacp_info *priority)
    OVS_REQUIRES(mutex);
static bool member_may_tx(const struct member *)
    OVS_REQUIRES(mutex);
static struct member *member_lookup(const struct lacp *, const void *member)
    OVS_REQUIRES(mutex);
static bool info_tx_equal(struct lacp_info *, struct lacp_info *)
    OVS_REQUIRES(mutex);
static bool member_may_enable__(struct member *) OVS_REQUIRES(mutex);

static unixctl_cb_func lacp_unixctl_show;
static unixctl_cb_func lacp_unixctl_show_stats;

/* Populates 'pdu' with a LACP PDU comprised of 'actor' and 'partner'. */
static void
compose_lacp_pdu(const struct lacp_info *actor,
                 const struct lacp_info *partner, struct lacp_pdu *pdu)
{
    memset(pdu, 0, sizeof *pdu);

    pdu->subtype = 1;
    pdu->version = 1;

    pdu->actor_type = 1;
    pdu->actor_len = 20;
    pdu->actor = *actor;

    pdu->partner_type = 2;
    pdu->partner_len = 20;
    pdu->partner = *partner;

    pdu->collector_type = 3;
    pdu->collector_len = 16;
    pdu->collector_delay = htons(0);
}

/* Parses 'p' which represents a packet containing a LACP PDU. This function
 * returns NULL if 'p' is malformed, or does not represent a LACP PDU format
 * supported by OVS.  Otherwise, it returns a pointer to the lacp_pdu contained
 * within 'p'. It also returns the subtype of PDU.*/

static const struct lacp_pdu *
parse_lacp_packet(const struct dp_packet *p, enum pdu_subtype *subtype)
{
    const struct lacp_pdu *pdu;

    pdu = dp_packet_at(p, (uint8_t *)dp_packet_l3(p) - (uint8_t *)dp_packet_data(p),
                    LACP_PDU_LEN);

    if (pdu && pdu->subtype == 1
        && pdu->actor_type == 1 && pdu->actor_len == 20
        && pdu->partner_type == 2 && pdu->partner_len == 20) {
        *subtype = SUBTYPE_LACP;
        return pdu;
    } else if (pdu && pdu->subtype == SUBTYPE_MARKER) {
        *subtype = SUBTYPE_MARKER;
        return NULL;
    } else{
        *subtype = SUBTYPE_UNUSED;
        return NULL;
    }
}

/* LACP Protocol Implementation. */

/* Initializes the lacp module. */
void
lacp_init(void)
{
    unixctl_command_register("lacp/show", "[port]", 0, 1,
                             lacp_unixctl_show, NULL);
    unixctl_command_register("lacp/show-stats", "[port]", 0, 1,
                             lacp_unixctl_show_stats, NULL);
}

static void
lacp_lock(void) OVS_ACQUIRES(mutex)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;

    if (ovsthread_once_start(&once)) {
        ovs_mutex_init_recursive(&mutex);
        ovsthread_once_done(&once);
    }
    ovs_mutex_lock(&mutex);
}

static void
lacp_unlock(void) OVS_RELEASES(mutex)
{
    ovs_mutex_unlock(&mutex);
}

/* Creates a LACP object. */
struct lacp *
lacp_create(void) OVS_EXCLUDED(mutex)
{
    struct lacp *lacp;

    lacp = xzalloc(sizeof *lacp);
    hmap_init(&lacp->members);
    ovs_refcount_init(&lacp->ref_cnt);

    lacp_lock();
    ovs_list_push_back(all_lacps, &lacp->node);
    lacp_unlock();
    return lacp;
}

struct lacp *
lacp_ref(const struct lacp *lacp_)
{
    struct lacp *lacp = CONST_CAST(struct lacp *, lacp_);
    if (lacp) {
        ovs_refcount_ref(&lacp->ref_cnt);
    }
    return lacp;
}

/* Destroys 'lacp' and its members. Does nothing if 'lacp' is NULL. */
void
lacp_unref(struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    if (lacp && ovs_refcount_unref_relaxed(&lacp->ref_cnt) == 1) {
        struct member *member, *next;

        lacp_lock();
        HMAP_FOR_EACH_SAFE (member, next, node, &lacp->members) {
            member_destroy(member);
        }

        hmap_destroy(&lacp->members);
        ovs_list_remove(&lacp->node);
        free(lacp->name);
        free(lacp);
        lacp_unlock();
    }
}

/* Configures 'lacp' with settings from 's'. */
void
lacp_configure(struct lacp *lacp, const struct lacp_settings *s)
    OVS_EXCLUDED(mutex)
{
    ovs_assert(!eth_addr_is_zero(s->id));

    lacp_lock();
    if (!lacp->name || strcmp(s->name, lacp->name)) {
        free(lacp->name);
        lacp->name = xstrdup(s->name);
    }

    if (!eth_addr_equals(lacp->sys_id, s->id)
        || lacp->sys_priority != s->priority) {
        lacp->sys_id = s->id;
        lacp->sys_priority = s->priority;
        lacp->update = true;
    }

    lacp->active = s->active;
    lacp->fast = s->fast;

    if (lacp->fallback_ab != s->fallback_ab_cfg) {
        lacp->fallback_ab = s->fallback_ab_cfg;
        lacp->update = true;
    }

    lacp_unlock();
}

/* Returns true if 'lacp' is configured in active mode, false if 'lacp' is
 * configured for passive mode. */
bool
lacp_is_active(const struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    bool ret;
    lacp_lock();
    ret = lacp->active;
    lacp_unlock();
    return ret;
}

/* Processes 'packet' which was received on 'member_'.  This function should be
 * called on all packets received on 'member_' with Ethernet Type
 * ETH_TYPE_LACP.
 */
bool
lacp_process_packet(struct lacp *lacp, const void *member_,
                    const struct dp_packet *packet)
    OVS_EXCLUDED(mutex)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const struct lacp_pdu *pdu;
    long long int tx_rate;
    struct member *member;
    bool lacp_may_enable = false;
    enum pdu_subtype subtype;

    lacp_lock();
    member = member_lookup(lacp, member_);
    if (!member) {
        goto out;
    }
    member->count_rx_pdus++;

    pdu = parse_lacp_packet(packet, &subtype);
    switch (subtype) {
        case SUBTYPE_LACP:
            break;
        case SUBTYPE_MARKER:
            member->count_rx_pdus_marker++;
            VLOG_DBG("%s: received a LACP marker PDU.", lacp->name);
            goto out;
        case SUBTYPE_UNUSED:
        default:
            member->count_rx_pdus_bad++;
            VLOG_WARN_RL(&rl, "%s: received an unparsable LACP PDU.",
                         lacp->name);
            goto out;
    }

    /* On some NICs L1 state reporting is slow. In case LACP packets are
     * received while carrier (L1) state is still down, drop the LACP PDU and
     * trigger re-checking of L1 state. */
    if (!member->carrier_up) {
        VLOG_INFO_RL(&rl, "%s: carrier state is DOWN,"
                     " dropping received LACP PDU.", member->name);
        seq_change(connectivity_seq_get());
        goto out;
    }

    member->status = LACP_CURRENT;
    tx_rate = lacp->fast ? LACP_FAST_TIME_TX : LACP_SLOW_TIME_TX;
    timer_set_duration(&member->rx, LACP_RX_MULTIPLIER * tx_rate);

    member->ntt_actor = pdu->partner;

    /* Update our information about our partner if it's out of date. This may
     * cause priorities to change so re-calculate attached status of all
     * members. */
    if (memcmp(&member->partner, &pdu->actor, sizeof pdu->actor)) {
        lacp->update = true;
        member->partner = pdu->actor;
    }

    /* Evaluate may_enable here to avoid dropping of packets till main thread
     * sets may_enable to true. */
    lacp_may_enable = member_may_enable__(member);

out:
    lacp_unlock();

    return lacp_may_enable;
}

/* Returns the lacp_status of the given 'lacp' object (which may be NULL). */
enum lacp_status
lacp_status(const struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    if (lacp) {
        enum lacp_status ret;

        lacp_lock();
        ret = lacp->negotiated ? LACP_NEGOTIATED : LACP_CONFIGURED;
        lacp_unlock();
        return ret;
    } else {
        /* Don't take 'mutex'.  It might not even be initialized, since we
         * don't know that any lacp object has been created. */
        return LACP_DISABLED;
    }
}

/* Registers 'member_' as subordinate to 'lacp'.  This should be called at
 * least once per member in a LACP managed bond.  Should also be called
 * whenever a member's settings change. */
void
lacp_member_register(struct lacp *lacp, void *member_,
                     const struct lacp_member_settings *s)
    OVS_EXCLUDED(mutex)
{
    struct member *member;

    lacp_lock();
    member = member_lookup(lacp, member_);
    if (!member) {
        member = xzalloc(sizeof *member);
        member->lacp = lacp;
        member->aux = member_;
        hmap_insert(&lacp->members, &member->node, hash_pointer(member_, 0));
        member_set_defaulted(member);

        if (!lacp->key_member) {
            lacp->key_member = member;
        }
    }

    if (!member->name || strcmp(s->name, member->name)) {
        free(member->name);
        member->name = xstrdup(s->name);
    }

    if (member->port_id != s->id
        || member->port_priority != s->priority
        || member->key != s->key) {
        member->port_id = s->id;
        member->port_priority = s->priority;
        member->key = s->key;

        lacp->update = true;

        if (lacp->active || lacp->negotiated) {
            member_set_expired(member);
        }
    }
    lacp_unlock();
}

/* Unregisters 'member_' with 'lacp'.  */
void
lacp_member_unregister(struct lacp *lacp, const void *member_)
    OVS_EXCLUDED(mutex)
{
    struct member *member;

    lacp_lock();
    member = member_lookup(lacp, member_);
    if (member) {
        member_destroy(member);
        lacp->update = true;
    }
    lacp_unlock();
}

/* This function should be called whenever the carrier status of 'member_' has
 * changed.  If 'lacp' is null, this function has no effect.*/
void
lacp_member_carrier_changed(const struct lacp *lacp, const void *member_,
                            bool carrier_up)
    OVS_EXCLUDED(mutex)
{
    struct member *member;
    if (!lacp) {
        return;
    }

    lacp_lock();
    member = member_lookup(lacp, member_);
    if (!member) {
        goto out;
    }

    if (member->status == LACP_CURRENT || member->lacp->active) {
        member_set_expired(member);
    }

    if (member->carrier_up != carrier_up) {
        member->carrier_up = carrier_up;
        member->count_carrier_changed++;
    }

out:
    lacp_unlock();
}

static bool
member_may_enable__(struct member *member) OVS_REQUIRES(mutex)
{
    /* The member may be enabled if it's attached to an aggregator and its
     * partner is synchronized.*/
    return member->attached && (member->partner.state & LACP_STATE_SYNC
            || (member->lacp && member->lacp->fallback_ab
                && member->status == LACP_DEFAULTED));
}

/* This function should be called before enabling 'member_' to send or receive
 * traffic.  If it returns false, 'member_' should not enabled.  As a
 * convenience, returns true if 'lacp' is NULL. */
bool
lacp_member_may_enable(const struct lacp *lacp, const void *member_)
    OVS_EXCLUDED(mutex)
{
    if (lacp) {
        struct member *member;
        bool ret = false;

        lacp_lock();
        member = member_lookup(lacp, member_);
        if (member) {
            /* It is only called when carrier is up. So, enable member's
             * carrier state if it is currently down. */
            if (!member->carrier_up) {
                member->carrier_up = true;
            }
            ret = member_may_enable__(member);
        }
        lacp_unlock();
        return ret;
    } else {
        return true;
    }
}

/* Returns true if partner information on 'member_' is up to date.  'member_'
 * not being current, generally indicates a connectivity problem, or a
 * misconfigured (or broken) partner. */
bool
lacp_member_is_current(const struct lacp *lacp, const void *member_)
    OVS_EXCLUDED(mutex)
{
    struct member *member;
    bool ret;

    lacp_lock();
    member = member_lookup(lacp, member_);
    ret = member ? member->status != LACP_DEFAULTED : false;
    lacp_unlock();
    return ret;
}

/* This function should be called periodically to update 'lacp'. */
void
lacp_run(struct lacp *lacp, lacp_send_pdu *send_pdu) OVS_EXCLUDED(mutex)
{
    struct member *member;

    lacp_lock();
    HMAP_FOR_EACH (member, node, &lacp->members) {
        if (timer_expired(&member->rx)) {
            enum member_status old_status = member->status;

            if (member->status == LACP_CURRENT) {
                member_set_expired(member);
                member->count_link_expired++;
            } else if (member->status == LACP_EXPIRED) {
                member_set_defaulted(member);
                member->count_link_defaulted++;
            }
            if (member->status != old_status) {
                seq_change(connectivity_seq_get());
            }
        }
    }

    if (lacp->update) {
        lacp_update_attached(lacp);
        seq_change(connectivity_seq_get());
    }

    HMAP_FOR_EACH (member, node, &lacp->members) {
        struct lacp_info actor;

        if (!member_may_tx(member)) {
            continue;
        }

        member_get_actor(member, &actor);

        if (timer_expired(&member->tx)
            || !info_tx_equal(&actor, &member->ntt_actor)) {
            long long int duration;
            struct lacp_pdu pdu;

            member->ntt_actor = actor;
            compose_lacp_pdu(&actor, &member->partner, &pdu);
            send_pdu(member->aux, &pdu, sizeof pdu);
            member->count_tx_pdus++;

            duration = (member->partner.state & LACP_STATE_TIME
                        ? LACP_FAST_TIME_TX
                        : LACP_SLOW_TIME_TX);

            timer_set_duration(&member->tx, duration);
            seq_change(connectivity_seq_get());
        }
    }
    lacp_unlock();
}

/* Causes poll_block() to wake up when lacp_run() needs to be called again. */
void
lacp_wait(struct lacp *lacp) OVS_EXCLUDED(mutex)
{
    struct member *member;

    lacp_lock();
    HMAP_FOR_EACH (member, node, &lacp->members) {
        if (member_may_tx(member)) {
            timer_wait(&member->tx);
        }

        if (member->status != LACP_DEFAULTED) {
            timer_wait(&member->rx);
        }
    }
    lacp_unlock();
}

/* Static Helpers. */

/* Updates the attached status of all members controlled by 'lacp' and sets its
 * negotiated parameter to true if any members are attachable. */
static void
lacp_update_attached(struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct member *lead, *lead_current, *member;
    struct lacp_info lead_pri;
    bool lead_enable;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 10);

    lacp->update = false;

    lead = NULL;
    lead_current = NULL;
    lead_enable = false;

    /* Check if there is a working interface.
     * Store as lead_current, if there is one. */
    HMAP_FOR_EACH (member, node, &lacp->members) {
        if (member->status == LACP_CURRENT && member->attached) {
            struct lacp_info pri;
            member_get_priority(member, &pri);
            if (!lead_current || memcmp(&pri, &lead_pri, sizeof pri) < 0) {
                lead_current = member;
                lead = lead_current;
                lead_pri = pri;
                lead_enable = true;
            }
        }
    }

    /* Find interface with highest priority. */
    HMAP_FOR_EACH (member, node, &lacp->members) {
        struct lacp_info pri;

        member->attached = false;

        /* XXX: In the future allow users to configure the expected system ID.
         * For now just special case loopback. */
        if (eth_addr_equals(member->partner.sys_id, member->lacp->sys_id)) {
            VLOG_WARN_RL(&rl, "member %s: Loopback detected. Interface is "
                         "connected to its own bond", member->name);
            continue;
        }

        if (member->status == LACP_DEFAULTED) {
            if (lacp->fallback_ab) {
                member->attached = true;
            }
            continue;
        }

        member_get_priority(member, &pri);
        bool enable = member_may_enable__(member);

        /* Check if partner MAC address is the same as on the working
         * interface. Activate member only if the MAC is the same, or
         * there is no working interface. */
        if (!lead_current || (lead_current
            && eth_addr_equals(member->partner.sys_id,
                               lead_current->partner.sys_id))) {
            member->attached = true;
        }
        if (member->attached &&
                (!lead
                 || enable > lead_enable
                 || (enable == lead_enable
                     && memcmp(&pri, &lead_pri, sizeof pri) < 0))) {
            lead = member;
            lead_enable = enable;
            lead_pri = pri;
        }
    }

    lacp->negotiated = lead != NULL;

    if (lead) {
        HMAP_FOR_EACH (member, node, &lacp->members) {
            if ((lacp->fallback_ab && member->status == LACP_DEFAULTED)
                || lead->partner.key != member->partner.key
                || !eth_addr_equals(lead->partner.sys_id,
                                    member->partner.sys_id)) {
                member->attached = false;
            }
        }
    }
}

static void
member_destroy(struct member *member) OVS_REQUIRES(mutex)
{
    if (member) {
        struct lacp *lacp = member->lacp;

        lacp->update = true;
        hmap_remove(&lacp->members, &member->node);

        if (lacp->key_member == member) {
            struct hmap_node *member_node = hmap_first(&lacp->members);

            if (member_node) {
                lacp->key_member = CONTAINER_OF(member_node, struct member,
                                                node);
            } else {
                lacp->key_member = NULL;
            }
        }

        free(member->name);
        free(member);
    }
}

static void
member_set_defaulted(struct member *member) OVS_REQUIRES(mutex)
{
    memset(&member->partner, 0, sizeof member->partner);

    member->lacp->update = true;
    member->status = LACP_DEFAULTED;
}

static void
member_set_expired(struct member *member) OVS_REQUIRES(mutex)
{
    member->status = LACP_EXPIRED;
    member->partner.state |= LACP_STATE_TIME;
    member->partner.state &= ~LACP_STATE_SYNC;

    timer_set_duration(&member->rx, LACP_RX_MULTIPLIER * LACP_FAST_TIME_TX);
}

static void
member_get_actor(struct member *member, struct lacp_info *actor)
    OVS_REQUIRES(mutex)
{
    struct lacp *lacp = member->lacp;
    uint16_t key;
    uint8_t state = 0;

    if (lacp->active) {
        state |= LACP_STATE_ACT;
    }

    if (lacp->fast) {
        state |= LACP_STATE_TIME;
    }

    if (member->attached) {
        state |= LACP_STATE_SYNC;
    }

    if (member->status == LACP_DEFAULTED) {
        state |= LACP_STATE_DEF;
    }

    if (member->status == LACP_EXPIRED) {
        state |= LACP_STATE_EXP;
    }

    if (hmap_count(&lacp->members) > 1) {
        state |= LACP_STATE_AGG;
    }

    if (member->attached || !lacp->negotiated) {
        state |= LACP_STATE_COL | LACP_STATE_DIST;
    }

    key = lacp->key_member->key;
    if (!key) {
        key = lacp->key_member->port_id;
    }

    actor->state = state;
    actor->key = htons(key);
    actor->port_priority = htons(member->port_priority);
    actor->port_id = htons(member->port_id);
    actor->sys_priority = htons(lacp->sys_priority);
    actor->sys_id = lacp->sys_id;
}

/* Given 'member', populates 'priority' with data representing its LACP link
 * priority.  If two priority objects populated by this function are compared
 * using memcmp, the higher priority link will be less than the lower priority
 * link. */
static void
member_get_priority(struct member *member, struct lacp_info *priority)
    OVS_REQUIRES(mutex)
{
    uint16_t partner_priority, actor_priority;

    /* Choose the lacp_info of the higher priority system by comparing their
     * system priorities and mac addresses. */
    actor_priority = member->lacp->sys_priority;
    partner_priority = ntohs(member->partner.sys_priority);
    if (actor_priority < partner_priority) {
        member_get_actor(member, priority);
    } else if (partner_priority < actor_priority) {
        *priority = member->partner;
    } else if (eth_addr_compare_3way(member->lacp->sys_id,
                                     member->partner.sys_id) < 0) {
        member_get_actor(member, priority);
    } else {
        *priority = member->partner;
    }

    /* Key and state are not used in priority comparisons. */
    priority->key = 0;
    priority->state = 0;
}

static bool
member_may_tx(const struct member *member) OVS_REQUIRES(mutex)
{
    /* Check for L1 state as well as LACP state. */
    return (member->carrier_up) && ((member->lacp->active) ||
            (member->status != LACP_DEFAULTED));
}

static struct member *
member_lookup(const struct lacp *lacp, const void *member_) OVS_REQUIRES(mutex)
{
    struct member *member;

    HMAP_FOR_EACH_IN_BUCKET (member, node, hash_pointer(member_, 0),
                             &lacp->members) {
        if (member->aux == member_) {
            return member;
        }
    }

    return NULL;
}

/* Two lacp_info structures are tx_equal if and only if they do not differ in
 * ways which would require a lacp_pdu transmission. */
static bool
info_tx_equal(struct lacp_info *a, struct lacp_info *b)
{

    /* LACP specification dictates that we transmit whenever the actor and
     * remote_actor differ in the following fields: Port, Port Priority,
     * System, System Priority, Aggregation Key, Activity State, Timeout State,
     * Sync State, and Aggregation State. The state flags are most likely to
     * change so are checked first. */
    return !((a->state ^ b->state) & (LACP_STATE_ACT
                                      | LACP_STATE_TIME
                                      | LACP_STATE_SYNC
                                      | LACP_STATE_AGG))
        && a->port_id == b->port_id
        && a->port_priority == b->port_priority
        && a->key == b->key
        && a->sys_priority == b->sys_priority
        && eth_addr_equals(a->sys_id, b->sys_id);
}

static struct lacp *
lacp_find(const char *name) OVS_REQUIRES(mutex)
{
    struct lacp *lacp;

    LIST_FOR_EACH (lacp, node, all_lacps) {
        if (!strcmp(lacp->name, name)) {
            return lacp;
        }
    }

    return NULL;
}

static void
ds_put_lacp_state(struct ds *ds, uint8_t state)
{
    if (state & LACP_STATE_ACT) {
        ds_put_cstr(ds, " activity");
    }

    if (state & LACP_STATE_TIME) {
        ds_put_cstr(ds, " timeout");
    }

    if (state & LACP_STATE_AGG) {
        ds_put_cstr(ds, " aggregation");
    }

    if (state & LACP_STATE_SYNC) {
        ds_put_cstr(ds, " synchronized");
    }

    if (state & LACP_STATE_COL) {
        ds_put_cstr(ds, " collecting");
    }

    if (state & LACP_STATE_DIST) {
        ds_put_cstr(ds, " distributing");
    }

    if (state & LACP_STATE_DEF) {
        ds_put_cstr(ds, " defaulted");
    }

    if (state & LACP_STATE_EXP) {
        ds_put_cstr(ds, " expired");
    }
}

static void
lacp_print_details(struct ds *ds, struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct shash member_shash = SHASH_INITIALIZER(&member_shash);
    const struct shash_node **sorted_members = NULL;

    struct member *member;
    int i;

    ds_put_format(ds, "---- %s ----\n", lacp->name);
    ds_put_format(ds, "  status: %s", lacp->active ? "active" : "passive");
    if (lacp->negotiated) {
        ds_put_cstr(ds, " negotiated");
    }
    ds_put_cstr(ds, "\n");

    ds_put_format(ds, "  sys_id: " ETH_ADDR_FMT "\n", ETH_ADDR_ARGS(lacp->sys_id));
    ds_put_format(ds, "  sys_priority: %u\n", lacp->sys_priority);
    ds_put_cstr(ds, "  aggregation key: ");
    if (lacp->key_member) {
        ds_put_format(ds, "%u", lacp->key_member->key
                                ? lacp->key_member->key
                                : lacp->key_member->port_id);
    } else {
        ds_put_cstr(ds, "none");
    }
    ds_put_cstr(ds, "\n");

    ds_put_cstr(ds, "  lacp_time: ");
    if (lacp->fast) {
        ds_put_cstr(ds, "fast\n");
    } else {
        ds_put_cstr(ds, "slow\n");
    }

    HMAP_FOR_EACH (member, node, &lacp->members) {
        shash_add(&member_shash, member->name, member);
    }
    sorted_members = shash_sort(&member_shash);

    for (i = 0; i < shash_count(&member_shash); i++) {
        char *status;
        struct lacp_info actor;

        member = sorted_members[i]->data;
        member_get_actor(member, &actor);
        switch (member->status) {
        case LACP_CURRENT:
            status = "current";
            break;
        case LACP_EXPIRED:
            status = "expired";
            break;
        case LACP_DEFAULTED:
            status = "defaulted";
            break;
        default:
            OVS_NOT_REACHED();
        }

        ds_put_format(ds, "\nmember: %s: %s %s\n", member->name, status,
                      member->attached ? "attached" : "detached");
        ds_put_format(ds, "  port_id: %u\n", member->port_id);
        ds_put_format(ds, "  port_priority: %u\n", member->port_priority);
        ds_put_format(ds, "  may_enable: %s\n", (member_may_enable__(member)
                                                 ? "true" : "false"));

        ds_put_format(ds, "\n  actor sys_id: " ETH_ADDR_FMT "\n",
                      ETH_ADDR_ARGS(actor.sys_id));
        ds_put_format(ds, "  actor sys_priority: %u\n",
                      ntohs(actor.sys_priority));
        ds_put_format(ds, "  actor port_id: %u\n",
                      ntohs(actor.port_id));
        ds_put_format(ds, "  actor port_priority: %u\n",
                      ntohs(actor.port_priority));
        ds_put_format(ds, "  actor key: %u\n",
                      ntohs(actor.key));
        ds_put_cstr(ds, "  actor state:");
        ds_put_lacp_state(ds, actor.state);
        ds_put_cstr(ds, "\n\n");

        ds_put_format(ds, "  partner sys_id: " ETH_ADDR_FMT "\n",
                      ETH_ADDR_ARGS(member->partner.sys_id));
        ds_put_format(ds, "  partner sys_priority: %u\n",
                      ntohs(member->partner.sys_priority));
        ds_put_format(ds, "  partner port_id: %u\n",
                      ntohs(member->partner.port_id));
        ds_put_format(ds, "  partner port_priority: %u\n",
                      ntohs(member->partner.port_priority));
        ds_put_format(ds, "  partner key: %u\n",
                      ntohs(member->partner.key));
        ds_put_cstr(ds, "  partner state:");
        ds_put_lacp_state(ds, member->partner.state);
        ds_put_cstr(ds, "\n");
    }

    shash_destroy(&member_shash);
    free(sorted_members);
}

static void
lacp_print_stats(struct ds *ds, struct lacp *lacp) OVS_REQUIRES(mutex)
{
    struct shash member_shash = SHASH_INITIALIZER(&member_shash);
    const struct shash_node **sorted_members = NULL;

    struct member *member;
    int i;

    ds_put_format(ds, "---- %s statistics ----\n", lacp->name);

    HMAP_FOR_EACH (member, node, &lacp->members) {
        shash_add(&member_shash, member->name, member);
    }
    sorted_members = shash_sort(&member_shash);

    for (i = 0; i < shash_count(&member_shash); i++) {
        member = sorted_members[i]->data;
        ds_put_format(ds, "\nmember: %s:\n", member->name);
        ds_put_format(ds, "  TX PDUs: %u\n", member->count_tx_pdus);
        ds_put_format(ds, "  RX PDUs: %u\n", member->count_rx_pdus);
        ds_put_format(ds, "  RX Bad PDUs: %u\n", member->count_rx_pdus_bad);
        ds_put_format(ds, "  RX Marker Request PDUs: %u\n",
                      member->count_rx_pdus_marker);
        ds_put_format(ds, "  Link Expired: %u\n",
                      member->count_link_expired);
        ds_put_format(ds, "  Link Defaulted: %u\n",
                      member->count_link_defaulted);
        ds_put_format(ds, "  Carrier Status Changed: %u\n",
                      member->count_carrier_changed);
    }

    shash_destroy(&member_shash);
    free(sorted_members);
}

static void
lacp_unixctl_show(struct unixctl_conn *conn, int argc, const char *argv[],
                  void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct lacp *lacp;

    lacp_lock();
    if (argc > 1) {
        lacp = lacp_find(argv[1]);
        if (!lacp) {
            unixctl_command_reply_error(conn, "no such lacp object");
            goto out;
        }
        lacp_print_details(&ds, lacp);
    } else {
        LIST_FOR_EACH (lacp, node, all_lacps) {
            lacp_print_details(&ds, lacp);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    lacp_unlock();
}

static void
lacp_unixctl_show_stats(struct unixctl_conn *conn,
                  int argc,
                  const char *argv[],
                  void *aux OVS_UNUSED) OVS_EXCLUDED(mutex)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct lacp *lacp;

    lacp_lock();
    if (argc > 1) {
        lacp = lacp_find(argv[1]);
        if (!lacp) {
            unixctl_command_reply_error(conn, "no such lacp object");
            goto out;
        }
        lacp_print_stats(&ds, lacp);
    } else {
        LIST_FOR_EACH (lacp, node, all_lacps) {
            lacp_print_stats(&ds, lacp);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    lacp_unlock();
}

/* Extract a snapshot of the current state and counters for a member port.
   Return false if the member is not active. */
bool
lacp_get_member_stats(const struct lacp *lacp, const void *member_,
                   struct lacp_member_stats *stats)
    OVS_EXCLUDED(mutex)
{
    struct member *member;
    struct lacp_info actor;
    bool ret;

    ovs_mutex_lock(&mutex);

    member = member_lookup(lacp, member_);
    if (member) {
        ret = true;
        member_get_actor(member, &actor);
        stats->dot3adAggPortActorSystemID = actor.sys_id;
        stats->dot3adAggPortPartnerOperSystemID = member->partner.sys_id;
        stats->dot3adAggPortAttachedAggID = (lacp->key_member->key ?
                                             lacp->key_member->key :
                                             lacp->key_member->port_id);

        /* Construct my admin-state.  Assume aggregation is configured on. */
        stats->dot3adAggPortActorAdminState = LACP_STATE_AGG;
        if (lacp->active) {
            stats->dot3adAggPortActorAdminState |= LACP_STATE_ACT;
        }
        if (lacp->fast) {
            stats->dot3adAggPortActorAdminState |= LACP_STATE_TIME;
        }
        /* XXX Not sure how to know the partner admin state. It
         * might have to be captured and remembered during the
         * negotiation phase.
         */
        stats->dot3adAggPortPartnerAdminState = 0;

        stats->dot3adAggPortActorOperState = actor.state;
        stats->dot3adAggPortPartnerOperState = member->partner.state;

        /* Read out the latest counters */
        stats->dot3adAggPortStatsLACPDUsRx = member->count_rx_pdus;
        stats->dot3adAggPortStatsIllegalRx = member->count_rx_pdus_bad;
        stats->dot3adAggPortStatsLACPDUsTx = member->count_tx_pdus;
    } else {
        ret = false;
    }
    ovs_mutex_unlock(&mutex);
    return ret;

}
