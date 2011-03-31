/* Copyright (c) 2011 Nicira Networks
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

#include <assert.h>
#include <stdlib.h>

#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "timer.h"
#include "timeval.h"
#include "unixctl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(lacp);

enum slave_status {
    LACP_CURRENT,   /* Current State.  Partner up to date. */
    LACP_EXPIRED,   /* Expired State.  Partner out of date. */
    LACP_DEFAULTED, /* Defaulted State.  No partner. */
};

struct lacp {
    struct list node;             /* Node in all_lacps list. */
    char *name;                   /* Name of this lacp object. */
    uint8_t sys_id[ETH_ADDR_LEN]; /* System ID. */
    uint16_t sys_priority;        /* System Priority. */
    bool active;                  /* Active or Passive. */

    struct hmap slaves;      /* Slaves this LACP object controls. */
    struct slave *key_slave; /* Slave whose ID will be the aggregation key. */

    bool fast;                /* Fast or Slow LACP time. */
    bool negotiated;         /* True if LACP negotiations were successful. */
    bool update;             /* True if lacp_update() needs to be called. */
};

struct slave {
    void *aux;                    /* Handle used to identify this slave. */
    struct hmap_node node;        /* Node in master's slaves map. */

    struct lacp *lacp;            /* LACP object containing this slave. */
    uint16_t port_id;             /* Port ID. */
    uint16_t port_priority;       /* Port Priority. */
    char *name;                   /* Name of this slave. */

    enum slave_status status;     /* Slave status. */
    bool attached;                /* Attached. Traffic may flow. */
    bool enabled;                 /* Enabled. Traffic is flowing. */
    struct lacp_info partner;     /* Partner information. */
    struct lacp_info ntt_actor;   /* Used to decide if we Need To Transmit. */
    struct timer tx;              /* Next message transmission timer. */
    struct timer rx;              /* Expected message receive timer. */
};

static struct list all_lacps = LIST_INITIALIZER(&all_lacps);

static void lacp_update_attached(struct lacp *);

static void slave_destroy(struct slave *);
static void slave_set_defaulted(struct slave *);
static void slave_set_expired(struct slave *);
static void slave_get_actor(struct slave *, struct lacp_info *actor);
static void slave_get_priority(struct slave *, struct lacp_info *priority);
static bool slave_may_tx(const struct slave *);
static struct slave *slave_lookup(const struct lacp *, const void *slave);
static bool info_tx_equal(struct lacp_info *, struct lacp_info *);

static void lacp_unixctl_show(struct unixctl_conn *, const char *args,
                              void *aux);

/* Initializes the lacp module. */
void
lacp_init(void)
{
    unixctl_command_register("lacp/show", lacp_unixctl_show, NULL);
}

/* Creates a LACP object. */
struct lacp *
lacp_create(void)
{
    struct lacp *lacp;

    lacp = xzalloc(sizeof *lacp);
    hmap_init(&lacp->slaves);
    list_push_back(&all_lacps, &lacp->node);
    return lacp;
}

/* Destroys 'lacp' and its slaves. Does nothing if 'lacp' is NULL. */
void
lacp_destroy(struct lacp *lacp)
{
    if (lacp) {
        struct slave *slave, *next;

        HMAP_FOR_EACH_SAFE (slave, next, node, &lacp->slaves) {
            slave_destroy(slave);
        }

        hmap_destroy(&lacp->slaves);
        list_remove(&lacp->node);
        free(lacp->name);
        free(lacp);
    }
}

/* Configures 'lacp' with the given 'name', 'sys_id', 'sys_priority', and
 * 'active' parameters. */
void
lacp_configure(struct lacp *lacp, const char *name,
               uint8_t sys_id[ETH_ADDR_LEN], uint16_t sys_priority,
               bool active, bool fast)
{
    if (!lacp->name || strcmp(name, lacp->name)) {
        free(lacp->name);
        lacp->name = xstrdup(name);
    }

    memcpy(lacp->sys_id, sys_id, ETH_ADDR_LEN);
    lacp->sys_priority = sys_priority;
    lacp->active = active;
    lacp->fast = fast;
}

/* Processes 'pdu', a parsed LACP packet received on 'slave_'.  This function
 * should be called on all packets received on 'slave_' with Ethernet Type
 * ETH_TYPE_LACP and parsable by parse_lacp_packet(). */
void
lacp_process_pdu(struct lacp *lacp, const void *slave_,
                 const struct lacp_pdu *pdu)
{
    struct slave *slave = slave_lookup(lacp, slave_);

    slave->status = LACP_CURRENT;
    timer_set_duration(&slave->rx, (lacp->fast
                                    ? LACP_FAST_TIME_RX
                                    : LACP_SLOW_TIME_RX));

    slave->ntt_actor = pdu->partner;

    /* Update our information about our partner if it's out of date.  This may
     * cause priorities to change so re-calculate attached status of all
     * slaves.  */
    if (memcmp(&slave->partner, &pdu->actor, sizeof pdu->actor)) {
        lacp->update = true;
        slave->partner = pdu->actor;
    }
}

/* Returns true if 'lacp' has successfully negotiated with its partner.  False
 * if 'lacp' is NULL. */
bool
lacp_negotiated(const struct lacp *lacp)
{
    return lacp ? lacp->negotiated : false;
}

/* Registers 'slave_' as subordinate to 'lacp'.  This should be called at least
 * once per slave in a LACP managed bond.  Should also be called whenever a
 * slave's name, port_id, or port_priority change. */
void
lacp_slave_register(struct lacp *lacp, void *slave_, const char *name,
                    uint16_t port_id, uint16_t port_priority)
{
    struct slave *slave = slave_lookup(lacp, slave_);

    if (!slave) {
        slave = xzalloc(sizeof *slave);
        slave->lacp = lacp;
        slave->aux = slave_;
        hmap_insert(&lacp->slaves, &slave->node, hash_pointer(slave_, 0));
        slave_set_defaulted(slave);

        if (!lacp->key_slave) {
            lacp->key_slave = slave;
        }
    }

    if (!slave->name || strcmp(name, slave->name)) {
        free(slave->name);
        slave->name = xstrdup(name);
    }

    if (slave->port_id != port_id || slave->port_priority != port_priority) {

        slave->port_id = port_id;
        slave->port_priority = port_priority;

        lacp->update = true;

        if (lacp->active || lacp->negotiated) {
            slave_set_expired(slave);
        }
    }
}

/* Unregisters 'slave_' with 'lacp'.  */
void
lacp_slave_unregister(struct lacp *lacp, const void *slave_)
{
    struct slave *slave = slave_lookup(lacp, slave_);

    if (slave) {
        slave_destroy(slave);
    }
}

/* Should be called regularly to indicate whether 'slave_' is enabled.  An
 * enabled slave is allowed to send and receive traffic.  Generally a slave
 * should not be enabled if its carrier is down, or lacp_slave_may_enable()
 * indicates it should not be enabled. */
void
lacp_slave_enable(struct lacp *lacp, void *slave_, bool enabled)
{
   slave_lookup(lacp, slave_)->enabled = enabled;
}

/* This function should be called whenever the carrier status of 'slave_' has
 * changed. */
void
lacp_slave_carrier_changed(const struct lacp *lacp, const void *slave_)
{
    struct slave *slave = slave_lookup(lacp, slave_);

    if (slave->status == LACP_CURRENT || slave->lacp->active) {
        slave_set_expired(slave);
    }
}

/* This function should be called before enabling 'slave_' to send or receive
 * traffic.  If it returns false, 'slave_' should not enabled.  As a
 * convenience, returns true if 'lacp' is NULL. */
bool
lacp_slave_may_enable(const struct lacp *lacp, const void *slave_)
{
    if (lacp) {
        struct slave *slave = slave_lookup(lacp, slave_);

        /* The slave may be enabled if it's attached to an aggregator and its
         * partner is synchronized.  The only exception is defaulted slaves.
         * They are not required to have synchronized partners because they
         * have no partners at all.  They will only be attached if negotiations
         * failed on all slaves in the bond. */
        return slave->attached && (slave->partner.state & LACP_STATE_SYNC
                                   || slave->status == LACP_DEFAULTED);
    } else {
        return true;
    }
}

/* This function should be called periodically to update 'lacp'. */
void
lacp_run(struct lacp *lacp, lacp_send_pdu *send_pdu)
{
    struct slave *slave;

    HMAP_FOR_EACH (slave, node, &lacp->slaves) {
        if (timer_expired(&slave->rx)) {
            if (slave->status == LACP_CURRENT) {
                slave_set_expired(slave);
            } else if (slave->status == LACP_EXPIRED) {
                slave_set_defaulted(slave);
            }
        }
    }

    if (lacp->update) {
        lacp_update_attached(lacp);
    }

    HMAP_FOR_EACH (slave, node, &lacp->slaves) {
        struct lacp_pdu pdu;
        struct lacp_info actor;

        if (!slave_may_tx(slave)) {
            continue;
        }

        slave_get_actor(slave, &actor);

        if (timer_expired(&slave->tx)
            || !info_tx_equal(&actor, &slave->ntt_actor)) {

            slave->ntt_actor = actor;
            compose_lacp_pdu(&actor, &slave->partner, &pdu);
            send_pdu(slave->aux, &pdu);

            timer_set_duration(&slave->tx,
                               (slave->partner.state & LACP_STATE_TIME
                                ? LACP_FAST_TIME_TX
                                : LACP_SLOW_TIME_TX));
        }
    }
}

/* Causes poll_block() to wake up when lacp_run() needs to be called again. */
void
lacp_wait(struct lacp *lacp)
{
    struct slave *slave;

    HMAP_FOR_EACH (slave, node, &lacp->slaves) {
        if (slave_may_tx(slave)) {
            timer_wait(&slave->tx);
        }

        if (slave->status != LACP_DEFAULTED) {
            timer_wait(&slave->rx);
        }
    }
}

/* Static Helpers. */

/* Updates the attached status of all slaves controlled b 'lacp' and sets its
 * negotiated parameter to true if any slaves are attachable. */
static void
lacp_update_attached(struct lacp *lacp)
{
    struct slave *lead, *slave;
    struct lacp_info lead_pri;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 10);

    lacp->update = false;

    lead = NULL;
    HMAP_FOR_EACH (slave, node, &lacp->slaves) {
        struct lacp_info pri;

        slave->attached = true;

        /* XXX: In the future allow users to configure the expected system ID.
         * For now just special case loopback. */
        if (eth_addr_equals(slave->partner.sys_id, slave->lacp->sys_id)) {
            VLOG_WARN_RL(&rl, "slave %s: Loopback detected. Slave is "
                         "connected to its own bond", slave->name);
            slave->attached = false;
            continue;
        }

        if (slave->status == LACP_DEFAULTED) {
            continue;
        }

        slave_get_priority(slave, &pri);

        if (!lead || memcmp(&pri, &lead_pri, sizeof pri) < 0) {
            lead = slave;
            lead_pri = pri;
        }
    }

    lacp->negotiated = lead != NULL;

    if (lead) {
        HMAP_FOR_EACH (slave, node, &lacp->slaves) {
            if (slave->status == LACP_DEFAULTED
                || lead->partner.key != slave->partner.key
                || !eth_addr_equals(lead->partner.sys_id,
                                    slave->partner.sys_id)) {
                slave->attached = false;
            }
        }
    }
}

static void
slave_destroy(struct slave *slave)
{
    if (slave) {
        struct lacp *lacp = slave->lacp;

        lacp->update = true;
        hmap_remove(&lacp->slaves, &slave->node);

        if (lacp->key_slave == slave) {
            struct hmap_node *slave_node = hmap_first(&lacp->slaves);

            if (slave_node) {
                lacp->key_slave = CONTAINER_OF(slave_node, struct slave, node);
            } else {
                lacp->key_slave = NULL;
            }
        }

        free(slave->name);
        free(slave);
    }
}

static void
slave_set_defaulted(struct slave *slave)
{
    memset(&slave->partner, 0, sizeof slave->partner);

    slave->lacp->update = true;
    slave->status = LACP_DEFAULTED;
}

static void
slave_set_expired(struct slave *slave)
{
    slave->status = LACP_EXPIRED;
    slave->partner.state |= LACP_STATE_TIME;
    slave->partner.state &= ~LACP_STATE_SYNC;
    timer_set_duration(&slave->rx, LACP_FAST_TIME_RX);
}

static void
slave_get_actor(struct slave *slave, struct lacp_info *actor)
{
    uint8_t state = 0;

    if (slave->lacp->active) {
        state |= LACP_STATE_ACT;
    }

    if (slave->lacp->fast) {
        state |= LACP_STATE_TIME;
    }

    if (slave->attached) {
        state |= LACP_STATE_SYNC;
    }

    if (slave->status == LACP_DEFAULTED) {
        state |= LACP_STATE_DEF;
    }

    if (slave->status == LACP_EXPIRED) {
        state |= LACP_STATE_EXP;
    }

    if (hmap_count(&slave->lacp->slaves) > 1) {
        state |= LACP_STATE_AGG;
    }

    if (slave->enabled) {
        state |= LACP_STATE_COL | LACP_STATE_DIST;
    }

    actor->state = state;
    actor->key = htons(slave->lacp->key_slave->port_id);
    actor->port_priority = htons(slave->port_priority);
    actor->port_id = htons(slave->port_id);
    actor->sys_priority = htons(slave->lacp->sys_priority);
    memcpy(&actor->sys_id, slave->lacp->sys_id, ETH_ADDR_LEN);
}

/* Given 'slave', populates 'priority' with data representing its LACP link
 * priority.  If two priority objects populated by this function are compared
 * using memcmp, the higher priority link will be less than the lower priority
 * link. */
static void
slave_get_priority(struct slave *slave, struct lacp_info *priority)
{
    uint16_t partner_priority, actor_priority;

    /* Choose the lacp_info of the higher priority system by comparing their
     * system priorities and mac addresses. */
    actor_priority = slave->lacp->sys_priority;
    partner_priority = ntohs(slave->partner.sys_priority);
    if (actor_priority < partner_priority) {
        slave_get_actor(slave, priority);
    } else if (partner_priority < actor_priority) {
        *priority = slave->partner;
    } else if (eth_addr_compare_3way(slave->lacp->sys_id,
                                     slave->partner.sys_id) < 0) {
        slave_get_actor(slave, priority);
    } else {
        *priority = slave->partner;
    }

    /* Key and state are not used in priority comparisons. */
    priority->key = 0;
    priority->state = 0;
}

static bool
slave_may_tx(const struct slave *slave)
{
    return slave->lacp->active || slave->status != LACP_DEFAULTED;
}

static struct slave *
slave_lookup(const struct lacp *lacp, const void *slave_)
{
    struct slave *slave;

    HMAP_FOR_EACH_IN_BUCKET (slave, node, hash_pointer(slave_, 0),
                             &lacp->slaves) {
        if (slave->aux == slave_) {
            return slave;
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
lacp_find(const char *name)
{
    struct lacp *lacp;

    LIST_FOR_EACH (lacp, node, &all_lacps) {
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
        ds_put_cstr(ds, "activity ");
    }

    if (state & LACP_STATE_TIME) {
        ds_put_cstr(ds, "timeout ");
    }

    if (state & LACP_STATE_AGG) {
        ds_put_cstr(ds, "aggregation ");
    }

    if (state & LACP_STATE_SYNC) {
        ds_put_cstr(ds, "synchronized ");
    }

    if (state & LACP_STATE_COL) {
        ds_put_cstr(ds, "collecting ");
    }

    if (state & LACP_STATE_DIST) {
        ds_put_cstr(ds, "distributing ");
    }

    if (state & LACP_STATE_DEF) {
        ds_put_cstr(ds, "defaulted ");
    }

    if (state & LACP_STATE_EXP) {
        ds_put_cstr(ds, "expired ");
    }
}

static void
lacp_unixctl_show(struct unixctl_conn *conn,
                  const char *args, void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct lacp *lacp;
    struct slave *slave;

    lacp = lacp_find(args);
    if (!lacp) {
        unixctl_command_reply(conn, 501, "no such lacp object");
        return;
    }

    ds_put_format(&ds, "lacp: %s\n", lacp->name);
    ds_put_format(&ds, "\tstatus: %s %s\n",
                  lacp->active ? "active" : "passive",
                  lacp->negotiated ? "negotiated" : "");
    ds_put_format(&ds, "\tsys_id: " ETH_ADDR_FMT "\n", ETH_ADDR_ARGS(lacp->sys_id));
    ds_put_format(&ds, "\tsys_priority: %u\n", lacp->sys_priority);
    ds_put_cstr(&ds, "\taggregation key: ");
    if (lacp->key_slave) {
        ds_put_format(&ds, "%u", lacp->key_slave->port_id);
    } else {
        ds_put_cstr(&ds, "none");
    }
    ds_put_cstr(&ds, "\n");

    HMAP_FOR_EACH (slave, node, &lacp->slaves) {
        char *status;
        struct lacp_info actor;

        slave_get_actor(slave, &actor);
        switch (slave->status) {
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
            NOT_REACHED();
        }

        ds_put_format(&ds, "\nslave: %s: %s %s %s\n", slave->name, status,
                      slave->attached ? "attached" : "detached",
                      slave->enabled ? "enabled" : "disabled");
        ds_put_format(&ds, "\tport_id: %u\n", slave->port_id);
        ds_put_format(&ds, "\tport_priority: %u\n", slave->port_priority);

        ds_put_format(&ds, "\n\tactor sys_id: " ETH_ADDR_FMT "\n",
                      ETH_ADDR_ARGS(actor.sys_id));
        ds_put_format(&ds, "\tactor sys_priority: %u\n",
                      ntohs(actor.sys_priority));
        ds_put_format(&ds, "\tactor port_id: %u\n",
                      ntohs(actor.port_id));
        ds_put_format(&ds, "\tactor port_priority: %u\n",
                      ntohs(actor.port_priority));
        ds_put_format(&ds, "\tactor key: %u\n",
                      ntohs(actor.key));
        ds_put_cstr(&ds, "\tactor state: ");
        ds_put_lacp_state(&ds, actor.state);
        ds_put_cstr(&ds, "\n\n");

        ds_put_format(&ds, "\tpartner sys_id: " ETH_ADDR_FMT "\n",
                      ETH_ADDR_ARGS(slave->partner.sys_id));
        ds_put_format(&ds, "\tpartner sys_priority: %u\n",
                      ntohs(slave->partner.sys_priority));
        ds_put_format(&ds, "\tpartner port_id: %u\n",
                      ntohs(slave->partner.port_id));
        ds_put_format(&ds, "\tpartner port_priority: %u\n",
                      ntohs(slave->partner.port_priority));
        ds_put_format(&ds, "\tpartner key: %u\n",
                      ntohs(slave->partner.key));
        ds_put_cstr(&ds, "\tpartner state: ");
        ds_put_lacp_state(&ds, slave->partner.state);
        ds_put_cstr(&ds, "\n");
    }

    unixctl_command_reply(conn, 200, ds_cstr(&ds));
    ds_destroy(&ds);
}
