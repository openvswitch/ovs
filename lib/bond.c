/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012 Nicira, Inc.
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

#include "bond.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include "coverage.h"
#include "dynamic-string.h"
#include "flow.h"
#include "hmap.h"
#include "lacp.h"
#include "list.h"
#include "netdev.h"
#include "odp-util.h"
#include "ofpbuf.h"
#include "packets.h"
#include "poll-loop.h"
#include "shash.h"
#include "tag.h"
#include "timeval.h"
#include "unixctl.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(bond);

/* Bit-mask for hashing a flow down to a bucket.
 * There are (BOND_MASK + 1) buckets. */
#define BOND_MASK 0xff

/* A hash bucket for mapping a flow to a slave.
 * "struct bond" has an array of (BOND_MASK + 1) of these. */
struct bond_entry {
    struct bond_slave *slave;   /* Assigned slave, NULL if unassigned. */
    uint64_t tx_bytes;          /* Count of bytes recently transmitted. */
    tag_type tag;               /* Tag for entry<->slave association. */
    struct list list_node;      /* In bond_slave's 'entries' list. */
};

/* A bond slave, that is, one of the links comprising a bond. */
struct bond_slave {
    struct hmap_node hmap_node; /* In struct bond's slaves hmap. */
    struct bond *bond;          /* The bond that contains this slave. */
    void *aux;                  /* Client-provided handle for this slave. */

    struct netdev *netdev;      /* Network device, owned by the client. */
    unsigned int change_seq;    /* Tracks changes in 'netdev'. */
    char *name;                 /* Name (a copy of netdev_get_name(netdev)). */

    /* Link status. */
    long long delay_expires;    /* Time after which 'enabled' may change. */
    bool enabled;               /* May be chosen for flows? */
    bool may_enable;            /* Client considers this slave bondable. */
    tag_type tag;               /* Tag associated with this slave. */

    /* Rebalancing info.  Used only by bond_rebalance(). */
    struct list bal_node;       /* In bond_rebalance()'s 'bals' list. */
    struct list entries;        /* 'struct bond_entry's assigned here. */
    uint64_t tx_bytes;          /* Sum across 'tx_bytes' of entries. */

    /* BM_STABLE specific bonding info. */
    uint32_t stb_id;            /* ID used for 'stb_slaves' ordering. */
};

/* A bond, that is, a set of network devices grouped to improve performance or
 * robustness.  */
struct bond {
    struct hmap_node hmap_node; /* In 'all_bonds' hmap. */
    char *name;                 /* Name provided by client. */

    /* Slaves. */
    struct hmap slaves;

    /* Bonding info. */
    enum bond_mode balance;     /* Balancing mode, one of BM_*. */
    struct bond_slave *active_slave;
    tag_type no_slaves_tag;     /* Tag for flows when all slaves disabled. */
    int updelay, downdelay;     /* Delay before slave goes up/down, in ms. */
    enum lacp_status lacp_status; /* Status of LACP negotiations. */
    bool bond_revalidate;       /* True if flows need revalidation. */
    uint32_t basis;             /* Basis for flow hash function. */

    /* SLB specific bonding info. */
    struct bond_entry *hash;     /* An array of (BOND_MASK + 1) elements. */
    int rebalance_interval;      /* Interval between rebalances, in ms. */
    long long int next_rebalance; /* Next rebalancing time. */
    bool send_learning_packets;

    /* BM_STABLE specific bonding info. */
    tag_type stb_tag;               /* Tag associated with this bond. */

    /* Legacy compatibility. */
    long long int next_fake_iface_update; /* LLONG_MAX if disabled. */

    /* Tag set saved for next bond_run().  This tag set is a kluge for cases
     * where we can't otherwise provide revalidation feedback to the client.
     * That's only unixctl commands now; I hope no other cases will arise. */
    struct tag_set unixctl_tags;
};

static struct hmap all_bonds = HMAP_INITIALIZER(&all_bonds);

static void bond_entry_reset(struct bond *);
static struct bond_slave *bond_slave_lookup(struct bond *, const void *slave_);
static void bond_enable_slave(struct bond_slave *, bool enable,
                              struct tag_set *);
static void bond_link_status_update(struct bond_slave *, struct tag_set *);
static void bond_choose_active_slave(struct bond *, struct tag_set *);
static unsigned int bond_hash_src(const uint8_t mac[ETH_ADDR_LEN],
                                  uint16_t vlan, uint32_t basis);
static unsigned int bond_hash_tcp(const struct flow *, uint16_t vlan,
                                  uint32_t basis);
static struct bond_entry *lookup_bond_entry(const struct bond *,
                                            const struct flow *,
                                            uint16_t vlan);
static tag_type bond_get_active_slave_tag(const struct bond *);
static struct bond_slave *choose_output_slave(const struct bond *,
                                              const struct flow *,
                                              uint16_t vlan, tag_type *tags);
static void bond_update_fake_slave_stats(struct bond *);

/* Attempts to parse 's' as the name of a bond balancing mode.  If successful,
 * stores the mode in '*balance' and returns true.  Otherwise returns false
 * without modifying '*balance'. */
bool
bond_mode_from_string(enum bond_mode *balance, const char *s)
{
    if (!strcmp(s, bond_mode_to_string(BM_TCP))) {
        *balance = BM_TCP;
    } else if (!strcmp(s, bond_mode_to_string(BM_SLB))) {
        *balance = BM_SLB;
    } else if (!strcmp(s, bond_mode_to_string(BM_STABLE))) {
        *balance = BM_STABLE;
    } else if (!strcmp(s, bond_mode_to_string(BM_AB))) {
        *balance = BM_AB;
    } else {
        return false;
    }
    return true;
}

/* Returns a string representing 'balance'. */
const char *
bond_mode_to_string(enum bond_mode balance) {
    switch (balance) {
    case BM_TCP:
        return "balance-tcp";
    case BM_SLB:
        return "balance-slb";
    case BM_STABLE:
        return "stable";
    case BM_AB:
        return "active-backup";
    }
    NOT_REACHED();
}


/* Creates and returns a new bond whose configuration is initially taken from
 * 's'.
 *
 * The caller should register each slave on the new bond by calling
 * bond_slave_register().  */
struct bond *
bond_create(const struct bond_settings *s)
{
    struct bond *bond;

    bond = xzalloc(sizeof *bond);
    hmap_init(&bond->slaves);
    bond->no_slaves_tag = tag_create_random();
    bond->stb_tag = tag_create_random();
    bond->next_fake_iface_update = LLONG_MAX;

    bond_reconfigure(bond, s);

    tag_set_init(&bond->unixctl_tags);

    return bond;
}

/* Frees 'bond'. */
void
bond_destroy(struct bond *bond)
{
    struct bond_slave *slave, *next_slave;

    if (!bond) {
        return;
    }

    hmap_remove(&all_bonds, &bond->hmap_node);

    HMAP_FOR_EACH_SAFE (slave, next_slave, hmap_node, &bond->slaves) {
        hmap_remove(&bond->slaves, &slave->hmap_node);
        /* Client owns 'slave->netdev'. */
        free(slave->name);
        free(slave);
    }
    hmap_destroy(&bond->slaves);

    free(bond->hash);
    free(bond->name);
    free(bond);
}

/* Updates 'bond''s overall configuration to 's'.
 *
 * The caller should register each slave on 'bond' by calling
 * bond_slave_register().  This is optional if none of the slaves'
 * configuration has changed.  In any case it can't hurt.
 *
 * Returns true if the configuration has changed in such a way that requires
 * flow revalidation.
 * */
bool
bond_reconfigure(struct bond *bond, const struct bond_settings *s)
{
    bool revalidate = false;

    if (!bond->name || strcmp(bond->name, s->name)) {
        if (bond->name) {
            hmap_remove(&all_bonds, &bond->hmap_node);
            free(bond->name);
        }
        bond->name = xstrdup(s->name);
        hmap_insert(&all_bonds, &bond->hmap_node, hash_string(bond->name, 0));
    }

    bond->updelay = s->up_delay;
    bond->downdelay = s->down_delay;

    if (bond->rebalance_interval != s->rebalance_interval) {
        bond->rebalance_interval = s->rebalance_interval;
        revalidate = true;
    }

    if (bond->balance != s->balance) {
        bond->balance = s->balance;
        revalidate = true;

        if (bond->balance == BM_STABLE) {
            VLOG_WARN_ONCE("Stable bond mode is deprecated and may be removed"
                           " in February 2013. Please email"
                           " dev@openvswitch.org with concerns.");
        }
    }

    if (bond->basis != s->basis) {
        bond->basis = s->basis;
        revalidate = true;
    }

    if (s->fake_iface) {
        if (bond->next_fake_iface_update == LLONG_MAX) {
            bond->next_fake_iface_update = time_msec();
        }
    } else {
        bond->next_fake_iface_update = LLONG_MAX;
    }

    if (bond->bond_revalidate) {
        revalidate = true;
        bond->bond_revalidate = false;
    }

    if (bond->balance == BM_AB || !bond->hash || revalidate) {
        bond_entry_reset(bond);
    }

    return revalidate;
}

static void
bond_slave_set_netdev__(struct bond_slave *slave, struct netdev *netdev)
{
    if (slave->netdev != netdev) {
        slave->netdev = netdev;
        slave->change_seq = 0;
    }
}

/* Registers 'slave_' as a slave of 'bond'.  The 'slave_' pointer is an
 * arbitrary client-provided pointer that uniquely identifies a slave within a
 * bond.  If 'slave_' already exists within 'bond' then this function
 * reconfigures the existing slave.
 *
 * 'stb_id' is used in BM_STABLE bonds to guarantee consistent slave choices
 * across restarts and distributed vswitch instances.  It should be unique per
 * slave, and preferably consistent across restarts and reconfigurations.
 *
 * 'netdev' must be the network device that 'slave_' represents.  It is owned
 * by the client, so the client must not close it before either unregistering
 * 'slave_' or destroying 'bond'.
 */
void
bond_slave_register(struct bond *bond, void *slave_, uint32_t stb_id,
                    struct netdev *netdev)
{
    struct bond_slave *slave = bond_slave_lookup(bond, slave_);

    if (!slave) {
        slave = xzalloc(sizeof *slave);

        hmap_insert(&bond->slaves, &slave->hmap_node, hash_pointer(slave_, 0));
        slave->bond = bond;
        slave->aux = slave_;
        slave->delay_expires = LLONG_MAX;
        slave->name = xstrdup(netdev_get_name(netdev));
        bond->bond_revalidate = true;

        slave->enabled = false;
        bond_enable_slave(slave, netdev_get_carrier(netdev), NULL);
    }

    if (slave->stb_id != stb_id) {
        slave->stb_id = stb_id;
        bond->bond_revalidate = true;
    }

    bond_slave_set_netdev__(slave, netdev);

    free(slave->name);
    slave->name = xstrdup(netdev_get_name(netdev));
}

/* Updates the network device to be used with 'slave_' to 'netdev'.
 *
 * This is useful if the caller closes and re-opens the network device
 * registered with bond_slave_register() but doesn't need to change anything
 * else. */
void
bond_slave_set_netdev(struct bond *bond, void *slave_, struct netdev *netdev)
{
    struct bond_slave *slave = bond_slave_lookup(bond, slave_);
    if (slave) {
        bond_slave_set_netdev__(slave, netdev);
    }
}

/* Unregisters 'slave_' from 'bond'.  If 'bond' does not contain such a slave
 * then this function has no effect.
 *
 * Unregistering a slave invalidates all flows. */
void
bond_slave_unregister(struct bond *bond, const void *slave_)
{
    struct bond_slave *slave = bond_slave_lookup(bond, slave_);
    bool del_active;

    if (!slave) {
        return;
    }

    bond_enable_slave(slave, false, NULL);

    del_active = bond->active_slave == slave;
    if (bond->hash) {
        struct bond_entry *e;
        for (e = bond->hash; e <= &bond->hash[BOND_MASK]; e++) {
            if (e->slave == slave) {
                e->slave = NULL;
            }
        }
    }

    free(slave->name);

    hmap_remove(&bond->slaves, &slave->hmap_node);
    /* Client owns 'slave->netdev'. */
    free(slave);

    if (del_active) {
        struct tag_set tags;

        tag_set_init(&tags);
        bond_choose_active_slave(bond, &tags);
        bond->send_learning_packets = true;
    }
}

/* Should be called on each slave in 'bond' before bond_run() to indicate
 * whether or not 'slave_' may be enabled. This function is intended to allow
 * other protocols to have some impact on bonding decisions.  For example LACP
 * or high level link monitoring protocols may decide that a given slave should
 * not be able to send traffic. */
void
bond_slave_set_may_enable(struct bond *bond, void *slave_, bool may_enable)
{
    bond_slave_lookup(bond, slave_)->may_enable = may_enable;
}

/* Performs periodic maintenance on 'bond'.  The caller must provide 'tags' to
 * allow tagged flows to be invalidated.
 *
 * The caller should check bond_should_send_learning_packets() afterward. */
void
bond_run(struct bond *bond, struct tag_set *tags, enum lacp_status lacp_status)
{
    struct bond_slave *slave;

    if (bond->lacp_status != lacp_status) {
        bond->lacp_status = lacp_status;
        bond->bond_revalidate = true;
    }

    /* Enable slaves based on link status and LACP feedback. */
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        bond_link_status_update(slave, tags);
        slave->change_seq = netdev_change_seq(slave->netdev);
    }
    if (!bond->active_slave || !bond->active_slave->enabled) {
        bond_choose_active_slave(bond, tags);
    }

    /* Update fake bond interface stats. */
    if (time_msec() >= bond->next_fake_iface_update) {
        bond_update_fake_slave_stats(bond);
        bond->next_fake_iface_update = time_msec() + 1000;
    }

    if (bond->bond_revalidate) {
        bond->bond_revalidate = false;

        bond_entry_reset(bond);
        if (bond->balance != BM_STABLE) {
            struct bond_slave *slave;

            HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
                tag_set_add(tags, slave->tag);
            }
        } else {
            tag_set_add(tags, bond->stb_tag);
        }
        tag_set_add(tags, bond->no_slaves_tag);
    }

    /* Invalidate any tags required by  */
    tag_set_union(tags, &bond->unixctl_tags);
    tag_set_init(&bond->unixctl_tags);
}

/* Causes poll_block() to wake up when 'bond' needs something to be done. */
void
bond_wait(struct bond *bond)
{
    struct bond_slave *slave;

    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        if (slave->delay_expires != LLONG_MAX) {
            poll_timer_wait_until(slave->delay_expires);
        }

        if (slave->change_seq != netdev_change_seq(slave->netdev)) {
            poll_immediate_wake();
        }
    }

    if (bond->next_fake_iface_update != LLONG_MAX) {
        poll_timer_wait_until(bond->next_fake_iface_update);
    }

    /* Ensure that any saved tags get revalidated right away. */
    if (!tag_set_is_empty(&bond->unixctl_tags)) {
        poll_immediate_wake();
    }

    /* We don't wait for bond->next_rebalance because rebalancing can only run
     * at a flow account checkpoint.  ofproto does checkpointing on its own
     * schedule and bond_rebalance() gets called afterward, so we'd just be
     * waking up for no purpose. */
}

/* MAC learning table interaction. */

static bool
may_send_learning_packets(const struct bond *bond)
{
    return bond->lacp_status == LACP_DISABLED
        && (bond->balance == BM_SLB || bond->balance == BM_AB)
        && bond->active_slave;
}

/* Returns true if 'bond' needs the client to send out packets to assist with
 * MAC learning on 'bond'.  If this function returns true, then the client
 * should iterate through its MAC learning table for the bridge on which 'bond'
 * is located.  For each MAC that has been learned on a port other than 'bond',
 * it should call bond_compose_learning_packet().
 *
 * This function will only return true if 'bond' is in SLB or active-backup
 * mode and LACP is not negotiated.  Otherwise sending learning packets isn't
 * necessary.
 *
 * Calling this function resets the state that it checks. */
bool
bond_should_send_learning_packets(struct bond *bond)
{
    bool send = bond->send_learning_packets && may_send_learning_packets(bond);
    bond->send_learning_packets = false;
    return send;
}

/* Sends a gratuitous learning packet on 'bond' from 'eth_src' on 'vlan'.
 *
 * See bond_should_send_learning_packets() for description of usage. The
 * caller should send the composed packet on the port associated with
 * port_aux and takes ownership of the returned ofpbuf. */
struct ofpbuf *
bond_compose_learning_packet(struct bond *bond,
                             const uint8_t eth_src[ETH_ADDR_LEN],
                             uint16_t vlan, void **port_aux)
{
    struct bond_slave *slave;
    struct ofpbuf *packet;
    tag_type tags = 0;
    struct flow flow;

    assert(may_send_learning_packets(bond));

    memset(&flow, 0, sizeof flow);
    memcpy(flow.dl_src, eth_src, ETH_ADDR_LEN);
    slave = choose_output_slave(bond, &flow, vlan, &tags);

    packet = ofpbuf_new(0);
    compose_rarp(packet, eth_src);
    if (vlan) {
        eth_push_vlan(packet, htons(vlan));
    }

    *port_aux = slave->aux;
    return packet;
}

/* Checks whether a packet that arrived on 'slave_' within 'bond', with an
 * Ethernet destination address of 'eth_dst', should be admitted.
 *
 * The return value is one of the following:
 *
 *    - BV_ACCEPT: Admit the packet.
 *
 *    - BV_DROP: Drop the packet.
 *
 *    - BV_DROP_IF_MOVED: Consult the MAC learning table for the packet's
 *      Ethernet source address and VLAN.  If there is none, or if the packet
 *      is on the learned port, then admit the packet.  If a different port has
 *      been learned, however, drop the packet (and do not use it for MAC
 *      learning).
 */
enum bond_verdict
bond_check_admissibility(struct bond *bond, const void *slave_,
                         const uint8_t eth_dst[ETH_ADDR_LEN], tag_type *tags)
{
    struct bond_slave *slave = bond_slave_lookup(bond, slave_);

    /* LACP bonds have very loose admissibility restrictions because we can
     * assume the remote switch is aware of the bond and will "do the right
     * thing".  However, as a precaution we drop packets on disabled slaves
     * because no correctly implemented partner switch should be sending
     * packets to them.
     *
     * If LACP is configured, but LACP negotiations have been unsuccessful, we
     * drop all incoming traffic. */
    switch (bond->lacp_status) {
    case LACP_NEGOTIATED: return slave->enabled ? BV_ACCEPT : BV_DROP;
    case LACP_CONFIGURED: return BV_DROP;
    case LACP_DISABLED: break;
    }

    /* Drop all multicast packets on inactive slaves. */
    if (eth_addr_is_multicast(eth_dst)) {
        *tags |= bond_get_active_slave_tag(bond);
        if (bond->active_slave != bond_slave_lookup(bond, slave_)) {
            return BV_DROP;
        }
    }

    switch (bond->balance) {
    case BM_AB:
        /* Drop all packets which arrive on backup slaves.  This is similar to
         * how Linux bonding handles active-backup bonds. */
        *tags |= bond_get_active_slave_tag(bond);
        if (bond->active_slave != slave) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_DBG_RL(&rl, "active-backup bond received packet on backup"
                        " slave (%s) destined for " ETH_ADDR_FMT,
                        slave->name, ETH_ADDR_ARGS(eth_dst));
            return BV_DROP;
        }
        return BV_ACCEPT;

    case BM_TCP:
        /* TCP balanced bonds require successful LACP negotiated. Based on the
         * above check, LACP is off on this bond.  Therfore, we drop all
         * incoming traffic. */
        return BV_DROP;

    case BM_SLB:
        /* Drop all packets for which we have learned a different input port,
         * because we probably sent the packet on one slave and got it back on
         * the other.  Gratuitous ARP packets are an exception to this rule:
         * the host has moved to another switch.  The exception to the
         * exception is if we locked the learning table to avoid reflections on
         * bond slaves. */
        return BV_DROP_IF_MOVED;

    case BM_STABLE:
        return BV_ACCEPT;
    }

    NOT_REACHED();
}

/* Returns the slave (registered on 'bond' by bond_slave_register()) to which
 * a packet with the given 'flow' and 'vlan' should be forwarded.  Returns
 * NULL if the packet should be dropped because no slaves are enabled.
 *
 * 'vlan' is not necessarily the same as 'flow->vlan_tci'.  First, 'vlan'
 * should be a VID only (i.e. excluding the PCP bits).  Second,
 * 'flow->vlan_tci' is the VLAN TCI that appeared on the packet (so it will be
 * nonzero only for trunk ports), whereas 'vlan' is the logical VLAN that the
 * packet belongs to (so for an access port it will be the access port's VLAN).
 *
 * Adds a tag to '*tags' that associates the flow with the returned slave.
 */
void *
bond_choose_output_slave(struct bond *bond, const struct flow *flow,
                         uint16_t vlan, tag_type *tags)
{
    struct bond_slave *slave = choose_output_slave(bond, flow, vlan, tags);
    if (slave) {
        *tags |= bond->balance == BM_STABLE ? bond->stb_tag : slave->tag;
        return slave->aux;
    } else {
        *tags |= bond->no_slaves_tag;
        return NULL;
    }
}

/* Rebalancing. */

static bool
bond_is_balanced(const struct bond *bond)
{
    return bond->rebalance_interval
        && (bond->balance == BM_SLB || bond->balance == BM_TCP);
}

/* Notifies 'bond' that 'n_bytes' bytes were sent in 'flow' within 'vlan'. */
void
bond_account(struct bond *bond, const struct flow *flow, uint16_t vlan,
             uint64_t n_bytes)
{
    if (bond_is_balanced(bond)) {
        lookup_bond_entry(bond, flow, vlan)->tx_bytes += n_bytes;
    }
}

static struct bond_slave *
bond_slave_from_bal_node(struct list *bal)
{
    return CONTAINER_OF(bal, struct bond_slave, bal_node);
}

static void
log_bals(struct bond *bond, const struct list *bals)
{
    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        const struct bond_slave *slave;

        LIST_FOR_EACH (slave, bal_node, bals) {
            if (ds.length) {
                ds_put_char(&ds, ',');
            }
            ds_put_format(&ds, " %s %"PRIu64"kB",
                          slave->name, slave->tx_bytes / 1024);

            if (!slave->enabled) {
                ds_put_cstr(&ds, " (disabled)");
            }
            if (!list_is_empty(&slave->entries)) {
                struct bond_entry *e;

                ds_put_cstr(&ds, " (");
                LIST_FOR_EACH (e, list_node, &slave->entries) {
                    if (&e->list_node != list_front(&slave->entries)) {
                        ds_put_cstr(&ds, " + ");
                    }
                    ds_put_format(&ds, "h%td: %"PRIu64"kB",
                                  e - bond->hash, e->tx_bytes / 1024);
                }
                ds_put_cstr(&ds, ")");
            }
        }
        VLOG_DBG("bond %s:%s", bond->name, ds_cstr(&ds));
        ds_destroy(&ds);
    }
}

/* Shifts 'hash' from its current slave to 'to'. */
static void
bond_shift_load(struct bond_entry *hash, struct bond_slave *to,
                struct tag_set *set)
{
    struct bond_slave *from = hash->slave;
    struct bond *bond = from->bond;
    uint64_t delta = hash->tx_bytes;

    VLOG_INFO("bond %s: shift %"PRIu64"kB of load (with hash %td) "
              "from %s to %s (now carrying %"PRIu64"kB and "
              "%"PRIu64"kB load, respectively)",
              bond->name, delta / 1024, hash - bond->hash,
              from->name, to->name,
              (from->tx_bytes - delta) / 1024,
              (to->tx_bytes + delta) / 1024);

    /* Shift load away from 'from' to 'to'. */
    from->tx_bytes -= delta;
    to->tx_bytes += delta;

    /* Arrange for flows to be revalidated. */
    tag_set_add(set, hash->tag);
    hash->slave = to;
    hash->tag = tag_create_random();
}

/* Pick and returns a bond_entry to migrate to 'to' (the least-loaded slave),
 * given that doing so must decrease the ratio of the load on the two slaves by
 * at least 0.1.  Returns NULL if there is no appropriate entry.
 *
 * The list of entries isn't sorted.  I don't know of a reason to prefer to
 * shift away small hashes or large hashes. */
static struct bond_entry *
choose_entry_to_migrate(const struct bond_slave *from, uint64_t to_tx_bytes)
{
    struct bond_entry *e;

    if (list_is_short(&from->entries)) {
        /* 'from' carries no more than one MAC hash, so shifting load away from
         * it would be pointless. */
        return NULL;
    }

    LIST_FOR_EACH (e, list_node, &from->entries) {
        double old_ratio, new_ratio;
        uint64_t delta;

        if (to_tx_bytes == 0) {
            /* Nothing on the new slave, move it. */
            return e;
        }

        delta = e->tx_bytes;
        old_ratio = (double)from->tx_bytes / to_tx_bytes;
        new_ratio = (double)(from->tx_bytes - delta) / (to_tx_bytes + delta);
        if (old_ratio - new_ratio > 0.1) {
            /* Would decrease the ratio, move it. */
            return e;
        }
    }

    return NULL;
}

/* Inserts 'slave' into 'bals' so that descending order of 'tx_bytes' is
 * maintained. */
static void
insert_bal(struct list *bals, struct bond_slave *slave)
{
    struct bond_slave *pos;

    LIST_FOR_EACH (pos, bal_node, bals) {
        if (slave->tx_bytes > pos->tx_bytes) {
            break;
        }
    }
    list_insert(&pos->bal_node, &slave->bal_node);
}

/* Removes 'slave' from its current list and then inserts it into 'bals' so
 * that descending order of 'tx_bytes' is maintained. */
static void
reinsert_bal(struct list *bals, struct bond_slave *slave)
{
    list_remove(&slave->bal_node);
    insert_bal(bals, slave);
}

/* If 'bond' needs rebalancing, does so.
 *
 * The caller should have called bond_account() for each active flow, to ensure
 * that flow data is consistently accounted at this point. */
void
bond_rebalance(struct bond *bond, struct tag_set *tags)
{
    struct bond_slave *slave;
    struct bond_entry *e;
    struct list bals;

    if (!bond_is_balanced(bond) || time_msec() < bond->next_rebalance) {
        return;
    }
    bond->next_rebalance = time_msec() + bond->rebalance_interval;

    /* Add each bond_entry to its slave's 'entries' list.
     * Compute each slave's tx_bytes as the sum of its entries' tx_bytes. */
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        slave->tx_bytes = 0;
        list_init(&slave->entries);
    }
    for (e = &bond->hash[0]; e <= &bond->hash[BOND_MASK]; e++) {
        if (e->slave && e->tx_bytes) {
            e->slave->tx_bytes += e->tx_bytes;
            list_push_back(&e->slave->entries, &e->list_node);
        }
    }

    /* Add enabled slaves to 'bals' in descending order of tx_bytes.
     *
     * XXX This is O(n**2) in the number of slaves but it could be O(n lg n)
     * with a proper list sort algorithm. */
    list_init(&bals);
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        if (slave->enabled) {
            insert_bal(&bals, slave);
        }
    }
    log_bals(bond, &bals);

    /* Shift load from the most-loaded slaves to the least-loaded slaves. */
    while (!list_is_short(&bals)) {
        struct bond_slave *from = bond_slave_from_bal_node(list_front(&bals));
        struct bond_slave *to = bond_slave_from_bal_node(list_back(&bals));
        uint64_t overload;

        overload = from->tx_bytes - to->tx_bytes;
        if (overload < to->tx_bytes >> 5 || overload < 100000) {
            /* The extra load on 'from' (and all less-loaded slaves), compared
             * to that of 'to' (the least-loaded slave), is less than ~3%, or
             * it is less than ~1Mbps.  No point in rebalancing. */
            break;
        }

        /* 'from' is carrying significantly more load than 'to', and that load
         * is split across at least two different hashes. */
        e = choose_entry_to_migrate(from, to->tx_bytes);
        if (e) {
            bond_shift_load(e, to, tags);

            /* Delete element from from->entries.
             *
             * We don't add the element to to->hashes.  That would only allow
             * 'e' to be migrated to another slave in this rebalancing run, and
             * there is no point in doing that. */
            list_remove(&e->list_node);

            /* Re-sort 'bals'. */
            reinsert_bal(&bals, from);
            reinsert_bal(&bals, to);
        } else {
            /* Can't usefully migrate anything away from 'from'.
             * Don't reconsider it. */
            list_remove(&from->bal_node);
        }
    }

    /* Implement exponentially weighted moving average.  A weight of 1/2 causes
     * historical data to decay to <1% in 7 rebalancing runs.  1,000,000 bytes
     * take 20 rebalancing runs to decay to 0 and get deleted entirely. */
    for (e = &bond->hash[0]; e <= &bond->hash[BOND_MASK]; e++) {
        e->tx_bytes /= 2;
        if (!e->tx_bytes) {
            e->slave = NULL;
        }
    }
}

/* Bonding unixctl user interface functions. */

static struct bond *
bond_find(const char *name)
{
    struct bond *bond;

    HMAP_FOR_EACH_WITH_HASH (bond, hmap_node, hash_string(name, 0),
                             &all_bonds) {
        if (!strcmp(bond->name, name)) {
            return bond;
        }
    }
    return NULL;
}

static struct bond_slave *
bond_lookup_slave(struct bond *bond, const char *slave_name)
{
    struct bond_slave *slave;

    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        if (!strcmp(slave->name, slave_name)) {
            return slave;
        }
    }
    return NULL;
}

static void
bond_unixctl_list(struct unixctl_conn *conn,
                  int argc OVS_UNUSED, const char *argv[] OVS_UNUSED,
                  void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    const struct bond *bond;

    ds_put_cstr(&ds, "bond\ttype\tslaves\n");

    HMAP_FOR_EACH (bond, hmap_node, &all_bonds) {
        const struct bond_slave *slave;
        size_t i;

        ds_put_format(&ds, "%s\t%s\t",
                      bond->name, bond_mode_to_string(bond->balance));

        i = 0;
        HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
            if (i++ > 0) {
                ds_put_cstr(&ds, ", ");
            }
            ds_put_cstr(&ds, slave->name);
        }
        ds_put_char(&ds, '\n');
    }
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
bond_print_details(struct ds *ds, const struct bond *bond)
{
    struct shash slave_shash = SHASH_INITIALIZER(&slave_shash);
    const struct shash_node **sorted_slaves = NULL;
    const struct bond_slave *slave;
    int i;

    ds_put_format(ds, "---- %s ----\n", bond->name);
    ds_put_format(ds, "bond_mode: %s\n",
                  bond_mode_to_string(bond->balance));

    ds_put_format(ds, "bond-hash-basis: %"PRIu32"\n", bond->basis);

    ds_put_format(ds, "updelay: %d ms\n", bond->updelay);
    ds_put_format(ds, "downdelay: %d ms\n", bond->downdelay);

    if (bond_is_balanced(bond)) {
        ds_put_format(ds, "next rebalance: %lld ms\n",
                      bond->next_rebalance - time_msec());
    }

    ds_put_cstr(ds, "lacp_status: ");
    switch (bond->lacp_status) {
    case LACP_NEGOTIATED:
        ds_put_cstr(ds, "negotiated\n");
        break;
    case LACP_CONFIGURED:
        ds_put_cstr(ds, "configured\n");
        break;
    case LACP_DISABLED:
        ds_put_cstr(ds, "off\n");
        break;
    default:
        ds_put_cstr(ds, "<unknown>\n");
        break;
    }

    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        shash_add(&slave_shash, slave->name, slave);
    }
    sorted_slaves = shash_sort(&slave_shash);

    for (i = 0; i < shash_count(&slave_shash); i++) {
        struct bond_entry *be;

        slave = sorted_slaves[i]->data;

        /* Basic info. */
        ds_put_format(ds, "\nslave %s: %s\n",
                      slave->name, slave->enabled ? "enabled" : "disabled");
        if (slave == bond->active_slave) {
            ds_put_cstr(ds, "\tactive slave\n");
        }
        if (slave->delay_expires != LLONG_MAX) {
            ds_put_format(ds, "\t%s expires in %lld ms\n",
                          slave->enabled ? "downdelay" : "updelay",
                          slave->delay_expires - time_msec());
        }

        ds_put_format(ds, "\tmay_enable: %s\n",
                      slave->may_enable ? "true" : "false");

        if (!bond_is_balanced(bond)) {
            continue;
        }

        /* Hashes. */
        for (be = bond->hash; be <= &bond->hash[BOND_MASK]; be++) {
            int hash = be - bond->hash;

            if (be->slave != slave) {
                continue;
            }

            ds_put_format(ds, "\thash %d: %"PRIu64" kB load\n",
                          hash, be->tx_bytes / 1024);

            /* XXX How can we list the MACs assigned to hashes of SLB bonds? */
        }
    }
    shash_destroy(&slave_shash);
    free(sorted_slaves);
    ds_put_cstr(ds, "\n");
}

static void
bond_unixctl_show(struct unixctl_conn *conn,
                  int argc, const char *argv[],
                  void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    if (argc > 1) {
        const struct bond *bond = bond_find(argv[1]);

        if (!bond) {
            unixctl_command_reply_error(conn, "no such bond");
            return;
        }
        bond_print_details(&ds, bond);
    } else {
        const struct bond *bond;

        HMAP_FOR_EACH (bond, hmap_node, &all_bonds) {
            bond_print_details(&ds, bond);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
bond_unixctl_migrate(struct unixctl_conn *conn,
                     int argc OVS_UNUSED, const char *argv[],
                     void *aux OVS_UNUSED)
{
    const char *bond_s = argv[1];
    const char *hash_s = argv[2];
    const char *slave_s = argv[3];
    struct bond *bond;
    struct bond_slave *slave;
    struct bond_entry *entry;
    int hash;

    bond = bond_find(bond_s);
    if (!bond) {
        unixctl_command_reply_error(conn, "no such bond");
        return;
    }

    if (bond->balance != BM_SLB) {
        unixctl_command_reply_error(conn, "not an SLB bond");
        return;
    }

    if (strspn(hash_s, "0123456789") == strlen(hash_s)) {
        hash = atoi(hash_s) & BOND_MASK;
    } else {
        unixctl_command_reply_error(conn, "bad hash");
        return;
    }

    slave = bond_lookup_slave(bond, slave_s);
    if (!slave) {
        unixctl_command_reply_error(conn, "no such slave");
        return;
    }

    if (!slave->enabled) {
        unixctl_command_reply_error(conn, "cannot migrate to disabled slave");
        return;
    }

    entry = &bond->hash[hash];
    tag_set_add(&bond->unixctl_tags, entry->tag);
    entry->slave = slave;
    entry->tag = tag_create_random();
    unixctl_command_reply(conn, "migrated");
}

static void
bond_unixctl_set_active_slave(struct unixctl_conn *conn,
                              int argc OVS_UNUSED, const char *argv[],
                              void *aux OVS_UNUSED)
{
    const char *bond_s = argv[1];
    const char *slave_s = argv[2];
    struct bond *bond;
    struct bond_slave *slave;

    bond = bond_find(bond_s);
    if (!bond) {
        unixctl_command_reply_error(conn, "no such bond");
        return;
    }

    slave = bond_lookup_slave(bond, slave_s);
    if (!slave) {
        unixctl_command_reply_error(conn, "no such slave");
        return;
    }

    if (!slave->enabled) {
        unixctl_command_reply_error(conn, "cannot make disabled slave active");
        return;
    }

    if (bond->active_slave != slave) {
        tag_set_add(&bond->unixctl_tags, bond_get_active_slave_tag(bond));
        bond->active_slave = slave;
        bond->active_slave->tag = tag_create_random();
        VLOG_INFO("bond %s: active interface is now %s",
                  bond->name, slave->name);
        bond->send_learning_packets = true;
        unixctl_command_reply(conn, "done");
    } else {
        unixctl_command_reply(conn, "no change");
    }
}

static void
enable_slave(struct unixctl_conn *conn, const char *argv[], bool enable)
{
    const char *bond_s = argv[1];
    const char *slave_s = argv[2];
    struct bond *bond;
    struct bond_slave *slave;

    bond = bond_find(bond_s);
    if (!bond) {
        unixctl_command_reply_error(conn, "no such bond");
        return;
    }

    slave = bond_lookup_slave(bond, slave_s);
    if (!slave) {
        unixctl_command_reply_error(conn, "no such slave");
        return;
    }

    bond_enable_slave(slave, enable, &bond->unixctl_tags);
    unixctl_command_reply(conn, enable ? "enabled" : "disabled");
}

static void
bond_unixctl_enable_slave(struct unixctl_conn *conn,
                          int argc OVS_UNUSED, const char *argv[],
                          void *aux OVS_UNUSED)
{
    enable_slave(conn, argv, true);
}

static void
bond_unixctl_disable_slave(struct unixctl_conn *conn,
                           int argc OVS_UNUSED, const char *argv[],
                           void *aux OVS_UNUSED)
{
    enable_slave(conn, argv, false);
}

static void
bond_unixctl_hash(struct unixctl_conn *conn, int argc, const char *argv[],
                  void *aux OVS_UNUSED)
{
    const char *mac_s = argv[1];
    const char *vlan_s = argc > 2 ? argv[2] : NULL;
    const char *basis_s = argc > 3 ? argv[3] : NULL;
    uint8_t mac[ETH_ADDR_LEN];
    uint8_t hash;
    char *hash_cstr;
    unsigned int vlan;
    uint32_t basis;

    if (vlan_s) {
        if (sscanf(vlan_s, "%u", &vlan) != 1) {
            unixctl_command_reply_error(conn, "invalid vlan");
            return;
        }
    } else {
        vlan = 0;
    }

    if (basis_s) {
        if (sscanf(basis_s, "%"PRIu32, &basis) != 1) {
            unixctl_command_reply_error(conn, "invalid basis");
            return;
        }
    } else {
        basis = 0;
    }

    if (sscanf(mac_s, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))
        == ETH_ADDR_SCAN_COUNT) {
        hash = bond_hash_src(mac, vlan, basis) & BOND_MASK;

        hash_cstr = xasprintf("%u", hash);
        unixctl_command_reply(conn, hash_cstr);
        free(hash_cstr);
    } else {
        unixctl_command_reply_error(conn, "invalid mac");
    }
}

void
bond_init(void)
{
    unixctl_command_register("bond/list", "", 0, 0, bond_unixctl_list, NULL);
    unixctl_command_register("bond/show", "[port]", 0, 1, bond_unixctl_show,
                             NULL);
    unixctl_command_register("bond/migrate", "port hash slave", 3, 3,
                             bond_unixctl_migrate, NULL);
    unixctl_command_register("bond/set-active-slave", "port slave", 2, 2,
                             bond_unixctl_set_active_slave, NULL);
    unixctl_command_register("bond/enable-slave", "port slave", 2, 2,
                             bond_unixctl_enable_slave, NULL);
    unixctl_command_register("bond/disable-slave", "port slave", 2, 2,
                             bond_unixctl_disable_slave, NULL);
    unixctl_command_register("bond/hash", "mac [vlan] [basis]", 1, 3,
                             bond_unixctl_hash, NULL);
}

static void
bond_entry_reset(struct bond *bond)
{
    if (bond->balance != BM_AB) {
        size_t hash_len = (BOND_MASK + 1) * sizeof *bond->hash;

        if (!bond->hash) {
            bond->hash = xmalloc(hash_len);
        }
        memset(bond->hash, 0, hash_len);

        bond->next_rebalance = time_msec() + bond->rebalance_interval;
    } else {
        free(bond->hash);
        bond->hash = NULL;
    }
}

static struct bond_slave *
bond_slave_lookup(struct bond *bond, const void *slave_)
{
    struct bond_slave *slave;

    HMAP_FOR_EACH_IN_BUCKET (slave, hmap_node, hash_pointer(slave_, 0),
                             &bond->slaves) {
        if (slave->aux == slave_) {
            return slave;
        }
    }

    return NULL;
}

static void
bond_enable_slave(struct bond_slave *slave, bool enable, struct tag_set *tags)
{
    struct bond *bond = slave->bond;
    slave->delay_expires = LLONG_MAX;
    if (enable != slave->enabled) {
        slave->enabled = enable;
        if (!slave->enabled) {
            VLOG_WARN("interface %s: disabled", slave->name);
            if (tags) {
                tag_set_add(tags, slave->tag);
            }
        } else {
            VLOG_WARN("interface %s: enabled", slave->name);
            slave->tag = tag_create_random();
        }

        if (bond->balance == BM_STABLE) {
            bond->bond_revalidate = true;
        }
    }
}

static void
bond_link_status_update(struct bond_slave *slave, struct tag_set *tags)
{
    struct bond *bond = slave->bond;
    bool up;

    up = netdev_get_carrier(slave->netdev) && slave->may_enable;
    if ((up == slave->enabled) != (slave->delay_expires == LLONG_MAX)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_INFO_RL(&rl, "interface %s: link state %s",
                     slave->name, up ? "up" : "down");
        if (up == slave->enabled) {
            slave->delay_expires = LLONG_MAX;
            VLOG_INFO_RL(&rl, "interface %s: will not be %s",
                         slave->name, up ? "disabled" : "enabled");
        } else {
            int delay = (bond->lacp_status != LACP_DISABLED ? 0
                         : up ? bond->updelay : bond->downdelay);
            slave->delay_expires = time_msec() + delay;
            if (delay) {
                VLOG_INFO_RL(&rl, "interface %s: will be %s if it stays %s "
                             "for %d ms",
                             slave->name,
                             up ? "enabled" : "disabled",
                             up ? "up" : "down",
                             delay);
            }
        }
    }

    if (time_msec() >= slave->delay_expires) {
        bond_enable_slave(slave, up, tags);
    }
}

static unsigned int
bond_hash_src(const uint8_t mac[ETH_ADDR_LEN], uint16_t vlan, uint32_t basis)
{
    return hash_3words(hash_bytes(mac, ETH_ADDR_LEN, 0), vlan, basis);
}

static unsigned int
bond_hash_tcp(const struct flow *flow, uint16_t vlan, uint32_t basis)
{
    struct flow hash_flow = *flow;
    hash_flow.vlan_tci = htons(vlan);

    /* The symmetric quality of this hash function is not required, but
     * flow_hash_symmetric_l4 already exists, and is sufficient for our
     * purposes, so we use it out of convenience. */
    return flow_hash_symmetric_l4(&hash_flow, basis);
}

static unsigned int
bond_hash(const struct bond *bond, const struct flow *flow, uint16_t vlan)
{
    assert(bond->balance == BM_TCP || bond->balance == BM_SLB);

    return (bond->balance == BM_TCP
            ? bond_hash_tcp(flow, vlan, bond->basis)
            : bond_hash_src(flow->dl_src, vlan, bond->basis));
}

static struct bond_entry *
lookup_bond_entry(const struct bond *bond, const struct flow *flow,
                  uint16_t vlan)
{
    return &bond->hash[bond_hash(bond, flow, vlan) & BOND_MASK];
}

/* This function uses Highest Random Weight hashing to choose an output slave.
 * This approach only reassigns a minimal number of flows when slaves are
 * enabled or disabled.  Unfortunately, it has O(n) performance against the
 * number of slaves.  There exist algorithms which are O(1), but have slightly
 * more complex implementations and require the use of memory.  This may need
 * to be reimplemented if it becomes a performance bottleneck. */
static struct bond_slave *
choose_stb_slave(const struct bond *bond, uint32_t flow_hash)
{
    struct bond_slave *best, *slave;
    uint32_t best_hash;

    best = NULL;
    best_hash = 0;
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        if (slave->enabled) {
            uint32_t hash;

            hash = hash_2words(flow_hash, slave->stb_id);
            if (!best || hash > best_hash) {
                best = slave;
                best_hash = hash;
            }
        }
    }

    return best;
}

static struct bond_slave *
choose_output_slave(const struct bond *bond, const struct flow *flow,
                    uint16_t vlan, tag_type *tags)
{
    struct bond_entry *e;

    if (bond->lacp_status == LACP_CONFIGURED) {
        /* LACP has been configured on this bond but negotiations were
         * unsuccussful.  Drop all traffic. */
        return NULL;
    }

    switch (bond->balance) {
    case BM_AB:
        return bond->active_slave;

    case BM_STABLE:
        return choose_stb_slave(bond, bond_hash_tcp(flow, vlan, bond->basis));

    case BM_TCP:
        if (bond->lacp_status != LACP_NEGOTIATED) {
            /* Must have LACP negotiations for TCP balanced bonds. */
            return NULL;
        }
        /* Fall Through. */
    case BM_SLB:
        if (!bond_is_balanced(bond)) {
            return choose_stb_slave(bond, bond_hash(bond, flow, vlan));
        }
        e = lookup_bond_entry(bond, flow, vlan);
        if (!e->slave || !e->slave->enabled) {
            e->slave = CONTAINER_OF(hmap_random_node(&bond->slaves),
                                    struct bond_slave, hmap_node);
            if (!e->slave->enabled) {
                e->slave = bond->active_slave;
            }
            e->tag = tag_create_random();
        }
        *tags |= e->tag;
        return e->slave;

    default:
        NOT_REACHED();
    }
}

static struct bond_slave *
bond_choose_slave(const struct bond *bond)
{
    struct bond_slave *slave, *best;

    /* Find an enabled slave. */
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        if (slave->enabled) {
            return slave;
        }
    }

    /* All interfaces are disabled.  Find an interface that will be enabled
     * after its updelay expires.  */
    best = NULL;
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        if (slave->delay_expires != LLONG_MAX
            && slave->may_enable
            && (!best || slave->delay_expires < best->delay_expires)) {
            best = slave;
        }
    }
    return best;
}

static void
bond_choose_active_slave(struct bond *bond, struct tag_set *tags)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct bond_slave *old_active_slave = bond->active_slave;

    bond->active_slave = bond_choose_slave(bond);
    if (bond->active_slave) {
        if (bond->active_slave->enabled) {
            VLOG_INFO_RL(&rl, "bond %s: active interface is now %s",
                         bond->name, bond->active_slave->name);
        } else {
            VLOG_INFO_RL(&rl, "bond %s: active interface is now %s, skipping "
                         "remaining %lld ms updelay (since no interface was "
                         "enabled)", bond->name, bond->active_slave->name,
                         bond->active_slave->delay_expires - time_msec());
            bond_enable_slave(bond->active_slave, true, tags);
        }

        if (!old_active_slave) {
            tag_set_add(tags, bond->no_slaves_tag);
        }

        bond->send_learning_packets = true;
    } else if (old_active_slave) {
        VLOG_WARN_RL(&rl, "bond %s: all interfaces disabled", bond->name);
    }
}

/* Returns the tag for 'bond''s active slave, or 'bond''s no_slaves_tag if
 * there is no active slave. */
static tag_type
bond_get_active_slave_tag(const struct bond *bond)
{
    return (bond->active_slave
            ? bond->active_slave->tag
            : bond->no_slaves_tag);
}

/* Attempts to make the sum of the bond slaves' statistics appear on the fake
 * bond interface. */
static void
bond_update_fake_slave_stats(struct bond *bond)
{
    struct netdev_stats bond_stats;
    struct bond_slave *slave;
    struct netdev *bond_dev;

    memset(&bond_stats, 0, sizeof bond_stats);

    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        struct netdev_stats slave_stats;

        if (!netdev_get_stats(slave->netdev, &slave_stats)) {
            /* XXX: We swap the stats here because they are swapped back when
             * reported by the internal device.  The reason for this is
             * internal devices normally represent packets going into the
             * system but when used as fake bond device they represent packets
             * leaving the system.  We really should do this in the internal
             * device itself because changing it here reverses the counts from
             * the perspective of the switch.  However, the internal device
             * doesn't know what type of device it represents so we have to do
             * it here for now. */
            bond_stats.tx_packets += slave_stats.rx_packets;
            bond_stats.tx_bytes += slave_stats.rx_bytes;
            bond_stats.rx_packets += slave_stats.tx_packets;
            bond_stats.rx_bytes += slave_stats.tx_bytes;
        }
    }

    if (!netdev_open(bond->name, "system", &bond_dev)) {
        netdev_set_stats(bond_dev, &bond_stats);
        netdev_close(bond_dev);
    }
}
