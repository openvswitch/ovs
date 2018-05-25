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

#include "bond.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#include "connectivity.h"
#include "coverage.h"
#include "dp-packet.h"
#include "flow.h"
#include "openvswitch/hmap.h"
#include "lacp.h"
#include "netdev.h"
#include "odp-util.h"
#include "ofproto/ofproto-dpif.h"
#include "ofproto/ofproto-dpif-rid.h"
#include "ofproto/ofproto-provider.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/list.h"
#include "openvswitch/match.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "openvswitch/poll-loop.h"
#include "seq.h"
#include "openvswitch/shash.h"
#include "timeval.h"
#include "unixctl.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(bond);

static struct ovs_rwlock rwlock = OVS_RWLOCK_INITIALIZER;
static struct hmap all_bonds__ = HMAP_INITIALIZER(&all_bonds__);
static struct hmap *const all_bonds OVS_GUARDED_BY(rwlock) = &all_bonds__;

/* Bit-mask for hashing a flow down to a bucket. */
#define BOND_MASK 0xff
#define BOND_BUCKETS (BOND_MASK + 1)

/* Priority for internal rules created to handle recirculation */
#define RECIRC_RULE_PRIORITY 20

/* A hash bucket for mapping a flow to a slave.
 * "struct bond" has an array of BOND_BUCKETS of these. */
struct bond_entry {
    struct bond_slave *slave;   /* Assigned slave, NULL if unassigned. */
    uint64_t tx_bytes           /* Count of bytes recently transmitted. */
        OVS_GUARDED_BY(rwlock);
    struct ovs_list list_node;  /* In bond_slave's 'entries' list. */

    /* Recirculation.
     *
     * 'pr_rule' is the post-recirculation rule for this entry.
     * 'pr_tx_bytes' is the most recently seen statistics for 'pr_rule', which
     * is used to determine delta (applied to 'tx_bytes' above.) */
    struct rule *pr_rule;
    uint64_t pr_tx_bytes OVS_GUARDED_BY(rwlock);
};

/* A bond slave, that is, one of the links comprising a bond. */
struct bond_slave {
    struct hmap_node hmap_node; /* In struct bond's slaves hmap. */
    struct ovs_list list_node;  /* In struct bond's enabled_slaves list. */
    struct bond *bond;          /* The bond that contains this slave. */
    void *aux;                  /* Client-provided handle for this slave. */

    struct netdev *netdev;      /* Network device, owned by the client. */
    uint64_t change_seq;        /* Tracks changes in 'netdev'. */
    char *name;                 /* Name (a copy of netdev_get_name(netdev)). */
    ofp_port_t  ofp_port;       /* OpenFlow port number. */

    /* Link status. */
    bool enabled;               /* May be chosen for flows? */
    bool may_enable;            /* Client considers this slave bondable. */
    long long delay_expires;    /* Time after which 'enabled' may change. */

    /* Rebalancing info.  Used only by bond_rebalance(). */
    struct ovs_list bal_node;   /* In bond_rebalance()'s 'bals' list. */
    struct ovs_list entries;    /* 'struct bond_entry's assigned here. */
    uint64_t tx_bytes;          /* Sum across 'tx_bytes' of entries. */
};

/* A bond, that is, a set of network devices grouped to improve performance or
 * robustness.  */
struct bond {
    struct hmap_node hmap_node; /* In 'all_bonds' hmap. */
    char *name;                 /* Name provided by client. */
    struct ofproto_dpif *ofproto; /* The bridge this bond belongs to. */

    /* Slaves. */
    struct hmap slaves;

    /* Enabled slaves.
     *
     * Any reader or writer of 'enabled_slaves' must hold 'mutex'.
     * (To prevent the bond_slave from disappearing they must also hold
     * 'rwlock'.) */
    struct ovs_mutex mutex OVS_ACQ_AFTER(rwlock);
    struct ovs_list enabled_slaves OVS_GUARDED; /* Contains struct bond_slaves. */

    /* Bonding info. */
    enum bond_mode balance;     /* Balancing mode, one of BM_*. */
    struct bond_slave *active_slave;
    int updelay, downdelay;     /* Delay before slave goes up/down, in ms. */
    enum lacp_status lacp_status; /* Status of LACP negotiations. */
    bool bond_revalidate;       /* True if flows need revalidation. */
    uint32_t basis;             /* Basis for flow hash function. */

    /* SLB specific bonding info. */
    struct bond_entry *hash;     /* An array of BOND_BUCKETS elements. */
    int rebalance_interval;      /* Interval between rebalances, in ms. */
    long long int next_rebalance; /* Next rebalancing time. */
    bool send_learning_packets;
    uint32_t recirc_id;          /* Non zero if recirculation can be used.*/
    struct hmap pr_rule_ops;     /* Helps to maintain post recirculation rules.*/

    /* Store active slave to OVSDB. */
    bool active_slave_changed; /* Set to true whenever the bond changes
                                   active slave. It will be reset to false
                                   after it is stored into OVSDB */

    /* Interface name may not be persistent across an OS reboot, use
     * MAC address for identifing the active slave */
    struct eth_addr active_slave_mac;
                               /* The MAC address of the active interface. */
    /* Legacy compatibility. */
    bool lacp_fallback_ab; /* Fallback to active-backup on LACP failure. */

    struct ovs_refcount ref_cnt;
};

/* What to do with an bond_recirc_rule. */
enum bond_op {
    ADD,        /* Add the rule to ofproto's flow table. */
    DEL,        /* Delete the rule from the ofproto's flow table. */
};

/* A rule to add to or delete from ofproto's internal flow table. */
struct bond_pr_rule_op {
    struct hmap_node hmap_node;
    struct match match;
    ofp_port_t out_ofport;
    enum bond_op op;
    struct rule **pr_rule;
};

static void bond_entry_reset(struct bond *) OVS_REQ_WRLOCK(rwlock);
static struct bond_slave *bond_slave_lookup(struct bond *, const void *slave_)
    OVS_REQ_RDLOCK(rwlock);
static void bond_enable_slave(struct bond_slave *, bool enable)
    OVS_REQ_WRLOCK(rwlock);
static void bond_link_status_update(struct bond_slave *)
    OVS_REQ_WRLOCK(rwlock);
static void bond_choose_active_slave(struct bond *)
    OVS_REQ_WRLOCK(rwlock);
static struct bond_entry *lookup_bond_entry(const struct bond *,
                                            const struct flow *,
                                            uint16_t vlan)
    OVS_REQ_RDLOCK(rwlock);
static struct bond_slave *get_enabled_slave(struct bond *)
    OVS_REQ_RDLOCK(rwlock);
static struct bond_slave *choose_output_slave(const struct bond *,
                                              const struct flow *,
                                              struct flow_wildcards *,
                                              uint16_t vlan)
    OVS_REQ_RDLOCK(rwlock);
static void update_recirc_rules__(struct bond *bond);

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
    case BM_AB:
        return "active-backup";
    }
    OVS_NOT_REACHED();
}


/* Creates and returns a new bond whose configuration is initially taken from
 * 's'.
 *
 * The caller should register each slave on the new bond by calling
 * bond_slave_register().  */
struct bond *
bond_create(const struct bond_settings *s, struct ofproto_dpif *ofproto)
{
    struct bond *bond;

    bond = xzalloc(sizeof *bond);
    bond->ofproto = ofproto;
    hmap_init(&bond->slaves);
    ovs_list_init(&bond->enabled_slaves);
    ovs_mutex_init(&bond->mutex);
    ovs_refcount_init(&bond->ref_cnt);
    hmap_init(&bond->pr_rule_ops);

    bond->active_slave_mac = eth_addr_zero;
    bond->active_slave_changed = false;

    bond_reconfigure(bond, s);
    return bond;
}

struct bond *
bond_ref(const struct bond *bond_)
{
    struct bond *bond = CONST_CAST(struct bond *, bond_);

    if (bond) {
        ovs_refcount_ref(&bond->ref_cnt);
    }
    return bond;
}

/* Frees 'bond'. */
void
bond_unref(struct bond *bond)
{
    struct bond_slave *slave;

    if (!bond || ovs_refcount_unref_relaxed(&bond->ref_cnt) != 1) {
        return;
    }

    ovs_rwlock_wrlock(&rwlock);
    hmap_remove(all_bonds, &bond->hmap_node);
    ovs_rwlock_unlock(&rwlock);

    HMAP_FOR_EACH_POP (slave, hmap_node, &bond->slaves) {
        /* Client owns 'slave->netdev'. */
        free(slave->name);
        free(slave);
    }
    hmap_destroy(&bond->slaves);

    ovs_mutex_destroy(&bond->mutex);

    /* Free bond resources. Remove existing post recirc rules. */
    if (bond->recirc_id) {
        recirc_free_id(bond->recirc_id);
        bond->recirc_id = 0;
    }
    free(bond->hash);
    bond->hash = NULL;
    update_recirc_rules__(bond);

    hmap_destroy(&bond->pr_rule_ops);
    free(bond->name);
    free(bond);
}

static void
add_pr_rule(struct bond *bond, const struct match *match,
            ofp_port_t out_ofport, struct rule **rule)
{
    uint32_t hash = match_hash(match, 0);
    struct bond_pr_rule_op *pr_op;

    HMAP_FOR_EACH_WITH_HASH(pr_op, hmap_node, hash, &bond->pr_rule_ops) {
        if (match_equal(&pr_op->match, match)) {
            pr_op->op = ADD;
            pr_op->out_ofport = out_ofport;
            pr_op->pr_rule = rule;
            return;
        }
    }

    pr_op = xmalloc(sizeof *pr_op);
    pr_op->match = *match;
    pr_op->op = ADD;
    pr_op->out_ofport = out_ofport;
    pr_op->pr_rule = rule;
    hmap_insert(&bond->pr_rule_ops, &pr_op->hmap_node, hash);
}

/* This function should almost never be called directly.
 * 'update_recirc_rules()' should be called instead.  Since
 * this function modifies 'bond->pr_rule_ops', it is only
 * safe when 'rwlock' is held.
 *
 * However, when the 'bond' is the only reference in the system,
 * calling this function avoid acquiring lock only to satisfy
 * lock annotation. Currently, only 'bond_unref()' calls
 * this function directly.  */
static void
update_recirc_rules__(struct bond *bond)
{
    struct match match;
    struct bond_pr_rule_op *pr_op, *next_op;
    uint64_t ofpacts_stub[128 / 8];
    struct ofpbuf ofpacts;
    int i;

    ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);

    HMAP_FOR_EACH(pr_op, hmap_node, &bond->pr_rule_ops) {
        pr_op->op = DEL;
    }

    if (bond->hash && bond->recirc_id) {
        for (i = 0; i < BOND_BUCKETS; i++) {
            struct bond_slave *slave = bond->hash[i].slave;

            if (slave) {
                match_init_catchall(&match);
                match_set_recirc_id(&match, bond->recirc_id);
                match_set_dp_hash_masked(&match, i, BOND_MASK);

                add_pr_rule(bond, &match, slave->ofp_port,
                            &bond->hash[i].pr_rule);
            }
        }
    }

    HMAP_FOR_EACH_SAFE(pr_op, next_op, hmap_node, &bond->pr_rule_ops) {
        int error;
        switch (pr_op->op) {
        case ADD:
            ofpbuf_clear(&ofpacts);
            ofpact_put_OUTPUT(&ofpacts)->port = pr_op->out_ofport;
            error = ofproto_dpif_add_internal_flow(bond->ofproto,
                                                   &pr_op->match,
                                                   RECIRC_RULE_PRIORITY, 0,
                                                   &ofpacts, pr_op->pr_rule);
            if (error) {
                char *err_s = match_to_string(&pr_op->match, NULL,
                                              RECIRC_RULE_PRIORITY);

                VLOG_ERR("failed to add post recirculation flow %s", err_s);
                free(err_s);
            }
            break;

        case DEL:
            error = ofproto_dpif_delete_internal_flow(bond->ofproto,
                                                      &pr_op->match,
                                                      RECIRC_RULE_PRIORITY);
            if (error) {
                char *err_s = match_to_string(&pr_op->match, NULL,
                                              RECIRC_RULE_PRIORITY);

                VLOG_ERR("failed to remove post recirculation flow %s", err_s);
                free(err_s);
            }

            hmap_remove(&bond->pr_rule_ops, &pr_op->hmap_node);
            if (bond->hash) {
                *pr_op->pr_rule = NULL;
            }
            free(pr_op);
            break;
        }
    }

    ofpbuf_uninit(&ofpacts);
}

static void
update_recirc_rules(struct bond *bond)
    OVS_REQ_RDLOCK(rwlock)
{
    update_recirc_rules__(bond);
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

    ovs_rwlock_wrlock(&rwlock);
    if (!bond->name || strcmp(bond->name, s->name)) {
        if (bond->name) {
            hmap_remove(all_bonds, &bond->hmap_node);
            free(bond->name);
        }
        bond->name = xstrdup(s->name);
        hmap_insert(all_bonds, &bond->hmap_node, hash_string(bond->name, 0));
    }

    bond->updelay = s->up_delay;
    bond->downdelay = s->down_delay;

    if (bond->lacp_fallback_ab != s->lacp_fallback_ab_cfg) {
        bond->lacp_fallback_ab = s->lacp_fallback_ab_cfg;
        revalidate = true;
    }

    if (bond->rebalance_interval != s->rebalance_interval) {
        bond->rebalance_interval = s->rebalance_interval;
        revalidate = true;
    }

    if (bond->balance != s->balance) {
        bond->balance = s->balance;
        revalidate = true;
    }

    if (bond->basis != s->basis) {
        bond->basis = s->basis;
        revalidate = true;
    }

    if (bond->bond_revalidate) {
        revalidate = true;
        bond->bond_revalidate = false;
    }

    if (bond->balance != BM_AB) {
        if (!bond->recirc_id) {
            bond->recirc_id = recirc_alloc_id(bond->ofproto);
        }
    } else if (bond->recirc_id) {
        recirc_free_id(bond->recirc_id);
        bond->recirc_id = 0;
    }

    if (bond->balance == BM_AB || !bond->hash || revalidate) {
        bond_entry_reset(bond);
    }

    ovs_rwlock_unlock(&rwlock);
    return revalidate;
}

static struct bond_slave *
bond_find_slave_by_mac(const struct bond *bond, const struct eth_addr mac)
{
    struct bond_slave *slave;

    /* Find the last active slave */
    HMAP_FOR_EACH(slave, hmap_node, &bond->slaves) {
        struct eth_addr slave_mac;

        if (netdev_get_etheraddr(slave->netdev, &slave_mac)) {
            continue;
        }

        if (eth_addr_equals(slave_mac, mac)) {
            return slave;
        }
    }

    return NULL;
}

static void
bond_active_slave_changed(struct bond *bond)
{
    if (bond->active_slave) {
        struct eth_addr mac;
        netdev_get_etheraddr(bond->active_slave->netdev, &mac);
        bond->active_slave_mac = mac;
    } else {
        bond->active_slave_mac = eth_addr_zero;
    }
    bond->active_slave_changed = true;
    seq_change(connectivity_seq_get());
}

static void
bond_slave_set_netdev__(struct bond_slave *slave, struct netdev *netdev)
    OVS_REQ_WRLOCK(rwlock)
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
 * 'netdev' must be the network device that 'slave_' represents.  It is owned
 * by the client, so the client must not close it before either unregistering
 * 'slave_' or destroying 'bond'.
 */
void
bond_slave_register(struct bond *bond, void *slave_,
                    ofp_port_t ofport, struct netdev *netdev)
{
    struct bond_slave *slave;

    ovs_rwlock_wrlock(&rwlock);
    slave = bond_slave_lookup(bond, slave_);
    if (!slave) {
        slave = xzalloc(sizeof *slave);

        hmap_insert(&bond->slaves, &slave->hmap_node, hash_pointer(slave_, 0));
        slave->bond = bond;
        slave->aux = slave_;
        slave->ofp_port = ofport;
        slave->delay_expires = LLONG_MAX;
        slave->name = xstrdup(netdev_get_name(netdev));
        bond->bond_revalidate = true;

        slave->enabled = false;
        bond_enable_slave(slave, netdev_get_carrier(netdev));
    }

    bond_slave_set_netdev__(slave, netdev);

    free(slave->name);
    slave->name = xstrdup(netdev_get_name(netdev));
    ovs_rwlock_unlock(&rwlock);
}

/* Updates the network device to be used with 'slave_' to 'netdev'.
 *
 * This is useful if the caller closes and re-opens the network device
 * registered with bond_slave_register() but doesn't need to change anything
 * else. */
void
bond_slave_set_netdev(struct bond *bond, void *slave_, struct netdev *netdev)
{
    struct bond_slave *slave;

    ovs_rwlock_wrlock(&rwlock);
    slave = bond_slave_lookup(bond, slave_);
    if (slave) {
        bond_slave_set_netdev__(slave, netdev);
    }
    ovs_rwlock_unlock(&rwlock);
}

/* Unregisters 'slave_' from 'bond'.  If 'bond' does not contain such a slave
 * then this function has no effect.
 *
 * Unregistering a slave invalidates all flows. */
void
bond_slave_unregister(struct bond *bond, const void *slave_)
{
    struct bond_slave *slave;
    bool del_active;

    ovs_rwlock_wrlock(&rwlock);
    slave = bond_slave_lookup(bond, slave_);
    if (!slave) {
        goto out;
    }

    bond->bond_revalidate = true;
    bond_enable_slave(slave, false);

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
        bond_choose_active_slave(bond);
        bond->send_learning_packets = true;
    }
out:
    ovs_rwlock_unlock(&rwlock);
}

/* Should be called on each slave in 'bond' before bond_run() to indicate
 * whether or not 'slave_' may be enabled. This function is intended to allow
 * other protocols to have some impact on bonding decisions.  For example LACP
 * or high level link monitoring protocols may decide that a given slave should
 * not be able to send traffic. */
void
bond_slave_set_may_enable(struct bond *bond, void *slave_, bool may_enable)
{
    ovs_rwlock_wrlock(&rwlock);
    bond_slave_lookup(bond, slave_)->may_enable = may_enable;
    ovs_rwlock_unlock(&rwlock);
}

/* Performs periodic maintenance on 'bond'.
 *
 * Returns true if the caller should revalidate its flows.
 *
 * The caller should check bond_should_send_learning_packets() afterward. */
bool
bond_run(struct bond *bond, enum lacp_status lacp_status)
{
    struct bond_slave *slave;
    bool revalidate;

    ovs_rwlock_wrlock(&rwlock);
    if (bond->lacp_status != lacp_status) {
        bond->lacp_status = lacp_status;
        bond->bond_revalidate = true;
    }

    /* Enable slaves based on link status and LACP feedback. */
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        bond_link_status_update(slave);
        slave->change_seq = seq_read(connectivity_seq_get());
    }
    if (!bond->active_slave || !bond->active_slave->enabled) {
        bond_choose_active_slave(bond);
    }

    revalidate = bond->bond_revalidate;
    bond->bond_revalidate = false;
    ovs_rwlock_unlock(&rwlock);

    return revalidate;
}

/* Causes poll_block() to wake up when 'bond' needs something to be done. */
void
bond_wait(struct bond *bond)
{
    struct bond_slave *slave;

    ovs_rwlock_rdlock(&rwlock);
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        if (slave->delay_expires != LLONG_MAX) {
            poll_timer_wait_until(slave->delay_expires);
        }

        seq_wait(connectivity_seq_get(), slave->change_seq);
    }

    if (bond->bond_revalidate) {
        poll_immediate_wake();
    }
    ovs_rwlock_unlock(&rwlock);

    /* We don't wait for bond->next_rebalance because rebalancing can only run
     * at a flow account checkpoint.  ofproto does checkpointing on its own
     * schedule and bond_rebalance() gets called afterward, so we'd just be
     * waking up for no purpose. */
}

/* MAC learning table interaction. */

static bool
may_send_learning_packets(const struct bond *bond)
{
    return ((bond->lacp_status == LACP_DISABLED
        && (bond->balance == BM_SLB || bond->balance == BM_AB))
        || (bond->lacp_fallback_ab && bond->lacp_status == LACP_CONFIGURED))
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
    bool send;

    ovs_rwlock_wrlock(&rwlock);
    send = bond->send_learning_packets && may_send_learning_packets(bond);
    bond->send_learning_packets = false;
    ovs_rwlock_unlock(&rwlock);
    return send;
}

/* Sends a gratuitous learning packet on 'bond' from 'eth_src' on 'vlan'.
 *
 * See bond_should_send_learning_packets() for description of usage. The
 * caller should send the composed packet on the port associated with
 * port_aux and takes ownership of the returned ofpbuf. */
struct dp_packet *
bond_compose_learning_packet(struct bond *bond, const struct eth_addr eth_src,
                             uint16_t vlan, void **port_aux)
{
    struct bond_slave *slave;
    struct dp_packet *packet;
    struct flow flow;

    ovs_rwlock_rdlock(&rwlock);
    ovs_assert(may_send_learning_packets(bond));
    memset(&flow, 0, sizeof flow);
    flow.dl_src = eth_src;
    slave = choose_output_slave(bond, &flow, NULL, vlan);

    packet = dp_packet_new(0);
    compose_rarp(packet, eth_src);
    if (vlan) {
        eth_push_vlan(packet, htons(ETH_TYPE_VLAN), htons(vlan));
    }

    *port_aux = slave->aux;
    ovs_rwlock_unlock(&rwlock);
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
                         const struct eth_addr eth_dst)
{
    enum bond_verdict verdict = BV_DROP;
    struct bond_slave *slave;

    ovs_rwlock_rdlock(&rwlock);
    slave = bond_slave_lookup(bond, slave_);
    if (!slave) {
        goto out;
    }

    /* LACP bonds have very loose admissibility restrictions because we can
     * assume the remote switch is aware of the bond and will "do the right
     * thing".  However, as a precaution we drop packets on disabled slaves
     * because no correctly implemented partner switch should be sending
     * packets to them.
     *
     * If LACP is configured, but LACP negotiations have been unsuccessful, we
     * drop all incoming traffic except if lacp_fallback_ab is enabled. */
    switch (bond->lacp_status) {
    case LACP_NEGOTIATED:
        verdict = slave->enabled ? BV_ACCEPT : BV_DROP;
        goto out;
    case LACP_CONFIGURED:
        if (!bond->lacp_fallback_ab) {
            goto out;
        }
        break;
    case LACP_DISABLED:
        if (bond->balance == BM_TCP) {
            goto out;
        }
        break;
    }

    /* Drop all multicast packets on inactive slaves. */
    if (eth_addr_is_multicast(eth_dst)) {
        if (bond->active_slave != slave) {
            goto out;
        }
    }

    switch (bond->balance) {
    case BM_TCP:
        /* TCP balanced bonds require successful LACP negotiations. Based on the
         * above check, LACP is off or lacp_fallback_ab is true on this bond.
         * If lacp_fallback_ab is true fall through to BM_AB case else, we
         * drop all incoming traffic. */
        if (!bond->lacp_fallback_ab) {
            goto out;
        }
        /* fall through */

    case BM_AB:
        /* Drop all packets which arrive on backup slaves.  This is similar to
         * how Linux bonding handles active-backup bonds. */
        if (bond->active_slave != slave) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

            VLOG_DBG_RL(&rl, "active-backup bond received packet on backup"
                        " slave (%s) destined for " ETH_ADDR_FMT,
                        slave->name, ETH_ADDR_ARGS(eth_dst));
            goto out;
        }
        verdict = BV_ACCEPT;
        goto out;

    case BM_SLB:
        /* Drop all packets for which we have learned a different input port,
         * because we probably sent the packet on one slave and got it back on
         * the other.  Gratuitous ARP packets are an exception to this rule:
         * the host has moved to another switch.  The exception to the
         * exception is if we locked the learning table to avoid reflections on
         * bond slaves. */
        verdict = BV_DROP_IF_MOVED;
        goto out;
    }

    OVS_NOT_REACHED();
out:
    ovs_rwlock_unlock(&rwlock);
    return verdict;

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
 * If 'wc' is non-NULL, bitwise-OR's 'wc' with the set of bits that were
 * significant in the selection.  At some point earlier, 'wc' should
 * have been initialized (e.g., by flow_wildcards_init_catchall()).
 */
void *
bond_choose_output_slave(struct bond *bond, const struct flow *flow,
                         struct flow_wildcards *wc, uint16_t vlan)
{
    struct bond_slave *slave;
    void *aux;

    ovs_rwlock_rdlock(&rwlock);
    slave = choose_output_slave(bond, flow, wc, vlan);
    aux = slave ? slave->aux : NULL;
    ovs_rwlock_unlock(&rwlock);

    return aux;
}

/* Recirculation. */
static void
bond_entry_account(struct bond_entry *entry, uint64_t rule_tx_bytes)
    OVS_REQ_WRLOCK(rwlock)
{
    if (entry->slave) {
        uint64_t delta;

        delta = rule_tx_bytes - entry->pr_tx_bytes;
        entry->tx_bytes += delta;
        entry->pr_tx_bytes = rule_tx_bytes;
    }
}

/* Maintain bond stats using post recirculation rule byte counters.*/
static void
bond_recirculation_account(struct bond *bond)
    OVS_REQ_WRLOCK(rwlock)
{
    int i;

    for (i=0; i<=BOND_MASK; i++) {
        struct bond_entry *entry = &bond->hash[i];
        struct rule *rule = entry->pr_rule;

        if (rule) {
            uint64_t n_packets OVS_UNUSED;
            long long int used OVS_UNUSED;
            uint64_t n_bytes;

            rule->ofproto->ofproto_class->rule_get_stats(
                rule, &n_packets, &n_bytes, &used);
            bond_entry_account(entry, n_bytes);
        }
    }
}

static bool
bond_may_recirc(const struct bond *bond)
{
    return bond->balance == BM_TCP && bond->recirc_id;
}

static void
bond_update_post_recirc_rules__(struct bond* bond, const bool force)
    OVS_REQ_WRLOCK(rwlock)
{
   struct bond_entry *e;
   bool update_rules = force;  /* Always update rules if caller forces it. */

   /* Make sure all bond entries are populated */
   for (e = bond->hash; e <= &bond->hash[BOND_MASK]; e++) {
       if (!e->slave || !e->slave->enabled) {
            update_rules = true;
            e->slave = CONTAINER_OF(hmap_random_node(&bond->slaves),
                                    struct bond_slave, hmap_node);
            if (!e->slave->enabled) {
                e->slave = bond->active_slave;
            }
        }
   }

   if (update_rules) {
        update_recirc_rules(bond);
   }
}

void
bond_update_post_recirc_rules(struct bond *bond, uint32_t *recirc_id,
                              uint32_t *hash_basis)
{
    bool may_recirc = bond_may_recirc(bond);

    if (may_recirc) {
        /* To avoid unnecessary locking, bond_may_recirc() is first
         * called outside of the 'rwlock'. After acquiring the lock,
         * check again to make sure bond configuration has not been changed. */
        ovs_rwlock_wrlock(&rwlock);
        may_recirc = bond_may_recirc(bond);
        if (may_recirc) {
            *recirc_id = bond->recirc_id;
            *hash_basis = bond->basis;
            bond_update_post_recirc_rules__(bond, false);
        }
        ovs_rwlock_unlock(&rwlock);
    }

    if (!may_recirc) {
        *recirc_id = *hash_basis = 0;
    }
}


/* Rebalancing. */

static bool
bond_is_balanced(const struct bond *bond) OVS_REQ_RDLOCK(rwlock)
{
    return bond->rebalance_interval
        && (bond->balance == BM_SLB || bond->balance == BM_TCP);
}

/* Notifies 'bond' that 'n_bytes' bytes were sent in 'flow' within 'vlan'. */
void
bond_account(struct bond *bond, const struct flow *flow, uint16_t vlan,
             uint64_t n_bytes)
{
    ovs_rwlock_wrlock(&rwlock);
    if (bond_is_balanced(bond)) {
        lookup_bond_entry(bond, flow, vlan)->tx_bytes += n_bytes;
    }
    ovs_rwlock_unlock(&rwlock);
}

static struct bond_slave *
bond_slave_from_bal_node(struct ovs_list *bal) OVS_REQ_RDLOCK(rwlock)
{
    return CONTAINER_OF(bal, struct bond_slave, bal_node);
}

static void
log_bals(struct bond *bond, const struct ovs_list *bals)
    OVS_REQ_RDLOCK(rwlock)
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
            if (!ovs_list_is_empty(&slave->entries)) {
                struct bond_entry *e;

                ds_put_cstr(&ds, " (");
                LIST_FOR_EACH (e, list_node, &slave->entries) {
                    if (&e->list_node != ovs_list_front(&slave->entries)) {
                        ds_put_cstr(&ds, " + ");
                    }
                    ds_put_format(&ds, "h%"PRIdPTR": %"PRIu64"kB",
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
bond_shift_load(struct bond_entry *hash, struct bond_slave *to)
    OVS_REQ_WRLOCK(rwlock)
{
    struct bond_slave *from = hash->slave;
    struct bond *bond = from->bond;
    uint64_t delta = hash->tx_bytes;

    VLOG_INFO("bond %s: shift %"PRIu64"kB of load (with hash %"PRIdPTR") "
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
    hash->slave = to;
    bond->bond_revalidate = true;
}

/* Picks and returns a bond_entry to migrate from 'from' (the most heavily
 * loaded bond slave) to a bond slave that has 'to_tx_bytes' bytes of load,
 * given that doing so must decrease the ratio of the load on the two slaves by
 * at least 0.1.  Returns NULL if there is no appropriate entry.
 *
 * The list of entries isn't sorted.  I don't know of a reason to prefer to
 * shift away small hashes or large hashes. */
static struct bond_entry *
choose_entry_to_migrate(const struct bond_slave *from, uint64_t to_tx_bytes)
    OVS_REQ_WRLOCK(rwlock)
{
    struct bond_entry *e;

    if (ovs_list_is_short(&from->entries)) {
        /* 'from' carries no more than one MAC hash, so shifting load away from
         * it would be pointless. */
        return NULL;
    }

    LIST_FOR_EACH (e, list_node, &from->entries) {
        uint64_t delta = e->tx_bytes;  /* The amount to rebalance.  */
        uint64_t ideal_tx_bytes = (from->tx_bytes + to_tx_bytes)/2;
                             /* Note, the ideal traffic is the mid point
                              * between 'from' and 'to'. This value does
                              * not change by rebalancing.  */
        uint64_t new_low;    /* The lower bandwidth between 'to' and 'from'
                                after rebalancing. */

        new_low = MIN(from->tx_bytes - delta, to_tx_bytes + delta);

        if ((new_low > to_tx_bytes) &&
            (new_low - to_tx_bytes >= (ideal_tx_bytes - to_tx_bytes) / 10)) {
            /* Only rebalance if the new 'low' is closer to to the mid point,
             * and the improvement exceeds 10% of current traffic
             * deviation from the ideal split.
             *
             * The improvement on the 'high' side is always the same as the
             * 'low' side. Thus consider 'low' side is sufficient.  */
            return e;
        }
    }

    return NULL;
}

/* Inserts 'slave' into 'bals' so that descending order of 'tx_bytes' is
 * maintained. */
static void
insert_bal(struct ovs_list *bals, struct bond_slave *slave)
{
    struct bond_slave *pos;

    LIST_FOR_EACH (pos, bal_node, bals) {
        if (slave->tx_bytes > pos->tx_bytes) {
            break;
        }
    }
    ovs_list_insert(&pos->bal_node, &slave->bal_node);
}

/* Removes 'slave' from its current list and then inserts it into 'bals' so
 * that descending order of 'tx_bytes' is maintained. */
static void
reinsert_bal(struct ovs_list *bals, struct bond_slave *slave)
{
    ovs_list_remove(&slave->bal_node);
    insert_bal(bals, slave);
}

/* If 'bond' needs rebalancing, does so.
 *
 * The caller should have called bond_account() for each active flow, or in case
 * of recirculation is used, have called bond_recirculation_account(bond),
 * to ensure that flow data is consistently accounted at this point.
 */
void
bond_rebalance(struct bond *bond)
{
    struct bond_slave *slave;
    struct bond_entry *e;
    struct ovs_list bals;
    bool rebalanced = false;
    bool use_recirc;

    ovs_rwlock_wrlock(&rwlock);
    if (!bond_is_balanced(bond) || time_msec() < bond->next_rebalance) {
        goto done;
    }
    bond->next_rebalance = time_msec() + bond->rebalance_interval;

    use_recirc = bond->ofproto->backer->rt_support.odp.recirc &&
                 bond_may_recirc(bond);

    if (use_recirc) {
        bond_recirculation_account(bond);
    }

    /* Add each bond_entry to its slave's 'entries' list.
     * Compute each slave's tx_bytes as the sum of its entries' tx_bytes. */
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        slave->tx_bytes = 0;
        ovs_list_init(&slave->entries);
    }
    for (e = &bond->hash[0]; e <= &bond->hash[BOND_MASK]; e++) {
        if (e->slave && e->tx_bytes) {
            e->slave->tx_bytes += e->tx_bytes;
            ovs_list_push_back(&e->slave->entries, &e->list_node);
        }
    }

    /* Add enabled slaves to 'bals' in descending order of tx_bytes.
     *
     * XXX This is O(n**2) in the number of slaves but it could be O(n lg n)
     * with a proper list sort algorithm. */
    ovs_list_init(&bals);
    HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
        if (slave->enabled) {
            insert_bal(&bals, slave);
        }
    }
    log_bals(bond, &bals);

    /* Shift load from the most-loaded slaves to the least-loaded slaves. */
    while (!ovs_list_is_short(&bals)) {
        struct bond_slave *from = bond_slave_from_bal_node(ovs_list_front(&bals));
        struct bond_slave *to = bond_slave_from_bal_node(ovs_list_back(&bals));
        uint64_t overload;

        overload = from->tx_bytes - to->tx_bytes;
        if (overload < to->tx_bytes >> 5 || overload < 100000) {
            /* The extra load on 'from' (and all less-loaded slaves), compared
             * to that of 'to' (the least-loaded slave), is less than ~3%, or
             * it is less than ~1Mbps.  No point in rebalancing. */
            break;
        }

        /* 'from' is carrying significantly more load than 'to'.  Pick a hash
         * to move from 'from' to 'to'. */
        e = choose_entry_to_migrate(from, to->tx_bytes);
        if (e) {
            bond_shift_load(e, to);

            /* Delete element from from->entries.
             *
             * We don't add the element to to->hashes.  That would only allow
             * 'e' to be migrated to another slave in this rebalancing run, and
             * there is no point in doing that. */
            ovs_list_remove(&e->list_node);

            /* Re-sort 'bals'. */
            reinsert_bal(&bals, from);
            reinsert_bal(&bals, to);
            rebalanced = true;
        } else {
            /* Can't usefully migrate anything away from 'from'.
             * Don't reconsider it. */
            ovs_list_remove(&from->bal_node);
        }
    }

    /* Implement exponentially weighted moving average.  A weight of 1/2 causes
     * historical data to decay to <1% in 7 rebalancing runs.  1,000,000 bytes
     * take 20 rebalancing runs to decay to 0 and get deleted entirely. */
    for (e = &bond->hash[0]; e <= &bond->hash[BOND_MASK]; e++) {
        e->tx_bytes /= 2;
    }

    if (use_recirc && rebalanced) {
        bond_update_post_recirc_rules__(bond,true);
    }

done:
    ovs_rwlock_unlock(&rwlock);
}

/* Bonding unixctl user interface functions. */

static struct bond *
bond_find(const char *name) OVS_REQ_RDLOCK(rwlock)
{
    struct bond *bond;

    HMAP_FOR_EACH_WITH_HASH (bond, hmap_node, hash_string(name, 0),
                             all_bonds) {
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

    ds_put_cstr(&ds, "bond\ttype\trecircID\tslaves\n");

    ovs_rwlock_rdlock(&rwlock);
    HMAP_FOR_EACH (bond, hmap_node, all_bonds) {
        const struct bond_slave *slave;
        size_t i;

        ds_put_format(&ds, "%s\t%s\t%d\t", bond->name,
                      bond_mode_to_string(bond->balance), bond->recirc_id);

        i = 0;
        HMAP_FOR_EACH (slave, hmap_node, &bond->slaves) {
            if (i++ > 0) {
                ds_put_cstr(&ds, ", ");
            }
            ds_put_cstr(&ds, slave->name);
        }
        ds_put_char(&ds, '\n');
    }
    ovs_rwlock_unlock(&rwlock);
    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

static void
bond_print_details(struct ds *ds, const struct bond *bond)
    OVS_REQ_RDLOCK(rwlock)
{
    struct shash slave_shash = SHASH_INITIALIZER(&slave_shash);
    const struct shash_node **sorted_slaves = NULL;
    const struct bond_slave *slave;
    bool may_recirc;
    uint32_t recirc_id;
    int i;

    ds_put_format(ds, "---- %s ----\n", bond->name);
    ds_put_format(ds, "bond_mode: %s\n",
                  bond_mode_to_string(bond->balance));

    may_recirc = bond_may_recirc(bond);
    recirc_id = bond->recirc_id;
    ds_put_format(ds, "bond may use recirculation: %s, Recirc-ID : %d\n",
                  may_recirc ? "yes" : "no", may_recirc ? recirc_id: -1);

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

    ds_put_format(ds, "lacp_fallback_ab: %s\n",
                  bond->lacp_fallback_ab ? "true" : "false");

    ds_put_cstr(ds, "active slave mac: ");
    ds_put_format(ds, ETH_ADDR_FMT, ETH_ADDR_ARGS(bond->active_slave_mac));
    slave = bond_find_slave_by_mac(bond, bond->active_slave_mac);
    ds_put_format(ds,"(%s)\n", slave ? slave->name : "none");

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
            ds_put_cstr(ds, "  active slave\n");
        }
        if (slave->delay_expires != LLONG_MAX) {
            ds_put_format(ds, "  %s expires in %lld ms\n",
                          slave->enabled ? "downdelay" : "updelay",
                          slave->delay_expires - time_msec());
        }

        ds_put_format(ds, "  may_enable: %s\n",
                      slave->may_enable ? "true" : "false");

        if (!bond_is_balanced(bond)) {
            continue;
        }

        /* Hashes. */
        for (be = bond->hash; be <= &bond->hash[BOND_MASK]; be++) {
            int hash = be - bond->hash;
            uint64_t be_tx_k;

            if (be->slave != slave) {
                continue;
            }

            be_tx_k = be->tx_bytes / 1024;
            if (be_tx_k) {
                ds_put_format(ds, "  hash %d: %"PRIu64" kB load\n",
                          hash, be_tx_k);
            }

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

    ovs_rwlock_rdlock(&rwlock);
    if (argc > 1) {
        const struct bond *bond = bond_find(argv[1]);

        if (!bond) {
            unixctl_command_reply_error(conn, "no such bond");
            goto out;
        }
        bond_print_details(&ds, bond);
    } else {
        const struct bond *bond;

        HMAP_FOR_EACH (bond, hmap_node, all_bonds) {
            bond_print_details(&ds, bond);
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);

out:
    ovs_rwlock_unlock(&rwlock);
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

    ovs_rwlock_wrlock(&rwlock);
    bond = bond_find(bond_s);
    if (!bond) {
        unixctl_command_reply_error(conn, "no such bond");
        goto out;
    }

    if (bond->balance != BM_SLB) {
        unixctl_command_reply_error(conn, "not an SLB bond");
        goto out;
    }

    if (strspn(hash_s, "0123456789") == strlen(hash_s)) {
        hash = atoi(hash_s) & BOND_MASK;
    } else {
        unixctl_command_reply_error(conn, "bad hash");
        goto out;
    }

    slave = bond_lookup_slave(bond, slave_s);
    if (!slave) {
        unixctl_command_reply_error(conn, "no such slave");
        goto out;
    }

    if (!slave->enabled) {
        unixctl_command_reply_error(conn, "cannot migrate to disabled slave");
        goto out;
    }

    entry = &bond->hash[hash];
    bond->bond_revalidate = true;
    entry->slave = slave;
    unixctl_command_reply(conn, "migrated");

out:
    ovs_rwlock_unlock(&rwlock);
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

    ovs_rwlock_wrlock(&rwlock);
    bond = bond_find(bond_s);
    if (!bond) {
        unixctl_command_reply_error(conn, "no such bond");
        goto out;
    }

    slave = bond_lookup_slave(bond, slave_s);
    if (!slave) {
        unixctl_command_reply_error(conn, "no such slave");
        goto out;
    }

    if (!slave->enabled) {
        unixctl_command_reply_error(conn, "cannot make disabled slave active");
        goto out;
    }

    if (bond->active_slave != slave) {
        bond->bond_revalidate = true;
        bond->active_slave = slave;
        VLOG_INFO("bond %s: active interface is now %s",
                  bond->name, slave->name);
        bond->send_learning_packets = true;
        unixctl_command_reply(conn, "done");
        bond_active_slave_changed(bond);
    } else {
        unixctl_command_reply(conn, "no change");
    }
out:
    ovs_rwlock_unlock(&rwlock);
}

static void
enable_slave(struct unixctl_conn *conn, const char *argv[], bool enable)
{
    const char *bond_s = argv[1];
    const char *slave_s = argv[2];
    struct bond *bond;
    struct bond_slave *slave;

    ovs_rwlock_wrlock(&rwlock);
    bond = bond_find(bond_s);
    if (!bond) {
        unixctl_command_reply_error(conn, "no such bond");
        goto out;
    }

    slave = bond_lookup_slave(bond, slave_s);
    if (!slave) {
        unixctl_command_reply_error(conn, "no such slave");
        goto out;
    }

    bond_enable_slave(slave, enable);
    unixctl_command_reply(conn, enable ? "enabled" : "disabled");

out:
    ovs_rwlock_unlock(&rwlock);
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
    struct eth_addr mac;
    uint8_t hash;
    char *hash_cstr;
    unsigned int vlan;
    uint32_t basis;

    if (vlan_s) {
        if (!ovs_scan(vlan_s, "%u", &vlan)) {
            unixctl_command_reply_error(conn, "invalid vlan");
            return;
        }
    } else {
        vlan = 0;
    }

    if (basis_s) {
        if (!ovs_scan(basis_s, "%"SCNu32, &basis)) {
            unixctl_command_reply_error(conn, "invalid basis");
            return;
        }
    } else {
        basis = 0;
    }

    if (ovs_scan(mac_s, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(mac))) {
        hash = hash_mac(mac, vlan, basis) & BOND_MASK;

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
        size_t hash_len = BOND_BUCKETS * sizeof *bond->hash;

        if (!bond->hash) {
            bond->hash = xmalloc(hash_len);
        }
        memset(bond->hash, 0, hash_len);

        bond->next_rebalance = time_msec() + bond->rebalance_interval;
    } else {
        free(bond->hash);
        bond->hash = NULL;
        /* Remove existing post recirc rules. */
        update_recirc_rules(bond);
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
bond_enable_slave(struct bond_slave *slave, bool enable)
{
    struct bond *bond = slave->bond;

    slave->delay_expires = LLONG_MAX;
    if (enable != slave->enabled) {
        slave->bond->bond_revalidate = true;
        slave->enabled = enable;

        ovs_mutex_lock(&slave->bond->mutex);
        if (enable) {
            ovs_list_insert(&slave->bond->enabled_slaves, &slave->list_node);
        } else {
            bond->send_learning_packets = true;
            ovs_list_remove(&slave->list_node);
        }
        ovs_mutex_unlock(&slave->bond->mutex);

        VLOG_INFO("interface %s: %s", slave->name,
                  slave->enabled ? "enabled" : "disabled");
    }
}

static void
bond_link_status_update(struct bond_slave *slave)
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
        bond_enable_slave(slave, up);
    }
}

static unsigned int
bond_hash(const struct bond *bond, const struct flow *flow, uint16_t vlan)
{
    ovs_assert(bond->balance == BM_TCP || bond->balance == BM_SLB);

    return (bond->balance == BM_TCP
            ? flow_hash_5tuple(flow, bond->basis)
            : hash_mac(flow->dl_src, vlan, bond->basis));
}

static struct bond_entry *
lookup_bond_entry(const struct bond *bond, const struct flow *flow,
                  uint16_t vlan)
{
    return &bond->hash[bond_hash(bond, flow, vlan) & BOND_MASK];
}

/* Selects and returns an enabled slave from the 'enabled_slaves' list
 * in a round-robin fashion.  If the 'enabled_slaves' list is empty,
 * returns NULL. */
static struct bond_slave *
get_enabled_slave(struct bond *bond)
{
    struct ovs_list *node;

    ovs_mutex_lock(&bond->mutex);
    if (ovs_list_is_empty(&bond->enabled_slaves)) {
        ovs_mutex_unlock(&bond->mutex);
        return NULL;
    }

    node = ovs_list_pop_front(&bond->enabled_slaves);
    ovs_list_push_back(&bond->enabled_slaves, node);
    ovs_mutex_unlock(&bond->mutex);

    return CONTAINER_OF(node, struct bond_slave, list_node);
}

static struct bond_slave *
choose_output_slave(const struct bond *bond, const struct flow *flow,
                    struct flow_wildcards *wc, uint16_t vlan)
{
    struct bond_entry *e;
    int balance;

    balance = bond->balance;
    if (bond->lacp_status == LACP_CONFIGURED) {
        /* LACP has been configured on this bond but negotiations were
         * unsuccussful. If lacp_fallback_ab is enabled use active-
         * backup mode else drop all traffic. */
        if (!bond->lacp_fallback_ab) {
            return NULL;
        }
        balance = BM_AB;
    }

    switch (balance) {
    case BM_AB:
        return bond->active_slave;

    case BM_TCP:
        if (bond->lacp_status != LACP_NEGOTIATED) {
            /* Must have LACP negotiations for TCP balanced bonds. */
            return NULL;
        }
        if (wc) {
            flow_mask_hash_fields(flow, wc, NX_HASH_FIELDS_SYMMETRIC_L3L4_UDP);
        }
        /* Fall Through. */
    case BM_SLB:
        if (wc && balance == BM_SLB) {
            flow_mask_hash_fields(flow, wc, NX_HASH_FIELDS_ETH_SRC);
        }
        e = lookup_bond_entry(bond, flow, vlan);
        if (!e->slave || !e->slave->enabled) {
            e->slave = get_enabled_slave(CONST_CAST(struct bond*, bond));
        }
        return e->slave;

    default:
        OVS_NOT_REACHED();
    }
}

static struct bond_slave *
bond_choose_slave(const struct bond *bond)
{
    struct bond_slave *slave, *best;

    /* Find the last active slave. */
    slave = bond_find_slave_by_mac(bond, bond->active_slave_mac);
    if (slave && slave->enabled) {
        return slave;
    }

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
bond_choose_active_slave(struct bond *bond)
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
            bond_enable_slave(bond->active_slave, true);
        }

        bond->send_learning_packets = true;

        if (bond->active_slave != old_active_slave) {
            bond_active_slave_changed(bond);
        }
    } else if (old_active_slave) {
        bond_active_slave_changed(bond);
        VLOG_INFO_RL(&rl, "bond %s: all interfaces disabled", bond->name);
    }
}

/*
 * Return true if bond has unstored active slave change.
 * If return true, 'mac' will store the bond's current active slave's
 * MAC address.  */
bool
bond_get_changed_active_slave(const char *name, struct eth_addr *mac,
                              bool force)
{
    struct bond *bond;

    ovs_rwlock_wrlock(&rwlock);
    bond = bond_find(name);
    if (bond) {
        if (bond->active_slave_changed || force) {
            *mac = bond->active_slave_mac;
            bond->active_slave_changed = false;
            ovs_rwlock_unlock(&rwlock);
            return true;
        }
    }
    ovs_rwlock_unlock(&rwlock);

    return false;
}
