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

/* Priority for internal rules created to handle recirculation */
#define RECIRC_RULE_PRIORITY 20

/* A hash bucket for mapping a flow to a member interface.
 * "struct bond" has an array of BOND_BUCKETS of these. */
struct bond_entry {
    struct bond_member *member; /* Assigned member, NULL if unassigned. */
    uint64_t tx_bytes           /* Count of bytes recently transmitted. */
        OVS_GUARDED_BY(rwlock);
    struct ovs_list list_node;  /* In bond_member's 'entries' list. */

    /* Recirculation.
     *
     * 'pr_rule' is the post-recirculation rule for this entry.
     * 'pr_tx_bytes' is the most recently seen statistics for 'pr_rule', which
     * is used to determine delta (applied to 'tx_bytes' above.) */
    struct rule *pr_rule;
    uint64_t pr_tx_bytes OVS_GUARDED_BY(rwlock);
};

/* A bond member interface, that is, one of the links comprising a bond. */
struct bond_member {
    struct hmap_node hmap_node; /* In struct bond's members hmap. */
    struct ovs_list list_node;  /* In struct bond's enabled_members list. */
    struct bond *bond;          /* The bond that contains this member. */
    void *aux;                  /* Client-provided handle for this member. */

    struct netdev *netdev;      /* Network device, owned by the client. */
    uint64_t change_seq;        /* Tracks changes in 'netdev'. */
    char *name;                 /* Name (a copy of netdev_get_name(netdev)). */
    ofp_port_t  ofp_port;       /* OpenFlow port number. */

    /* Link status. */
    bool enabled;               /* May be chosen for flows? */
    bool may_enable;            /* Client considers this member bondable. */
    bool is_primary;            /* This member is preferred over others. */
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

    /* Members. */
    struct hmap members;

    /* Enabled members.
     *
     * Any reader or writer of 'enabled_members' must hold 'mutex'.
     * (To prevent the bond_member from disappearing they must also hold
     * 'rwlock'.) */
    struct ovs_mutex mutex OVS_ACQ_AFTER(rwlock);
    struct ovs_list enabled_members OVS_GUARDED; /* Of struct bond_members. */

    /* Bonding info. */
    enum bond_mode balance;     /* Balancing mode, one of BM_*. */
    struct bond_member *active_member;
    int updelay, downdelay;     /* Delay before member goes up/down, in ms. */
    enum lacp_status lacp_status; /* Status of LACP negotiations. */
    bool bond_revalidate;       /* True if flows need revalidation. */
    uint32_t basis;             /* Basis for flow hash function. */
    bool use_lb_output_action;  /* Use lb_output action to avoid recirculation.
                                   Applicable only for Balance TCP mode. */
    char *primary;              /* Name of the primary member. */

    /* SLB specific bonding info. */
    struct bond_entry *hash;     /* An array of BOND_BUCKETS elements. */
    int rebalance_interval;      /* Interval between rebalances, in ms. */
    long long int next_rebalance; /* Next rebalancing time. */
    bool send_learning_packets;
    uint32_t recirc_id;          /* Non zero if recirculation can be used.*/
    struct hmap pr_rule_ops;     /* Helps to maintain post recirculation rules.*/

    /* Store active member to OVSDB. */
    bool active_member_changed; /* Set to true whenever the bond changes active
                                 * member. It will be reset to false after
                                 * it is stored into OVSDB */

    /* Interface name may not be persistent across an OS reboot, use
     * MAC address for identifing the active member. */
    struct eth_addr active_member_mac; /* MAC address of the active member. */
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
static struct bond_member *bond_member_lookup(struct bond *, const void *member_)
    OVS_REQ_RDLOCK(rwlock);
static void bond_enable_member(struct bond_member *, bool enable)
    OVS_REQ_WRLOCK(rwlock);
static void bond_link_status_update(struct bond_member *)
    OVS_REQ_WRLOCK(rwlock);
static void bond_choose_active_member(struct bond *)
    OVS_REQ_WRLOCK(rwlock);
static struct bond_entry *lookup_bond_entry(const struct bond *,
                                            const struct flow *,
                                            uint16_t vlan)
    OVS_REQ_RDLOCK(rwlock);
static struct bond_member *get_enabled_member(struct bond *)
    OVS_REQ_RDLOCK(rwlock);
static struct bond_member *choose_output_member(const struct bond *,
                                                const struct flow *,
                                                struct flow_wildcards *,
                                                uint16_t vlan)
    OVS_REQ_RDLOCK(rwlock);
static void update_recirc_rules__(struct bond *);
static bool bond_is_falling_back_to_ab(const struct bond *);
static void bond_add_lb_output_buckets(const struct bond *);
static void bond_del_lb_output_buckets(const struct bond *);

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
 * The caller should register each member on the new bond by calling
 * bond_member_register().  */
struct bond *
bond_create(const struct bond_settings *s, struct ofproto_dpif *ofproto)
{
    struct bond *bond;

    bond = xzalloc(sizeof *bond);
    bond->ofproto = ofproto;
    hmap_init(&bond->members);
    ovs_list_init(&bond->enabled_members);
    ovs_mutex_init(&bond->mutex);
    ovs_refcount_init(&bond->ref_cnt);
    hmap_init(&bond->pr_rule_ops);

    bond->active_member_mac = eth_addr_zero;
    bond->active_member_changed = false;
    bond->primary = NULL;

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
    struct bond_member *member;

    if (!bond || ovs_refcount_unref_relaxed(&bond->ref_cnt) != 1) {
        return;
    }

    ovs_rwlock_wrlock(&rwlock);
    hmap_remove(all_bonds, &bond->hmap_node);
    ovs_rwlock_unlock(&rwlock);

    HMAP_FOR_EACH_POP (member, hmap_node, &bond->members) {
        /* Client owns 'member->netdev'. */
        free(member->name);
        free(member);
    }
    hmap_destroy(&bond->members);

    ovs_mutex_destroy(&bond->mutex);

    /* Free bond resources. Remove existing post recirc rules. */
    if (bond->recirc_id) {
        if (bond_use_lb_output_action(bond)) {
            /* Delete bond buckets from datapath if installed. */
            bond_del_lb_output_buckets(bond);
        }
        recirc_free_id(bond->recirc_id);
        bond->recirc_id = 0;
    }
    free(bond->hash);
    bond->hash = NULL;
    update_recirc_rules__(bond);

    hmap_destroy(&bond->pr_rule_ops);
    free(bond->primary);
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

    HMAP_FOR_EACH(pr_op, hmap_node, &bond->pr_rule_ops) {
        pr_op->op = DEL;
    }

    if (bond->hash && bond->recirc_id) {
        if (bond_use_lb_output_action(bond)) {
            bond_add_lb_output_buckets(bond);
            /* No need to install post recirculation rules as we are using
             * lb_output action with bond buckets.
             */
            return;
        } else {
            for (i = 0; i < BOND_BUCKETS; i++) {
                struct bond_member *member = bond->hash[i].member;

                if (member) {
                    match_init_catchall(&match);
                    match_set_recirc_id(&match, bond->recirc_id);
                    match_set_dp_hash_masked(&match, i, BOND_MASK);

                    add_pr_rule(bond, &match, member->ofp_port,
                                &bond->hash[i].pr_rule);
                }
            }
        }
    }

    ofpbuf_use_stub(&ofpacts, ofpacts_stub, sizeof ofpacts_stub);

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
 * The caller should register each member on 'bond' by calling
 * bond_member_register().  This is optional if none of the members'
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

    if (!nullable_string_is_equal(bond->primary, s->primary)) {
        free(bond->primary);
        bond->primary = nullable_xstrdup(s->primary);
        revalidate = true;
    }

    if (bond->balance != BM_AB) {
        if (!bond->recirc_id) {
            bond->recirc_id = recirc_alloc_id(bond->ofproto);
        }
    } else if (bond->recirc_id) {
        if (bond_use_lb_output_action(bond)) {
            /* Delete bond buckets from datapath if installed. */
            bond_del_lb_output_buckets(bond);
        }
        recirc_free_id(bond->recirc_id);
        bond->recirc_id = 0;
    }
    if (bond->use_lb_output_action != s->use_lb_output_action) {
        if (s->use_lb_output_action &&
            !ovs_lb_output_action_supported(bond->ofproto)) {
            VLOG_WARN("%s: Datapath does not support 'lb_output' action, "
                      "disabled.", bond->name);
        } else {
            bond->use_lb_output_action = s->use_lb_output_action;
            if (!bond->use_lb_output_action) {
                bond_del_lb_output_buckets(bond);
            }
            revalidate = true;
        }
    }

    if (bond->balance == BM_AB || !bond->hash || revalidate) {
        bond_entry_reset(bond);
    }

    ovs_rwlock_unlock(&rwlock);
    return revalidate;
}

static struct bond_member *
bond_find_member_by_mac(const struct bond *bond, const struct eth_addr mac)
{
    struct bond_member *member;

    /* Find the last active member */
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        struct eth_addr member_mac;

        if (netdev_get_etheraddr(member->netdev, &member_mac)) {
            continue;
        }

        if (eth_addr_equals(member_mac, mac)) {
            return member;
        }
    }

    return NULL;
}

static void
bond_active_member_changed(struct bond *bond)
{
    if (bond->active_member) {
        struct eth_addr mac;
        netdev_get_etheraddr(bond->active_member->netdev, &mac);
        bond->active_member_mac = mac;
    } else {
        bond->active_member_mac = eth_addr_zero;
    }
    bond->active_member_changed = true;
    seq_change(connectivity_seq_get());
}

static void
bond_member_set_netdev__(struct bond_member *member, struct netdev *netdev)
    OVS_REQ_WRLOCK(rwlock)
{
    if (member->netdev != netdev) {
        member->netdev = netdev;
        member->change_seq = 0;
    }
}

/* Registers 'member_' as a member interface of 'bond'.  The 'member_' pointer
 * is an arbitrary client-provided pointer that uniquely identifies a member
 * within a bond.  If 'member_' already exists within 'bond' then this function
 * reconfigures the existing member.
 *
 * 'netdev' must be the network device that 'member_' represents.  It is owned
 * by the client, so the client must not close it before either unregistering
 * 'member_' or destroying 'bond'.
 */
void
bond_member_register(struct bond *bond, void *member_,
                     ofp_port_t ofport, struct netdev *netdev)
{
    struct bond_member *member;

    ovs_rwlock_wrlock(&rwlock);
    member = bond_member_lookup(bond, member_);
    if (!member) {
        member = xzalloc(sizeof *member);

        hmap_insert(&bond->members, &member->hmap_node, hash_pointer(member_, 0));
        member->bond = bond;
        member->aux = member_;
        member->ofp_port = ofport;
        member->delay_expires = LLONG_MAX;
        member->name = xstrdup(netdev_get_name(netdev));
        bond->bond_revalidate = true;

        member->enabled = false;
        bond_enable_member(member, netdev_get_carrier(netdev));
    }

    bond_member_set_netdev__(member, netdev);

    free(member->name);
    member->name = xstrdup(netdev_get_name(netdev));
    if (bond->primary && !strcmp(bond->primary, member->name)) {
        member->is_primary = true;
    } else {
        member->is_primary = false;
    }
    ovs_rwlock_unlock(&rwlock);
}

/* Updates the network device to be used with 'member_' to 'netdev'.
 *
 * This is useful if the caller closes and re-opens the network device
 * registered with bond_member_register() but doesn't need to change anything
 * else. */
void
bond_member_set_netdev(struct bond *bond, void *member_, struct netdev *netdev)
{
    struct bond_member *member;

    ovs_rwlock_wrlock(&rwlock);
    member = bond_member_lookup(bond, member_);
    if (member) {
        bond_member_set_netdev__(member, netdev);
    }
    ovs_rwlock_unlock(&rwlock);
}

/* Unregisters 'member_' from 'bond'.  If 'bond' does not contain such a
 * member then this function has no effect.
 *
 * Unregistering a member invalidates all flows. */
void
bond_member_unregister(struct bond *bond, const void *member_)
{
    struct bond_member *member;
    bool del_active;

    ovs_rwlock_wrlock(&rwlock);
    member = bond_member_lookup(bond, member_);
    if (!member) {
        goto out;
    }

    bond->bond_revalidate = true;
    bond_enable_member(member, false);

    del_active = bond->active_member == member;
    if (bond->hash) {
        struct bond_entry *e;
        for (e = bond->hash; e <= &bond->hash[BOND_MASK]; e++) {
            if (e->member == member) {
                e->member = NULL;
            }
        }
    }

    free(member->name);

    hmap_remove(&bond->members, &member->hmap_node);
    /* Client owns 'member->netdev'. */
    free(member);

    if (del_active) {
        bond_choose_active_member(bond);
        bond->send_learning_packets = true;
    }
out:
    ovs_rwlock_unlock(&rwlock);
}

/* Should be called on each member in 'bond' before bond_run() to indicate
 * whether or not 'member_' may be enabled. This function is intended to allow
 * other protocols to have some impact on bonding decisions.  For example LACP
 * or high level link monitoring protocols may decide that a given member
 * should not be able to send traffic. */
void
bond_member_set_may_enable(struct bond *bond, void *member_, bool may_enable)
{
    ovs_rwlock_wrlock(&rwlock);
    bond_member_lookup(bond, member_)->may_enable = may_enable;
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
    struct bond_member *member, *primary;
    bool revalidate;

    ovs_rwlock_wrlock(&rwlock);
    if (bond->lacp_status != lacp_status) {
        bond->lacp_status = lacp_status;
        bond->bond_revalidate = true;

        /* Change in LACP status can affect whether the bond is falling back to
         * active-backup.  Make sure to create or destroy buckets if
         * necessary.  */
        if (bond_is_falling_back_to_ab(bond) || !bond->hash) {
            bond_entry_reset(bond);
        }
    }

    /* Enable members based on link status and LACP feedback. */
    primary = NULL;
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        bond_link_status_update(member);
        member->change_seq = seq_read(connectivity_seq_get());

        /* Discover if there is an active member marked 'primary'. */
        if (bond->balance == BM_AB && member->is_primary && member->enabled) {
            primary = member;
        }
    }

    if (!bond->active_member || !bond->active_member->enabled ||
        (primary && bond->active_member != primary)) {
        bond_choose_active_member(bond);
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
    struct bond_member *member;

    ovs_rwlock_rdlock(&rwlock);
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        if (member->delay_expires != LLONG_MAX) {
            poll_timer_wait_until(member->delay_expires);
        }

        seq_wait(connectivity_seq_get(), member->change_seq);
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
        && bond->active_member;
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
    struct bond_member *member;
    struct dp_packet *packet;
    struct flow flow;

    ovs_rwlock_rdlock(&rwlock);
    ovs_assert(may_send_learning_packets(bond));
    memset(&flow, 0, sizeof flow);
    flow.dl_src = eth_src;
    member = choose_output_member(bond, &flow, NULL, vlan);

    packet = dp_packet_new(0);
    compose_rarp(packet, eth_src);
    if (vlan) {
        eth_push_vlan(packet, htons(ETH_TYPE_VLAN), htons(vlan));
    }

    *port_aux = member->aux;
    ovs_rwlock_unlock(&rwlock);
    return packet;
}


static bool
bond_is_falling_back_to_ab(const struct bond *bond)
{
    return (bond->lacp_fallback_ab
            && (bond->balance == BM_SLB || bond->balance == BM_TCP)
            && bond->lacp_status == LACP_CONFIGURED);
}

/* Checks whether a packet that arrived on 'member_' within 'bond', with an
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
bond_check_admissibility(struct bond *bond, const void *member_,
                         const struct eth_addr eth_dst)
{
    enum bond_verdict verdict = BV_DROP;
    struct bond_member *member;
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    ovs_rwlock_rdlock(&rwlock);
    member = bond_member_lookup(bond, member_);
    if (!member) {
        goto out;
    }

    /* LACP bonds have very loose admissibility restrictions because we can
     * assume the remote switch is aware of the bond and will "do the right
     * thing".  However, as a precaution we drop packets on disabled members
     * because no correctly implemented partner switch should be sending
     * packets to them.
     *
     * If LACP is configured, but LACP negotiations have been unsuccessful, we
     * drop all incoming traffic except if lacp_fallback_ab is enabled. */
    switch (bond->lacp_status) {
    case LACP_NEGOTIATED:
        /* To reduce packet-drops due to delay in enabling of member (post
         * LACP-SYNC), from main thread, check for may_enable as well.
         * When may_enable is TRUE, it means LACP is UP and waiting for the
         * main thread to run LACP state machine and enable the member. */
        verdict = (member->enabled || member->may_enable) ? BV_ACCEPT : BV_DROP;
        if (!member->enabled && member->may_enable) {
            VLOG_DBG_RL(&rl, "bond %s: member %s: "
                        "main thread has not yet enabled member",
                         bond->name, bond->active_member->name);
        }
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

    /* Drop all multicast packets on inactive members. */
    if (eth_addr_is_multicast(eth_dst)) {
        if (bond->active_member != member) {
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
        /* Drop all packets which arrive on backup members.  This is similar to
         * how Linux bonding handles active-backup bonds. */
        if (bond->active_member != member) {
            VLOG_DBG_RL(&rl, "active-backup bond received packet on backup"
                        " member (%s) destined for " ETH_ADDR_FMT,
                        member->name, ETH_ADDR_ARGS(eth_dst));
            goto out;
        }
        verdict = BV_ACCEPT;
        goto out;

    case BM_SLB:
        /* Drop all packets for which we have learned a different input port,
         * because we probably sent the packet on one member and got it back on
         * the other.  Gratuitous ARP packets are an exception to this rule:
         * the host has moved to another switch.  The exception to the
         * exception is if we locked the learning table to avoid reflections on
         * bond members. */
        verdict = BV_DROP_IF_MOVED;
        goto out;
    }

    OVS_NOT_REACHED();
out:
    if (member && (verdict != BV_ACCEPT)) {
        VLOG_DBG_RL(&rl, "member (%s): "
                    "Admissibility verdict is to drop pkt %s."
                    "active member: %s, may_enable: %s enable: %s "
                    "LACP status:%d",
                    member->name,
                    (verdict == BV_DROP_IF_MOVED) ?
                        "as different port is learned" : "",
                    (bond->active_member == member) ? "true" : "false",
                    member->may_enable ? "true" : "false",
                    member->enabled ? "true" : "false",
                    bond->lacp_status);
    }

    ovs_rwlock_unlock(&rwlock);
    return verdict;

}

/* Returns the member (registered on 'bond' by bond_member_register()) to which
 * a packet with the given 'flow' and 'vlan' should be forwarded.  Returns NULL
 * if the packet should be dropped because no members are enabled.
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
bond_choose_output_member(struct bond *bond, const struct flow *flow,
                          struct flow_wildcards *wc, uint16_t vlan)
{
    struct bond_member *member;
    void *aux;

    ovs_rwlock_rdlock(&rwlock);
    member = choose_output_member(bond, flow, wc, vlan);
    aux = member ? member->aux : NULL;
    ovs_rwlock_unlock(&rwlock);

    return aux;
}

/* Recirculation. */
static void
bond_entry_account(struct bond_entry *entry, uint64_t rule_tx_bytes)
    OVS_REQ_WRLOCK(rwlock)
{
    if (entry->member) {
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
    uint64_t n_bytes[BOND_BUCKETS];
    bool use_lb_output_action = bond_use_lb_output_action(bond);

    if (use_lb_output_action) {
        /* Retrieve bond stats from datapath. */
        dpif_bond_stats_get(bond->ofproto->backer->dpif,
                            bond->recirc_id, n_bytes);
    }

    for (i=0; i<=BOND_MASK; i++) {
        struct bond_entry *entry = &bond->hash[i];
        struct rule *rule = entry->pr_rule;
        struct pkt_stats stats;

        if (use_lb_output_action) {
            stats.n_bytes = n_bytes[i];
        } else if (rule) {
            long long int used OVS_UNUSED;

            rule->ofproto->ofproto_class->rule_get_stats(
                rule, &stats, &used);
        } else {
            continue;
        }
        bond_entry_account(entry, stats.n_bytes);
    }
}

static bool
bond_may_recirc(const struct bond *bond)
{
    return (bond->balance == BM_TCP && bond->recirc_id
            && !bond_is_falling_back_to_ab(bond));
}

static void
bond_update_post_recirc_rules__(struct bond* bond, const bool force)
    OVS_REQ_WRLOCK(rwlock)
{
   struct bond_entry *e;
   bool update_rules = force;  /* Always update rules if caller forces it. */

   /* Make sure all bond entries are populated */
   for (e = bond->hash; e <= &bond->hash[BOND_MASK]; e++) {
       if (!e->member || !e->member->enabled) {
            update_rules = true;
            e->member = CONTAINER_OF(hmap_random_node(&bond->members),
                                     struct bond_member, hmap_node);
            if (!e->member->enabled) {
                e->member = bond->active_member;
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
        && (bond->balance == BM_SLB || bond->balance == BM_TCP)
        && !(bond->lacp_fallback_ab && bond->lacp_status == LACP_CONFIGURED);
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

static struct bond_member *
bond_member_from_bal_node(struct ovs_list *bal) OVS_REQ_RDLOCK(rwlock)
{
    return CONTAINER_OF(bal, struct bond_member, bal_node);
}

static void
log_bals(struct bond *bond, const struct ovs_list *bals)
    OVS_REQ_RDLOCK(rwlock)
{
    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;
        const struct bond_member *member;

        LIST_FOR_EACH (member, bal_node, bals) {
            if (ds.length) {
                ds_put_char(&ds, ',');
            }
            ds_put_format(&ds, " %s %"PRIu64"kB",
                          member->name, member->tx_bytes / 1024);

            if (!member->enabled) {
                ds_put_cstr(&ds, " (disabled)");
            }
            if (!ovs_list_is_empty(&member->entries)) {
                struct bond_entry *e;

                ds_put_cstr(&ds, " (");
                LIST_FOR_EACH (e, list_node, &member->entries) {
                    if (&e->list_node != ovs_list_front(&member->entries)) {
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

/* Shifts 'hash' from its current member to 'to'. */
static void
bond_shift_load(struct bond_entry *hash, struct bond_member *to)
    OVS_REQ_WRLOCK(rwlock)
{
    struct bond_member *from = hash->member;
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
    hash->member = to;
    bond->bond_revalidate = true;
}

/* Picks and returns a bond_entry to migrate from 'from' (the most heavily
 * loaded bond member) to a bond member that has 'to_tx_bytes' bytes of load,
 * given that doing so must decrease the ratio of the load on the two members
 * by at least 0.1.  Returns NULL if there is no appropriate entry.
 *
 * The list of entries isn't sorted.  I don't know of a reason to prefer to
 * shift away small hashes or large hashes. */
static struct bond_entry *
choose_entry_to_migrate(const struct bond_member *from, uint64_t to_tx_bytes)
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

/* Inserts 'member' into 'bals' so that descending order of 'tx_bytes' is
 * maintained. */
static void
insert_bal(struct ovs_list *bals, struct bond_member *member)
{
    struct bond_member *pos;

    LIST_FOR_EACH (pos, bal_node, bals) {
        if (member->tx_bytes > pos->tx_bytes) {
            break;
        }
    }
    ovs_list_insert(&pos->bal_node, &member->bal_node);
}

/* Removes 'member' from its current list and then inserts it into 'bals' so
 * that descending order of 'tx_bytes' is maintained. */
static void
reinsert_bal(struct ovs_list *bals, struct bond_member *member)
{
    ovs_list_remove(&member->bal_node);
    insert_bal(bals, member);
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
    struct bond_member *member;
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

    /* Add each bond_entry to its member's 'entries' list.
     * Compute each member's tx_bytes as the sum of its entries' tx_bytes. */
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        member->tx_bytes = 0;
        ovs_list_init(&member->entries);
    }
    for (e = &bond->hash[0]; e <= &bond->hash[BOND_MASK]; e++) {
        if (e->member && e->tx_bytes) {
            e->member->tx_bytes += e->tx_bytes;
            ovs_list_push_back(&e->member->entries, &e->list_node);
        }
    }

    /* Add enabled members to 'bals' in descending order of tx_bytes.
     *
     * XXX This is O(n**2) in the number of members but it could be O(n lg n)
     * with a proper list sort algorithm. */
    ovs_list_init(&bals);
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        if (member->enabled) {
            insert_bal(&bals, member);
        }
    }
    log_bals(bond, &bals);

    /* Shift load from the most-loaded members to the least-loaded members. */
    while (!ovs_list_is_short(&bals)) {
        struct bond_member *from
            = bond_member_from_bal_node(ovs_list_front(&bals));
        struct bond_member *to
            = bond_member_from_bal_node(ovs_list_back(&bals));
        uint64_t overload;

        overload = from->tx_bytes - to->tx_bytes;
        if (overload < to->tx_bytes >> 5 || overload < 100000) {
            /* The extra load on 'from' (and all less-loaded members), compared
             * to that of 'to' (the least-loaded member), is less than ~3%, or
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
             * 'e' to be migrated to another member in this rebalancing run, and
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

static struct bond_member *
bond_lookup_member(struct bond *bond, const char *member_name)
{
    struct bond_member *member;

    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        if (!strcmp(member->name, member_name)) {
            return member;
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

    ds_put_cstr(&ds, "bond\ttype\trecircID\tmembers\n");

    ovs_rwlock_rdlock(&rwlock);
    HMAP_FOR_EACH (bond, hmap_node, all_bonds) {
        const struct bond_member *member;
        size_t i;

        ds_put_format(&ds, "%s\t%s\t%d\t", bond->name,
                      bond_mode_to_string(bond->balance), bond->recirc_id);

        i = 0;
        HMAP_FOR_EACH (member, hmap_node, &bond->members) {
            if (i++ > 0) {
                ds_put_cstr(&ds, ", ");
            }
            ds_put_cstr(&ds, member->name);
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
    struct shash member_shash = SHASH_INITIALIZER(&member_shash);
    const struct shash_node **sorted_members = NULL;
    const struct bond_member *member;
    bool use_lb_output_action;
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

    use_lb_output_action = bond_use_lb_output_action(bond);
    ds_put_format(ds, "lb_output action: %s, bond-id: %d\n",
                  use_lb_output_action ? "enabled" : "disabled",
                  use_lb_output_action ? recirc_id : -1);

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

    bool found_primary = false;
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        if (member->is_primary) {
            found_primary = true;
        }
        shash_add(&member_shash, member->name, member);
    }

    ds_put_format(ds, "active-backup primary: %s%s\n",
                  bond->primary ? bond->primary : "<none>",
                  (!found_primary && bond->primary)
                  ? " (no such member)" : "");

    member = bond_find_member_by_mac(bond, bond->active_member_mac);
    ds_put_cstr(ds, "active member mac: ");
    ds_put_format(ds, ETH_ADDR_FMT, ETH_ADDR_ARGS(bond->active_member_mac));
    ds_put_format(ds, "(%s)\n", member ? member->name : "none");

    sorted_members = shash_sort(&member_shash);
    for (i = 0; i < shash_count(&member_shash); i++) {
        struct bond_entry *be;

        member = sorted_members[i]->data;

        /* Basic info. */
        ds_put_format(ds, "\nmember %s: %s\n",
                      member->name, member->enabled ? "enabled" : "disabled");
        if (member == bond->active_member) {
            ds_put_cstr(ds, "  active member\n");
        }
        if (member->delay_expires != LLONG_MAX) {
            ds_put_format(ds, "  %s expires in %lld ms\n",
                          member->enabled ? "downdelay" : "updelay",
                          member->delay_expires - time_msec());
        }

        ds_put_format(ds, "  may_enable: %s\n",
                      member->may_enable ? "true" : "false");

        if (!bond_is_balanced(bond)) {
            continue;
        }

        /* Hashes. */
        for (be = bond->hash; be <= &bond->hash[BOND_MASK]; be++) {
            int hash = be - bond->hash;
            uint64_t be_tx_k;

            if (be->member != member) {
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
    shash_destroy(&member_shash);
    free(sorted_members);
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
    const char *member_s = argv[3];
    struct bond *bond;
    struct bond_member *member;
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

    member = bond_lookup_member(bond, member_s);
    if (!member) {
        unixctl_command_reply_error(conn, "no such member");
        goto out;
    }

    if (!member->enabled) {
        unixctl_command_reply_error(conn,
                                    "cannot migrate to disabled member");
        goto out;
    }

    entry = &bond->hash[hash];
    bond->bond_revalidate = true;
    entry->member = member;
    unixctl_command_reply(conn, "migrated");

out:
    ovs_rwlock_unlock(&rwlock);
}

static void
bond_unixctl_set_active_member(struct unixctl_conn *conn,
                               int argc OVS_UNUSED, const char *argv[],
                               void *aux OVS_UNUSED)
{
    const char *bond_s = argv[1];
    const char *member_s = argv[2];
    struct bond *bond;
    struct bond_member *member;

    ovs_rwlock_wrlock(&rwlock);
    bond = bond_find(bond_s);
    if (!bond) {
        unixctl_command_reply_error(conn, "no such bond");
        goto out;
    }

    member = bond_lookup_member(bond, member_s);
    if (!member) {
        unixctl_command_reply_error(conn, "no such member");
        goto out;
    }

    if (!member->enabled) {
        unixctl_command_reply_error(conn,
                                    "cannot make disabled member active");
        goto out;
    }

    if (bond->active_member != member) {
        bond->bond_revalidate = true;
        bond->active_member = member;
        VLOG_INFO("bond %s: active member is now %s",
                  bond->name, member->name);
        bond->send_learning_packets = true;
        unixctl_command_reply(conn, "done");
        bond_active_member_changed(bond);
    } else {
        unixctl_command_reply(conn, "no change");
    }
out:
    ovs_rwlock_unlock(&rwlock);
}

static void
enable_member(struct unixctl_conn *conn, const char *argv[], bool enable)
{
    const char *bond_s = argv[1];
    const char *member_s = argv[2];
    struct bond *bond;
    struct bond_member *member;

    ovs_rwlock_wrlock(&rwlock);
    bond = bond_find(bond_s);
    if (!bond) {
        unixctl_command_reply_error(conn, "no such bond");
        goto out;
    }

    member = bond_lookup_member(bond, member_s);
    if (!member) {
        unixctl_command_reply_error(conn, "no such member");
        goto out;
    }

    bond_enable_member(member, enable);
    unixctl_command_reply(conn, enable ? "enabled" : "disabled");

out:
    ovs_rwlock_unlock(&rwlock);
}

static void
bond_unixctl_enable_member(struct unixctl_conn *conn,
                           int argc OVS_UNUSED, const char *argv[],
                           void *aux OVS_UNUSED)
{
    enable_member(conn, argv, true);
}

static void
bond_unixctl_disable_member(struct unixctl_conn *conn,
                            int argc OVS_UNUSED, const char *argv[],
                            void *aux OVS_UNUSED)
{
    enable_member(conn, argv, false);
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
    unixctl_command_register("bond/migrate", "port hash member", 3, 3,
                             bond_unixctl_migrate, NULL);
    unixctl_command_register("bond/set-active-member", "port member", 2, 2,
                             bond_unixctl_set_active_member, NULL);
    unixctl_command_register("bond/enable-member", "port member", 2, 2,
                             bond_unixctl_enable_member, NULL);
    unixctl_command_register("bond/disable-member", "port member", 2, 2,
                             bond_unixctl_disable_member, NULL);
    unixctl_command_register("bond/hash", "mac [vlan] [basis]", 1, 3,
                             bond_unixctl_hash, NULL);

    /* Backward-compatibility command names. */
    unixctl_command_register("bond/set-active-slave", NULL, 2, 2,
                             bond_unixctl_set_active_member, NULL);
    unixctl_command_register("bond/enable-slave", NULL, 2, 2,
                             bond_unixctl_enable_member, NULL);
    unixctl_command_register("bond/disable-slave", NULL, 2, 2,
                             bond_unixctl_disable_member, NULL);
}

static void
bond_entry_reset(struct bond *bond)
{
    if (bond->balance != BM_AB && !bond_is_falling_back_to_ab(bond)) {
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

static struct bond_member *
bond_member_lookup(struct bond *bond, const void *member_)
{
    struct bond_member *member;

    HMAP_FOR_EACH_IN_BUCKET (member, hmap_node, hash_pointer(member_, 0),
                             &bond->members) {
        if (member->aux == member_) {
            return member;
        }
    }

    return NULL;
}

static void
bond_enable_member(struct bond_member *member, bool enable)
{
    struct bond *bond = member->bond;

    member->delay_expires = LLONG_MAX;
    if (enable != member->enabled) {
        member->bond->bond_revalidate = true;
        member->enabled = enable;

        ovs_mutex_lock(&member->bond->mutex);
        if (enable) {
            ovs_list_insert(&member->bond->enabled_members, &member->list_node);
        } else {
            bond->send_learning_packets = true;
            ovs_list_remove(&member->list_node);
        }
        ovs_mutex_unlock(&member->bond->mutex);

        VLOG_INFO("member %s: %s", member->name,
                  member->enabled ? "enabled" : "disabled");
    }
}

static void
bond_link_status_update(struct bond_member *member)
{
    struct bond *bond = member->bond;
    bool up;

    up = netdev_get_carrier(member->netdev) && member->may_enable;
    if ((up == member->enabled) != (member->delay_expires == LLONG_MAX)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
        VLOG_INFO_RL(&rl, "member %s: link state %s",
                     member->name, up ? "up" : "down");
        if (up == member->enabled) {
            member->delay_expires = LLONG_MAX;
            VLOG_INFO_RL(&rl, "member %s: will not be %s",
                         member->name, up ? "disabled" : "enabled");
        } else {
            int delay = up ? bond->updelay : bond->downdelay;
            member->delay_expires = time_msec() + delay;
            if (delay) {
                VLOG_INFO_RL(&rl, "member %s: will be %s if it stays %s "
                             "for %d ms",
                             member->name,
                             up ? "enabled" : "disabled",
                             up ? "up" : "down",
                             delay);
            }
        }
    }

    if (time_msec() >= member->delay_expires) {
        bond_enable_member(member, up);
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

/* Selects and returns an enabled member from the 'enabled_members' list
 * in a round-robin fashion.  If the 'enabled_members' list is empty,
 * returns NULL. */
static struct bond_member *
get_enabled_member(struct bond *bond)
{
    struct ovs_list *node;

    ovs_mutex_lock(&bond->mutex);
    if (ovs_list_is_empty(&bond->enabled_members)) {
        ovs_mutex_unlock(&bond->mutex);
        return NULL;
    }

    node = ovs_list_pop_front(&bond->enabled_members);
    ovs_list_push_back(&bond->enabled_members, node);
    ovs_mutex_unlock(&bond->mutex);

    return CONTAINER_OF(node, struct bond_member, list_node);
}

static struct bond_member *
choose_output_member(const struct bond *bond, const struct flow *flow,
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
        return bond->active_member;

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
        if (!e->member || !e->member->enabled) {
            e->member = get_enabled_member(CONST_CAST(struct bond *, bond));
        }
        return e->member;

    default:
        OVS_NOT_REACHED();
    }
}

static struct bond_member *
bond_choose_member(const struct bond *bond)
{
    struct bond_member *member, *best;

    /* If there's a primary and it's active, return that. */
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        if (member->is_primary && member->enabled) {
            return member;
        }
    }

    /* Find the last active member. */
    member = bond_find_member_by_mac(bond, bond->active_member_mac);
    if (member && member->enabled) {
        return member;
    }

    /* Find an enabled member. */
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        if (member->enabled) {
            return member;
        }
    }

    /* All members are disabled.  Find an member that will be enabled
     * after its updelay expires.  */
    best = NULL;
    HMAP_FOR_EACH (member, hmap_node, &bond->members) {
        if (member->delay_expires != LLONG_MAX
            && member->may_enable
            && (!best || member->delay_expires < best->delay_expires)) {
            best = member;
        }
    }
    return best;
}

static void
bond_choose_active_member(struct bond *bond)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct bond_member *old_active_member = bond->active_member;

    bond->active_member = bond_choose_member(bond);
    if (bond->active_member) {
        if (bond->active_member->enabled) {
            VLOG_INFO_RL(&rl, "bond %s: active member is now %s",
                         bond->name, bond->active_member->name);
        } else {
            VLOG_INFO_RL(&rl, "bond %s: active member is now %s, skipping "
                         "remaining %lld ms updelay (since no member was "
                         "enabled)", bond->name, bond->active_member->name,
                         bond->active_member->delay_expires - time_msec());
            bond_enable_member(bond->active_member, true);
        }

        bond->send_learning_packets = true;

        if (bond->active_member != old_active_member) {
            bond_active_member_changed(bond);
        }
    } else if (old_active_member) {
        bond_active_member_changed(bond);
        VLOG_INFO_RL(&rl, "bond %s: all members disabled", bond->name);
    }
}

/*
 * Return true if bond has unstored active member change.
 * If return true, 'mac' will store the bond's current active member's
 * MAC address.  */
bool
bond_get_changed_active_member(const char *name, struct eth_addr *mac,
                              bool force)
{
    struct bond *bond;

    ovs_rwlock_wrlock(&rwlock);
    bond = bond_find(name);
    if (bond) {
        if (bond->active_member_changed || force) {
            *mac = bond->active_member_mac;
            bond->active_member_changed = false;
            ovs_rwlock_unlock(&rwlock);
            return true;
        }
    }
    ovs_rwlock_unlock(&rwlock);

    return false;
}

bool
bond_use_lb_output_action(const struct bond *bond)
{
    return bond_may_recirc(bond) && bond->use_lb_output_action;
}

static void
bond_add_lb_output_buckets(const struct bond *bond)
{
    ofp_port_t member_map[BOND_BUCKETS];

    for (int i = 0; i < BOND_BUCKETS; i++) {
        struct bond_member *member = bond->hash[i].member;

        if (member) {
            member_map[i] = member->ofp_port;
        } else {
            member_map[i] = OFPP_NONE;
        }
    }
    ofproto_dpif_add_lb_output_buckets(bond->ofproto, bond->recirc_id,
                                       member_map);
}

static void
bond_del_lb_output_buckets(const struct bond *bond)
{
    ofproto_dpif_delete_lb_output_buckets(bond->ofproto,
                                          bond->recirc_id);
}
