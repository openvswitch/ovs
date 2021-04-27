/*
 * Copyright (c) 2020 VMware, Inc.
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

#include <errno.h>
#include "conntrack-private.h"
#include "conntrack-tp.h"
#include "ct-dpif.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(conntrack_tp);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

static const char *ct_timeout_str[] = {
#define CT_TIMEOUT(NAME) #NAME,
    CT_TIMEOUTS
#undef CT_TIMEOUT
};

/* Default timeout policy in seconds. */
static unsigned int ct_dpif_netdev_tp_def[] = {
    [CT_DPIF_TP_ATTR_TCP_SYN_SENT] = 30,
    [CT_DPIF_TP_ATTR_TCP_SYN_RECV] = 30,
    [CT_DPIF_TP_ATTR_TCP_ESTABLISHED] = 24 * 60 * 60,
    [CT_DPIF_TP_ATTR_TCP_FIN_WAIT] = 15 * 60,
    [CT_DPIF_TP_ATTR_TCP_TIME_WAIT] = 45,
    [CT_DPIF_TP_ATTR_TCP_CLOSE] = 30,
    [CT_DPIF_TP_ATTR_UDP_FIRST] = 60,
    [CT_DPIF_TP_ATTR_UDP_SINGLE] = 60,
    [CT_DPIF_TP_ATTR_UDP_MULTIPLE] = 30,
    [CT_DPIF_TP_ATTR_ICMP_FIRST] = 60,
    [CT_DPIF_TP_ATTR_ICMP_REPLY] = 30,
};

static struct timeout_policy *
timeout_policy_lookup(struct conntrack *ct, int32_t tp_id)
    OVS_REQUIRES(ct->ct_lock)
{
    struct timeout_policy *tp;
    uint32_t hash;

    hash = hash_int(tp_id, ct->hash_basis);
    HMAP_FOR_EACH_IN_BUCKET (tp, node, hash, &ct->timeout_policies) {
        if (tp->policy.id == tp_id) {
            return tp;
        }
    }
    return NULL;
}

struct timeout_policy *
timeout_policy_get(struct conntrack *ct, int32_t tp_id)
{
    struct timeout_policy *tp;

    ovs_mutex_lock(&ct->ct_lock);
    tp = timeout_policy_lookup(ct, tp_id);
    if (!tp) {
        ovs_mutex_unlock(&ct->ct_lock);
        return NULL;
    }

    ovs_mutex_unlock(&ct->ct_lock);
    return tp;
}

static void
update_existing_tp(struct timeout_policy *tp_dst,
                   const struct timeout_policy *tp_src)
{
    struct ct_dpif_timeout_policy *dst;
    const struct ct_dpif_timeout_policy *src;
    int i;

    dst = &tp_dst->policy;
    src = &tp_src->policy;

    /* Set the value and present bit to dst if present
     * bit in src is set.
     */
    for (i = 0; i < ARRAY_SIZE(dst->attrs); i++) {
        if (src->present & (1 << i)) {
            dst->attrs[i] = src->attrs[i];
            dst->present |= (1 << i);
        }
    }
}

static void
init_default_tp(struct timeout_policy *tp, uint32_t tp_id)
{
    tp->policy.id = tp_id;
    /* Initialize the timeout value to default, but not
     * setting the present bit.
     */
    tp->policy.present = 0;
    memcpy(tp->policy.attrs, ct_dpif_netdev_tp_def,
           sizeof tp->policy.attrs);
}

static void
timeout_policy_create(struct conntrack *ct,
                      struct timeout_policy *new_tp)
    OVS_REQUIRES(ct->ct_lock)
{
    uint32_t tp_id = new_tp->policy.id;
    struct timeout_policy *tp;
    uint32_t hash;

    tp = xzalloc(sizeof *tp);
    init_default_tp(tp, tp_id);
    update_existing_tp(tp, new_tp);
    hash = hash_int(tp_id, ct->hash_basis);
    hmap_insert(&ct->timeout_policies, &tp->node, hash);
}

static void
timeout_policy_clean(struct conntrack *ct, struct timeout_policy *tp)
    OVS_REQUIRES(ct->ct_lock)
{
    hmap_remove(&ct->timeout_policies, &tp->node);
    free(tp);
}

static int
timeout_policy_delete__(struct conntrack *ct, uint32_t tp_id)
    OVS_REQUIRES(ct->ct_lock)
{
    int err = 0;
    struct timeout_policy *tp = timeout_policy_lookup(ct, tp_id);

    if (tp) {
        timeout_policy_clean(ct, tp);
    } else {
        VLOG_WARN_RL(&rl, "Failed to delete a non-existent timeout "
                     "policy: id=%d", tp_id);
        err = ENOENT;
    }
    return err;
}

int
timeout_policy_delete(struct conntrack *ct, uint32_t tp_id)
{
    int err;

    ovs_mutex_lock(&ct->ct_lock);
    err = timeout_policy_delete__(ct, tp_id);
    ovs_mutex_unlock(&ct->ct_lock);
    return err;
}

void
timeout_policy_init(struct conntrack *ct)
    OVS_REQUIRES(ct->ct_lock)
{
    struct timeout_policy tp;

    hmap_init(&ct->timeout_policies);

    /* Create default timeout policy. */
    memset(&tp, 0, sizeof tp);
    tp.policy.id = DEFAULT_TP_ID;
    timeout_policy_create(ct, &tp);
}

int
timeout_policy_update(struct conntrack *ct,
                      struct timeout_policy *new_tp)
{
    int err = 0;
    uint32_t tp_id = new_tp->policy.id;

    ovs_mutex_lock(&ct->ct_lock);
    struct timeout_policy *tp = timeout_policy_lookup(ct, tp_id);
    if (tp) {
        err = timeout_policy_delete__(ct, tp_id);
    }
    timeout_policy_create(ct, new_tp);
    ovs_mutex_unlock(&ct->ct_lock);
    return err;
}

static enum ct_dpif_tp_attr
tm_to_ct_dpif_tp(enum ct_timeout tm)
{
    switch (tm) {
    case CT_TM_TCP_FIRST_PACKET:
        return CT_DPIF_TP_ATTR_TCP_SYN_SENT;
    case CT_TM_TCP_OPENING:
        return CT_DPIF_TP_ATTR_TCP_SYN_RECV;
    case CT_TM_TCP_ESTABLISHED:
        return CT_DPIF_TP_ATTR_TCP_ESTABLISHED;
    case CT_TM_TCP_CLOSING:
        return CT_DPIF_TP_ATTR_TCP_FIN_WAIT;
    case CT_TM_TCP_FIN_WAIT:
        return CT_DPIF_TP_ATTR_TCP_TIME_WAIT;
    case CT_TM_TCP_CLOSED:
        return CT_DPIF_TP_ATTR_TCP_CLOSE;
    case CT_TM_OTHER_FIRST:
        return CT_DPIF_TP_ATTR_UDP_FIRST;
    case CT_TM_OTHER_BIDIR:
        return CT_DPIF_TP_ATTR_UDP_MULTIPLE;
    case CT_TM_OTHER_MULTIPLE:
        return CT_DPIF_TP_ATTR_UDP_SINGLE;
    case CT_TM_ICMP_FIRST:
        return CT_DPIF_TP_ATTR_ICMP_FIRST;
    case CT_TM_ICMP_REPLY:
        return CT_DPIF_TP_ATTR_ICMP_REPLY;
    case N_CT_TM:
    default:
        OVS_NOT_REACHED();
        break;
    }
    OVS_NOT_REACHED();
    return CT_DPIF_TP_ATTR_MAX;
}

static void
conn_update_expiration__(struct conntrack *ct, struct conn *conn,
                         enum ct_timeout tm, long long now,
                         uint32_t tp_value)
    OVS_REQUIRES(conn->lock)
{
    ovs_mutex_unlock(&conn->lock);

    ovs_mutex_lock(&ct->ct_lock);
    ovs_mutex_lock(&conn->lock);
    if (!conn->cleaned) {
        conn->expiration = now + tp_value * 1000;
        ovs_list_remove(&conn->exp_node);
        ovs_list_push_back(&ct->exp_lists[tm], &conn->exp_node);
    }
    ovs_mutex_unlock(&conn->lock);
    ovs_mutex_unlock(&ct->ct_lock);

    ovs_mutex_lock(&conn->lock);
}

/* The conn entry lock must be held on entry and exit. */
void
conn_update_expiration(struct conntrack *ct, struct conn *conn,
                       enum ct_timeout tm, long long now)
    OVS_REQUIRES(conn->lock)
{
    struct timeout_policy *tp;
    uint32_t val;

    ovs_mutex_unlock(&conn->lock);

    ovs_mutex_lock(&ct->ct_lock);
    ovs_mutex_lock(&conn->lock);
    tp = timeout_policy_lookup(ct, conn->tp_id);
    if (tp) {
        val = tp->policy.attrs[tm_to_ct_dpif_tp(tm)];
    } else {
        val = ct_dpif_netdev_tp_def[tm_to_ct_dpif_tp(tm)];
    }
    ovs_mutex_unlock(&conn->lock);
    ovs_mutex_unlock(&ct->ct_lock);

    ovs_mutex_lock(&conn->lock);
    VLOG_DBG_RL(&rl, "Update timeout %s zone=%u with policy id=%d "
                "val=%u sec.",
                ct_timeout_str[tm], conn->key.zone, conn->tp_id, val);

    conn_update_expiration__(ct, conn, tm, now, val);
}

static void
conn_init_expiration__(struct conntrack *ct, struct conn *conn,
                       enum ct_timeout tm, long long now,
                       uint32_t tp_value)
{
    conn->expiration = now + tp_value * 1000;
    ovs_list_push_back(&ct->exp_lists[tm], &conn->exp_node);
}

/* ct_lock must be held. */
void
conn_init_expiration(struct conntrack *ct, struct conn *conn,
                     enum ct_timeout tm, long long now)
    OVS_REQUIRES(ct->ct_lock)
{
    struct timeout_policy *tp;
    uint32_t val;

    tp = timeout_policy_lookup(ct, conn->tp_id);
    if (tp) {
        val = tp->policy.attrs[tm_to_ct_dpif_tp(tm)];
    } else {
        val = ct_dpif_netdev_tp_def[tm_to_ct_dpif_tp(tm)];
    }

    VLOG_DBG_RL(&rl, "Init timeout %s zone=%u with policy id=%d val=%u sec.",
                ct_timeout_str[tm], conn->key.zone, conn->tp_id, val);

    conn_init_expiration__(ct, conn, tm, now, val);
}
