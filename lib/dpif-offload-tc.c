/*
 * Copyright (c) 2025 Red Hat, Inc.
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

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "dpif-offload-tc-private.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "tc.h"
#include "util.h"

#include "openvswitch/json.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_tc);

/* dpif offload interface for the tc implementation. */
struct tc_offload {
    struct dpif_offload offload;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
    bool recirc_id_shared;
};

/* tc's flow dump specific data structures. */
struct tc_flow_dump {
    struct dpif_offload_flow_dump dump;
    struct ovs_mutex netdev_dump_mutex;
    size_t netdev_dump_index;
    size_t netdev_dump_count;
    struct netdev_tc_flow_dump *netdev_dumps[];
};

#define FLOW_DUMP_MAX_BATCH 50

struct tc_flow_dump_thread {
    struct dpif_offload_flow_dump_thread thread;
    struct tc_flow_dump *dump;
    bool netdev_dump_done;
    size_t netdev_dump_index;

    /* (Flows/Key/Mask/Actions) Buffers for netdev dumping. */
    struct ofpbuf nl_flows;
    struct odputil_keybuf keybuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf maskbuf[FLOW_DUMP_MAX_BATCH];
    struct odputil_keybuf actbuf[FLOW_DUMP_MAX_BATCH];
};

static struct tc_offload *
tc_offload_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_tc_class);
    return CONTAINER_OF(offload, struct tc_offload, offload);
}

static int
tc_offload_enable(struct dpif_offload *dpif_offload,
                  struct dpif_offload_port *port)
{
    int ret = tc_netdev_init(port->netdev);

    if (ret) {
        VLOG_WARN("%s: Failed assigning flow API 'tc', error %d",
                  netdev_get_name(port->netdev), ret);
        return ret;
    }
    dpif_offload_set_netdev_offload(port->netdev, dpif_offload);
    VLOG_INFO("%s: Assigned flow API 'tc'", netdev_get_name(port->netdev));
    return 0;
}

static int
tc_offload_cleanup(struct dpif_offload *dpif_offload OVS_UNUSED,
                   struct dpif_offload_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, NULL);
    return 0;
}

static int
tc_port_add(struct dpif_offload *dpif_offload, struct netdev *netdev,
            odp_port_t port_no)
{
    struct dpif_offload_port *port = xmalloc(sizeof *port);

    if (dpif_offload_port_mgr_add(dpif_offload, port, netdev, port_no, true)) {
        if (dpif_offload_enabled()) {
            return tc_offload_enable(dpif_offload, port);
        }
        return 0;
    }

    free(port);
    return EEXIST;
}

static void
tc_free_port(struct dpif_offload_port *port)
{
    netdev_close(port->netdev);
    free(port);
}

static int
tc_port_del(struct dpif_offload *dpif_offload, odp_port_t port_no)
{
    struct dpif_offload_port *port;
    int ret = 0;

    port = dpif_offload_port_mgr_remove(dpif_offload, port_no);
    if (port) {
        if (dpif_offload_enabled()) {
            ret = tc_offload_cleanup(dpif_offload, port);
        }
        ovsrcu_postpone(tc_free_port, port);
    }
    return ret;
}

static struct netdev *
tc_get_netdev(const struct dpif_offload *dpif_offload, odp_port_t port_no)
{
    struct dpif_offload_port *port;

    port = dpif_offload_port_mgr_find_by_odp_port(dpif_offload, port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

static int
tc_offload_open(const struct dpif_offload_class *offload_class,
                struct dpif *dpif, struct dpif_offload **dpif_offload)
{
    struct tc_offload *offload = xmalloc(sizeof *offload);

    dpif_offload_init(&offload->offload, offload_class, dpif);
    offload->once_enable = (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;
    offload->recirc_id_shared = !!(dpif_get_features(dpif)
                                   & OVS_DP_F_TC_RECIRC_SHARING);

    VLOG_DBG("Datapath %s recirculation id sharing ",
             offload->recirc_id_shared ? "supports" : "does not support");

    tc_meter_init();

    *dpif_offload = &offload->offload;
    return 0;
}

static void
tc_offload_close(struct dpif_offload *dpif_offload)
{
    struct tc_offload *offload = tc_offload_cast(dpif_offload);
    struct dpif_offload_port *port;

    DPIF_OFFLOAD_PORT_FOR_EACH (port, dpif_offload) {
        tc_port_del(dpif_offload, port->port_no);
    }

    ovsthread_once_destroy(&offload->once_enable);
    dpif_offload_destroy(dpif_offload);
    free(offload);
}

static void
tc_offload_set_config(struct dpif_offload *offload_,
                      const struct smap *other_cfg)
{
    struct tc_offload *offload = tc_offload_cast(offload_);

    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload->once_enable)) {
            struct dpif_offload_port *port;

            tc_set_policy(smap_get_def(other_cfg, "tc-policy",
                                       TC_POLICY_DEFAULT));

            DPIF_OFFLOAD_PORT_FOR_EACH (port, offload_) {
                tc_offload_enable(offload_, port);
            }

            ovsthread_once_done(&offload->once_enable);
        }
    }
}

static void
tc_offload_get_debug(const struct dpif_offload *offload, struct ds *ds,
                     struct json *json)
{
    if (json) {
        struct json *json_ports = json_object_create();
        struct dpif_offload_port *port;

        DPIF_OFFLOAD_PORT_FOR_EACH (port, offload) {
            struct json *json_port = json_object_create();

            json_object_put(json_port, "port_no",
                            json_integer_create(odp_to_u32(port->port_no)));
            json_object_put(json_port, "ifindex",
                            json_integer_create(port->ifindex));

            json_object_put(json_ports, netdev_get_name(port->netdev),
                            json_port);
        }

        if (!json_object_is_empty(json_ports)) {
            json_object_put(json, "ports", json_ports);
        } else {
            json_destroy(json_ports);
        }
    } else if (ds) {
        struct dpif_offload_port *port;

        DPIF_OFFLOAD_PORT_FOR_EACH (port, offload) {
            ds_put_format(ds, "  - %s: port_no: %u, ifindex: %d\n",
                          netdev_get_name(port->netdev),
                          port->port_no, port->ifindex);
        }
    }
}

static bool
tc_can_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
               struct netdev *netdev)
{
    if (netdev_vport_is_vport_class(netdev->netdev_class) &&
        strcmp(netdev_get_dpif_type(netdev), "system")) {
        VLOG_DBG("%s: vport doesn't belong to the system datapath, skipping",
                 netdev_get_name(netdev));
        return false;
    }
    return true;
}

static int
tc_flow_flush(const struct dpif_offload *offload)
{
    struct dpif_offload_port *port;
    int error = 0;

    DPIF_OFFLOAD_PORT_FOR_EACH (port, offload) {
        int rc = tc_netdev_flow_flush(port->netdev);

        if (rc && !error) {
            error = rc;
        }
    }
    return error;
}

static struct tc_flow_dump *
tc_flow_dump_cast(struct dpif_offload_flow_dump *dump)
{
    return CONTAINER_OF(dump, struct tc_flow_dump, dump);
}

static struct tc_flow_dump_thread *
tc_flow_dump_thread_cast(
    struct dpif_offload_flow_dump_thread *thread)
{
    return CONTAINER_OF(thread, struct tc_flow_dump_thread, thread);
}

static struct dpif_offload_flow_dump *
tc_flow_dump_create(const struct dpif_offload *offload, bool terse)
{
    struct dpif_offload_port *port;
    size_t added_port_count = 0;
    struct tc_flow_dump *dump;
    size_t port_count;

    port_count = dpif_offload_port_mgr_port_count(offload);

    dump = xmalloc(sizeof *dump +
                   (port_count * sizeof(struct netdev_tc_flow_dump)));

    dpif_offload_flow_dump_init(&dump->dump, offload, terse);

    DPIF_OFFLOAD_PORT_FOR_EACH (port, offload) {
        if (added_port_count >= port_count) {
            break;
        }
        if (tc_netdev_flow_dump_create(
            port->netdev, &dump->netdev_dumps[added_port_count], terse)) {
            continue;
        }
        dump->netdev_dumps[added_port_count]->port = port->port_no;
        added_port_count++;
    }
    dump->netdev_dump_count = added_port_count;
    dump->netdev_dump_index = 0;
    ovs_mutex_init(&dump->netdev_dump_mutex);
    return &dump->dump;
}

static int
tc_match_to_dpif_flow(struct match *match, struct ofpbuf *key_buf,
                      struct ofpbuf *mask_buf, struct nlattr *actions,
                      struct dpif_flow_stats *stats,
                      struct dpif_flow_attrs *attrs, ovs_u128 *ufid,
                      struct dpif_flow *flow, bool terse)
{
    memset(flow, 0, sizeof *flow);

    if (!terse) {
        struct odp_flow_key_parms odp_parms = {
            .flow = &match->flow,
            .mask = &match->wc.masks,
            .support = {
                .max_vlan_headers = 2,
                .recirc = true,
                .ct_state = true,
                .ct_zone = true,
                .ct_mark = true,
                .ct_label = true,
            },
        };
        size_t offset;

        /* Key */
        offset = key_buf->size;
        flow->key = ofpbuf_tail(key_buf);
        odp_flow_key_from_flow(&odp_parms, key_buf);
        flow->key_len = key_buf->size - offset;

        /* Mask */
        offset = mask_buf->size;
        flow->mask = ofpbuf_tail(mask_buf);
        odp_parms.key_buf = key_buf;
        odp_flow_key_from_mask(&odp_parms, mask_buf);
        flow->mask_len = mask_buf->size - offset;

        /* Actions */
        flow->actions = nl_attr_get(actions);
        flow->actions_len = nl_attr_get_size(actions);
    }

    /* Stats */
    memcpy(&flow->stats, stats, sizeof *stats);

    /* UFID */
    flow->ufid_present = true;
    flow->ufid = *ufid;

    flow->pmd_id = PMD_ID_NULL;

    memcpy(&flow->attrs, attrs, sizeof *attrs);

    return 0;
}

static void
tc_advance_provider_dump(struct tc_flow_dump_thread *thread)
{
    struct tc_flow_dump *dump = thread->dump;

    ovs_mutex_lock(&dump->netdev_dump_mutex);

    /* If we haven't finished (dumped all providers). */
    if (dump->netdev_dump_index < dump->netdev_dump_count) {
        /* If we are the first to find that current dump is finished
         * advance it. */
        if (thread->netdev_dump_index == dump->netdev_dump_index) {
            thread->netdev_dump_index = ++dump->netdev_dump_index;
            /* Did we just finish the last dump? If so we are done. */
            if (dump->netdev_dump_index == dump->netdev_dump_count) {
                thread->netdev_dump_done = true;
            }
        } else {
            /* Otherwise, we are behind, catch up. */
            thread->netdev_dump_index = dump->netdev_dump_index;
        }
    } else {
        /* Some other thread finished. */
        thread->netdev_dump_done = true;
    }

    ovs_mutex_unlock(&dump->netdev_dump_mutex);
}

static int
tc_flow_dump_next(struct dpif_offload_flow_dump_thread *thread_,
                  struct dpif_flow *flows, int max_flows)
{
    struct tc_flow_dump_thread *thread = tc_flow_dump_thread_cast(thread_);
    int n_flows = 0;

    max_flows = MIN(max_flows, FLOW_DUMP_MAX_BATCH);

    while (!thread->netdev_dump_done && n_flows < max_flows) {
        struct odputil_keybuf *maskbuf = &thread->maskbuf[n_flows];
        struct odputil_keybuf *keybuf = &thread->keybuf[n_flows];
        struct odputil_keybuf *actbuf = &thread->actbuf[n_flows];
        struct netdev_tc_flow_dump *netdev_dump;
        struct dpif_flow *f = &flows[n_flows];
        int cur = thread->netdev_dump_index;
        struct ofpbuf key, mask, act;
        struct dpif_flow_stats stats;
        struct dpif_flow_attrs attrs;
        struct nlattr *actions;
        struct match match;
        ovs_u128 ufid;
        bool has_next;

        netdev_dump = thread->dump->netdev_dumps[cur];
        ofpbuf_use_stack(&key, keybuf, sizeof *keybuf);
        ofpbuf_use_stack(&act, actbuf, sizeof *actbuf);
        ofpbuf_use_stack(&mask, maskbuf, sizeof *maskbuf);
        has_next = tc_netdev_flow_dump_next(netdev_dump, &match, &actions,
                                            &stats, &attrs, &ufid,
                                            &thread->nl_flows, &act);
        if (has_next) {
            tc_match_to_dpif_flow(&match, &key, &mask, actions, &stats,
                                  &attrs, &ufid, f, thread->dump->dump.terse);
            n_flows++;
        } else {
            tc_advance_provider_dump(thread);
        }
    }
    return n_flows;
}

static int
tc_flow_dump_destroy(struct dpif_offload_flow_dump *dump_)
{
    struct tc_flow_dump *dump = tc_flow_dump_cast(dump_);
    int error = 0;

    for (int i = 0; i < dump->netdev_dump_count; i++) {
        struct netdev_tc_flow_dump *dump_netdev = dump->netdev_dumps[i];
        int rc = tc_netdev_flow_dump_destroy(dump_netdev);

        if (rc && !error) {
            error = rc;
        }
    }
    ovs_mutex_destroy(&dump->netdev_dump_mutex);
    free(dump);
    return error;
}

static struct dpif_offload_flow_dump_thread *
tc_flow_dump_thread_create(struct dpif_offload_flow_dump *dump)
{
    struct tc_flow_dump_thread *thread;

    thread = xmalloc(sizeof *thread);
    dpif_offload_flow_dump_thread_init(&thread->thread, dump);
    thread->dump = tc_flow_dump_cast(dump);
    thread->netdev_dump_index = 0;
    thread->netdev_dump_done = !thread->dump->netdev_dump_count;
    ofpbuf_init(&thread->nl_flows, NL_DUMP_BUFSIZE);
    return &thread->thread;
}

static void
tc_flow_dump_thread_destroy(struct dpif_offload_flow_dump_thread *thread_)
{
    struct tc_flow_dump_thread *thread = tc_flow_dump_thread_cast(thread_);

    ofpbuf_uninit(&thread->nl_flows);
    free(thread);
}

static int
tc_parse_flow_put(struct tc_offload *offload_tc, struct dpif *dpif,
                  struct dpif_flow_put *put)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct dpif_offload_port *port;
    const struct nlattr *nla;
    struct tc_offload_info info;
    struct match match;
    odp_port_t in_port;
    size_t left;
    int err;

    info.tc_modify_flow_deleted = false;
    info.tc_modify_flow = false;

    if (put->flags & DPIF_FP_PROBE) {
        return EOPNOTSUPP;
    }

    err = parse_key_and_mask_to_match(put->key, put->key_len, put->mask,
                                      put->mask_len, &match);
    if (err) {
        return err;
    }

    in_port = match.flow.in_port.odp_port;
    port = dpif_offload_port_mgr_find_by_odp_port(&offload_tc->offload,
                                                  in_port);
    if (!port) {
        return EOPNOTSUPP;
    }

    /* Check the output port for a tunnel. */
    NL_ATTR_FOR_EACH (nla, left, put->actions, put->actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            struct dpif_offload_port *mgr_port;
            odp_port_t out_port;

            out_port = nl_attr_get_odp_port(nla);
            mgr_port = dpif_offload_port_mgr_find_by_odp_port(
                                &offload_tc->offload, out_port);

            if (!mgr_port) {
                err = EOPNOTSUPP;
                goto out;
            }
        }
    }

    info.recirc_id_shared_with_tc = offload_tc->recirc_id_shared;

    err = tc_netdev_flow_put(dpif, port->netdev, &match,
                             CONST_CAST(struct nlattr *, put->actions),
                             put->actions_len,
                             CONST_CAST(ovs_u128 *, put->ufid),
                             &info, put->stats);

    if (!err) {
        if (put->flags & DPIF_FP_MODIFY && !info.tc_modify_flow) {
            struct dpif_op *opp;
            struct dpif_op op;

            op.type = DPIF_OP_FLOW_DEL;
            op.flow_del.key = put->key;
            op.flow_del.key_len = put->key_len;
            op.flow_del.ufid = put->ufid;
            op.flow_del.pmd_id = put->pmd_id;
            op.flow_del.stats = NULL;
            op.flow_del.terse = false;

            opp = &op;
            dpif_operate(dpif, &opp, 1, DPIF_OFFLOAD_NEVER);
        }

        VLOG_DBG("added flow");
    } else if (err != EEXIST) {
        struct netdev *oor_netdev = NULL;
        enum vlog_level level;

        if (err == ENOSPC && dpif_offload_rebalance_policy_enabled()) {
            /*
             * We need to set OOR on the input netdev (i.e, 'dev') for the
             * flow.  But if the flow has a tunnel attribute (i.e, decap
             * action, with a virtual device like a VxLAN interface as its
             * in-port), then lookup and set OOR on the underlying tunnel
             * (real) netdev. */
            oor_netdev = flow_get_tunnel_netdev(&match.flow.tunnel);
            if (!oor_netdev) {
                /* Not a 'tunnel' flow. */
                oor_netdev = port->netdev;
            }
            netdev_set_hw_info(oor_netdev, HW_INFO_TYPE_OOR, true);
        }
        level = (err == ENOSPC || err == EOPNOTSUPP) ? VLL_DBG : VLL_ERR;
        VLOG_RL(&rl, level, "failed to offload flow: %s: %s",
                ovs_strerror(err),
                (oor_netdev ? netdev_get_name(oor_netdev) :
                              netdev_get_name(port->netdev)));
    }

out:
    if (err && err != EEXIST && (put->flags & DPIF_FP_MODIFY)) {
        /* Modified rule can't be offloaded, try and delete from HW. */
        int del_err = 0;

        if (!info.tc_modify_flow_deleted) {
            del_err = tc_netdev_flow_del(put->ufid, put->stats);
        }

        if (!del_err) {
            /* Delete from hw success, so old flow was offloaded.
             * Change flags to create the flow at the dpif level. */
            put->flags &= ~DPIF_FP_MODIFY;
            put->flags |= DPIF_FP_CREATE;
        } else if (del_err != ENOENT) {
            VLOG_ERR_RL(&rl, "failed to delete offloaded flow: %s",
                        ovs_strerror(del_err));
            /* Stop processing the flow in kernel. */
            err = 0;
        }
    }

    return err;
}

static int
tc_parse_flow_get(struct tc_offload *offload_tc, struct dpif_flow_get *get)
{
    struct dpif_flow *dpif_flow = get->flow;
    struct dpif_offload_port *port;
    struct odputil_keybuf maskbuf;
    struct odputil_keybuf keybuf;
    struct odputil_keybuf actbuf;
    struct ofpbuf key, mask, act;
    struct dpif_flow_stats stats;
    struct dpif_flow_attrs attrs;
    uint64_t act_buf[1024 / 8];
    struct nlattr *actions;
    struct match match;
    struct ofpbuf buf;
    int err = ENOENT;

    ofpbuf_use_stack(&buf, &act_buf, sizeof act_buf);

    DPIF_OFFLOAD_PORT_FOR_EACH (port, &offload_tc->offload) {
        if (!tc_netdev_flow_get(port->netdev, &match, &actions, get->ufid,
                                &stats, &attrs, &buf)) {
            err = 0;
            break;
        }
    }

    if (err) {
        return err;
    }

    VLOG_DBG("found flow from netdev, translating to dpif flow");

    ofpbuf_use_stack(&key, &keybuf, sizeof keybuf);
    ofpbuf_use_stack(&act, &actbuf, sizeof actbuf);
    ofpbuf_use_stack(&mask, &maskbuf, sizeof maskbuf);
    tc_match_to_dpif_flow(&match, &key, &mask, actions, &stats, &attrs,
                          (ovs_u128 *) get->ufid, dpif_flow, false);
    ofpbuf_put(get->buffer, nl_attr_get(actions), nl_attr_get_size(actions));
    dpif_flow->actions = ofpbuf_at(get->buffer, 0, 0);
    dpif_flow->actions_len = nl_attr_get_size(actions);

    return 0;
}

static void
tc_operate(struct dpif *dpif, const struct dpif_offload *offload_,
           struct dpif_op **ops, size_t n_ops)
{
    struct tc_offload *offload = tc_offload_cast(offload_);

    for (size_t i = 0; i < n_ops; i++) {
        struct dpif_op *op = ops[i];
        int error = EOPNOTSUPP;

        if (op->error >= 0) {
            continue;
        }

        switch (op->type) {
        case DPIF_OP_FLOW_PUT: {
            struct dpif_flow_put *put = &op->flow_put;

            if (!put->ufid) {
                break;
            }

            error = tc_parse_flow_put(offload, dpif, put);
            break;
        }
        case DPIF_OP_FLOW_DEL: {
            struct dpif_flow_del *del = &op->flow_del;

            if (!del->ufid) {
                break;
            }

            error = tc_netdev_flow_del(del->ufid, del->stats);
            break;
        }
        case DPIF_OP_FLOW_GET: {
            struct dpif_flow_get *get = &op->flow_get;

            if (!get->ufid) {
                break;
            }

            error = tc_parse_flow_get(offload, get);
            break;
        }
        case DPIF_OP_EXECUTE:
            break;
        } /* End of 'switch (op->type)'. */

        if (error != EOPNOTSUPP && error != ENOENT) {
            /* If the operation is unsupported or the entry was not found,
             * we are skipping this flow operation.  Otherwise, it was
             * processed and we should report the result. */
            op->error = error;
        }
    }
}

odp_port_t
tc_get_port_id_by_ifindex(const struct dpif_offload *offload, int ifindex)
{
    struct dpif_offload_port *port;

    port = dpif_offload_port_mgr_find_by_ifindex(offload, ifindex);
    if (port) {
        return port->port_no;
    }
    return ODPP_NONE;
}

struct dpif_offload_class dpif_offload_tc_class = {
    .type = "tc",
    .impl_type = DPIF_OFFLOAD_IMPL_FLOWS_PROVIDER_ONLY,
    .supported_dpif_types = (const char *const[]) {"system", NULL},
    .open = tc_offload_open,
    .close = tc_offload_close,
    .set_config = tc_offload_set_config,
    .get_debug = tc_offload_get_debug,
    .can_offload = tc_can_offload,
    .port_add = tc_port_add,
    .port_del = tc_port_del,
    .flow_flush = tc_flow_flush,
    .flow_dump_create = tc_flow_dump_create,
    .flow_dump_next = tc_flow_dump_next,
    .flow_dump_destroy = tc_flow_dump_destroy,
    .flow_dump_thread_create = tc_flow_dump_thread_create,
    .flow_dump_thread_destroy = tc_flow_dump_thread_destroy,
    .operate = tc_operate,
    .flow_count = tc_flow_count,
    .meter_set = tc_meter_set,
    .meter_get = tc_meter_get,
    .meter_del = tc_meter_del,
    .get_netdev = tc_get_netdev,
};
