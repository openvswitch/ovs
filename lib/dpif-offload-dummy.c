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

#include "dpif.h"
#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "dummy.h"
#include "id-fpool.h"
#include "netdev-provider.h"
#include "odp-util.h"
#include "util.h"
#include "uuid.h"

#include "openvswitch/json.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_dummy);

struct pmd_id_data {
    struct hmap_node node;
    void *flow_reference;
    unsigned pmd_id;
};

struct dummy_offloaded_flow {
    struct hmap_node node;
    struct match match;
    ovs_u128 ufid;
    uint32_t mark;

    /* The pmd_id_map below is also protected by the port_mutex. */
    struct hmap pmd_id_map;
 };

struct dummy_offload {
    struct dpif_offload offload;
    struct id_fpool *flow_mark_pool;
    dpif_offload_flow_unreference_cb *unreference_cb;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

struct dummy_offload_port {
    struct dpif_offload_port pm_port;

    struct ovs_mutex port_mutex; /* Protect all below members. */
    struct hmap offloaded_flows OVS_GUARDED;
};

static void dummy_flow_unreference(struct dummy_offload *, unsigned pmd_id,
                                   void *flow_reference);

static uint32_t
dummy_allocate_flow_mark(struct dummy_offload *offload)
{
    static struct ovsthread_once init_once = OVSTHREAD_ONCE_INITIALIZER;
    uint32_t flow_mark;

    if (ovsthread_once_start(&init_once)) {
        /* Haven't initiated yet, do it here. */
        offload->flow_mark_pool = id_fpool_create(1, 1, UINT32_MAX - 1);
        ovsthread_once_done(&init_once);
    }

    if (id_fpool_new_id(offload->flow_mark_pool, 0, &flow_mark)) {
        return flow_mark;
    }

    return INVALID_FLOW_MARK;
}

static void
dummy_free_flow_mark(struct dummy_offload *offload, uint32_t flow_mark)
{
    if (flow_mark != INVALID_FLOW_MARK) {
        id_fpool_free_id(offload->flow_mark_pool, 0, flow_mark);
    }
}

static struct dummy_offload_port *
dummy_offload_port_cast(struct dpif_offload_port *port)
{
    return CONTAINER_OF(port, struct dummy_offload_port, pm_port);
}

static struct dummy_offload *
dummy_offload_cast(const struct dpif_offload *offload)
{
    return CONTAINER_OF(offload, struct dummy_offload, offload);
}

static uint32_t
dummy_flow_hash(const ovs_u128 *ufid)
{
    return ufid->u32[0];
}

static struct pmd_id_data *
dummy_find_flow_pmd_data(struct dummy_offload_port *port OVS_UNUSED,
                         struct dummy_offloaded_flow *off_flow,
                         unsigned pmd_id)
    OVS_REQUIRES(port->port_mutex)
{
    size_t hash = hash_int(pmd_id, 0);
    struct pmd_id_data *data;

    HMAP_FOR_EACH_WITH_HASH (data, node, hash, &off_flow->pmd_id_map) {
        if (data->pmd_id == pmd_id) {
            return data;
        }
    }
    return NULL;
}

static void
dummy_add_flow_pmd_data(struct dummy_offload_port *port OVS_UNUSED,
                        struct dummy_offloaded_flow *off_flow, unsigned pmd_id,
                        void *flow_reference)
    OVS_REQUIRES(port->port_mutex)
{
    struct pmd_id_data *pmd_data = xmalloc(sizeof *pmd_data);

    pmd_data->pmd_id = pmd_id;
    pmd_data->flow_reference = flow_reference;
    hmap_insert(&off_flow->pmd_id_map, &pmd_data->node,
                hash_int(pmd_id, 0));
}

static void
dummy_update_flow_pmd_data(struct dummy_offload_port *port,
                           struct dummy_offloaded_flow *off_flow,
                           unsigned pmd_id, void *flow_reference,
                           void **previous_flow_reference)
    OVS_REQUIRES(port->port_mutex)
{
    struct pmd_id_data *data = dummy_find_flow_pmd_data(port, off_flow,
                                                        pmd_id);

    if (data) {
        *previous_flow_reference = data->flow_reference;
        data->flow_reference = flow_reference;
    } else {
        dummy_add_flow_pmd_data(port, off_flow, pmd_id, flow_reference);
        *previous_flow_reference = NULL;
    }
}

static bool
dummy_del_flow_pmd_data(struct dummy_offload_port *port OVS_UNUSED,
                        struct dummy_offloaded_flow *off_flow, unsigned pmd_id,
                        void *flow_reference)
    OVS_REQUIRES(port->port_mutex)
{
    size_t hash = hash_int(pmd_id, 0);
    struct pmd_id_data *data;

    HMAP_FOR_EACH_WITH_HASH (data, node, hash, &off_flow->pmd_id_map) {
        if (data->pmd_id == pmd_id && data->flow_reference == flow_reference) {
            hmap_remove(&off_flow->pmd_id_map, &data->node);
            free(data);
            return true;
        }
    }

    return false;
}

static void
dummy_cleanup_flow_pmd_data(struct dummy_offload *offload,
                            struct dummy_offload_port *port OVS_UNUSED,
                            struct dummy_offloaded_flow *off_flow)
    OVS_REQUIRES(port->port_mutex)
{
    struct pmd_id_data *data;

    HMAP_FOR_EACH_SAFE (data, node, &off_flow->pmd_id_map) {
        hmap_remove(&off_flow->pmd_id_map, &data->node);

        dummy_flow_unreference(offload, data->pmd_id, data->flow_reference);
        free(data);
    }
}

static struct dummy_offloaded_flow *
dummy_add_flow(struct dummy_offload_port *port, const ovs_u128 *ufid,
               unsigned pmd_id, void *flow_reference, uint32_t mark)
    OVS_REQUIRES(port->port_mutex)
{
    struct dummy_offloaded_flow *off_flow = xzalloc(sizeof *off_flow);

    off_flow->mark = mark;
    memcpy(&off_flow->ufid, ufid, sizeof off_flow->ufid);
    hmap_init(&off_flow->pmd_id_map);
    dummy_add_flow_pmd_data(port, off_flow, pmd_id, flow_reference);

    hmap_insert(&port->offloaded_flows, &off_flow->node,
                dummy_flow_hash(ufid));

    return off_flow;
}

static void
dummy_free_flow(struct dummy_offload_port *port,
                struct dummy_offloaded_flow *off_flow, bool remove_from_port)
    OVS_REQUIRES(port->port_mutex)
{
    if (remove_from_port) {
        hmap_remove(&port->offloaded_flows, &off_flow->node);
    }
    ovs_assert(!hmap_count(&off_flow->pmd_id_map));

    hmap_destroy(&off_flow->pmd_id_map);
    free(off_flow);
}

static struct dummy_offloaded_flow *
dummy_find_offloaded_flow(struct dummy_offload_port *port,
                          const ovs_u128 *ufid)
    OVS_REQUIRES(port->port_mutex)
{
    uint32_t hash = dummy_flow_hash(ufid);
    struct dummy_offloaded_flow *data;

    HMAP_FOR_EACH_WITH_HASH (data, node, hash, &port->offloaded_flows) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    return NULL;
}

static struct dummy_offloaded_flow *
dummy_find_offloaded_flow_and_update(struct dummy_offload_port *port,
                                     const ovs_u128 *ufid, unsigned pmd_id,
                                     void *new_flow_reference,
                                     void **previous_flow_reference)
    OVS_REQUIRES(port->port_mutex)
{
    struct dummy_offloaded_flow *off_flow;

    off_flow = dummy_find_offloaded_flow(port, ufid);
    if (!off_flow) {
        return NULL;
    }

    dummy_update_flow_pmd_data(port, off_flow, pmd_id, new_flow_reference,
                               previous_flow_reference);

    return off_flow;
}

static void
dummy_offload_enable(struct dpif_offload *dpif_offload,
                     struct dpif_offload_port *port)
{
    atomic_store_relaxed(&port->netdev->hw_info.post_process_api_supported,
                         true);
    dpif_offload_set_netdev_offload(port->netdev, dpif_offload);
}

static void
dummy_offload_cleanup(struct dpif_offload_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, NULL);
}

static void
dummy_free_port__(struct dummy_offload *offload,
                  struct dummy_offload_port *port, bool close_netdev)
{
    struct dummy_offloaded_flow *off_flow;

    ovs_mutex_lock(&port->port_mutex);
    HMAP_FOR_EACH_POP (off_flow, node, &port->offloaded_flows) {
        dummy_cleanup_flow_pmd_data(offload, port, off_flow);
        dummy_free_flow(port, off_flow, false);
    }
    hmap_destroy(&port->offloaded_flows);
    ovs_mutex_unlock(&port->port_mutex);
    ovs_mutex_destroy(&port->port_mutex);
    if (close_netdev) {
        netdev_close(port->pm_port.netdev);
    }
    free(port);
}

struct free_port_rcu {
    struct dummy_offload *offload;
    struct dummy_offload_port *port;
};

static void
dummy_free_port_rcu(struct free_port_rcu *fpc)
{
    dummy_free_port__(fpc->offload, fpc->port, true);
    free(fpc);
}

static void
dummy_free_port(struct dummy_offload *offload, struct dummy_offload_port *port)
{
    struct free_port_rcu *fpc = xmalloc(sizeof *fpc);

    fpc->offload = offload;
    fpc->port = port;
    ovsrcu_postpone(dummy_free_port_rcu, fpc);
}

static int
dummy_offload_port_add(struct dpif_offload *dpif_offload,
                       struct netdev *netdev, odp_port_t port_no)
{
    struct dummy_offload *offload = dummy_offload_cast(dpif_offload);
    struct dummy_offload_port *port = xmalloc(sizeof *port);

    ovs_mutex_init(&port->port_mutex);
    ovs_mutex_lock(&port->port_mutex);
    hmap_init(&port->offloaded_flows);
    ovs_mutex_unlock(&port->port_mutex);

    if (dpif_offload_port_mgr_add(dpif_offload, &port->pm_port, netdev,
                                  port_no, false)) {

        if (dpif_offload_enabled()) {
            dummy_offload_enable(dpif_offload, &port->pm_port);
        }
        return 0;
    }

    dummy_free_port__(offload, port, false);
    return EEXIST;
}

static int
dummy_offload_port_del(struct dpif_offload *dpif_offload, odp_port_t port_no)
{
    struct dummy_offload *offload = dummy_offload_cast(dpif_offload);
    struct dpif_offload_port *port;

    port = dpif_offload_port_mgr_remove(dpif_offload, port_no);
    if (port) {
        struct dummy_offload_port *dummy_port;

        dummy_port = dummy_offload_port_cast(port);
        if (dpif_offload_enabled()) {
            dummy_offload_cleanup(port);
        }
        dummy_free_port(offload, dummy_port);
    }
    return 0;
}

static struct netdev *
dummy_offload_get_netdev(const struct dpif_offload *dpif_offload,
                         odp_port_t port_no)
{
    struct dpif_offload_port *port;

    port = dpif_offload_port_mgr_find_by_odp_port(dpif_offload, port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

static int
dummy_offload_open(const struct dpif_offload_class *offload_class,
                   struct dpif *dpif, struct dpif_offload **dpif_offload)
{
    struct dummy_offload *offload;

    offload = xmalloc(sizeof *offload);

    dpif_offload_init(&offload->offload, offload_class, dpif);
    offload->once_enable = (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;
    offload->flow_mark_pool = NULL;
    offload->unreference_cb = NULL;

    *dpif_offload = &offload->offload;
    return 0;
}

static void
dummy_offload_close(struct dpif_offload *dpif_offload)
{
    struct dummy_offload *offload = dummy_offload_cast(dpif_offload);
    struct dpif_offload_port *port;

    /* The ofproto layer may not call dpif_port_del() for all ports,
     * especially internal ones, so we need to clean up any remaining ports. */
    DPIF_OFFLOAD_PORT_FOR_EACH (port, dpif_offload) {
        dummy_offload_port_del(dpif_offload, port->port_no);
    }

    if (offload->flow_mark_pool) {
        id_fpool_destroy(offload->flow_mark_pool);
    }
    ovsthread_once_destroy(&offload->once_enable);
    dpif_offload_destroy(dpif_offload);
    free(offload);
}

static void
dummy_offload_set_config(struct dpif_offload *dpif_offload,
                         const struct smap *other_cfg)
{
    struct dummy_offload *offload = dummy_offload_cast(dpif_offload);

    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload->once_enable)) {
            struct dpif_offload_port *port;

            DPIF_OFFLOAD_PORT_FOR_EACH (port, dpif_offload) {
                dummy_offload_enable(dpif_offload, port);
            }

            ovsthread_once_done(&offload->once_enable);
        }
    }
}

static void
dummy_offload_get_debug(const struct dpif_offload *offload, struct ds *ds,
                        struct json *json)
{
    if (json) {
        struct json *json_ports = json_object_create();
        struct dpif_offload_port *port;

        DPIF_OFFLOAD_PORT_FOR_EACH (port, offload) {
            struct json *json_port = json_object_create();

            json_object_put(json_port, "port_no",
                            json_integer_create(odp_to_u32(port->port_no)));

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
            ds_put_format(ds, "  - %s: port_no: %u\n",
                          netdev_get_name(port->netdev), port->port_no);
        }
    }
}

static int
dummy_offload_get_global_stats(const struct dpif_offload *offload,
                               struct netdev_custom_stats *stats)
{
    /* Add a single counter telling how many ports we are servicing. */
    stats->label = xstrdup(dpif_offload_name(offload));
    stats->size = 1;
    stats->counters = xmalloc(sizeof(struct netdev_custom_counter) * 1);
    stats->counters[0].value = dpif_offload_port_mgr_port_count(offload);
    ovs_strzcpy(stats->counters[0].name, "Offloaded port count",
                sizeof stats->counters[0].name);

    return 0;
}

static bool
dummy_can_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
                  struct netdev *netdev)
{
    return is_dummy_netdev_class(netdev->netdev_class);
}

static void
dummy_offload_log_operation(const char *op, int error, const ovs_u128 *ufid)
{
    VLOG_DBG("%s to %s netdev flow "UUID_FMT,
             error == 0 ? "succeed" : "failed", op,
             UUID_ARGS((struct uuid *) ufid));
}

static struct dummy_offload_port *
dummy_offload_get_port_by_netdev(const struct dpif_offload *offload,
                                 struct netdev *netdev)
{
    struct dpif_offload_port *port;

    port = dpif_offload_port_mgr_find_by_netdev(offload, netdev);
    if (!port) {
        return NULL;
    }
    return dummy_offload_port_cast(port);
}

static int
dummy_offload_hw_post_process(const struct dpif_offload *offload_,
                              struct netdev *netdev, unsigned pmd_id,
                              struct dp_packet *packet, void **flow_reference_)
{
    struct dummy_offloaded_flow *off_flow;
    struct dummy_offload_port *port;
    void *flow_reference = NULL;
    uint32_t flow_mark;

    port = dummy_offload_get_port_by_netdev(offload_, netdev);
    if (!port || !dp_packet_has_flow_mark(packet, &flow_mark)) {
        *flow_reference_ = NULL;
        return 0;
    }

    ovs_mutex_lock(&port->port_mutex);
    HMAP_FOR_EACH (off_flow, node, &port->offloaded_flows) {
        struct pmd_id_data *pmd_data;

        if (flow_mark == off_flow->mark) {
            pmd_data = dummy_find_flow_pmd_data(port, off_flow, pmd_id);
            if (pmd_data) {
                flow_reference = pmd_data->flow_reference;
            }
            break;
        }
    }
    ovs_mutex_unlock(&port->port_mutex);

     *flow_reference_ = flow_reference;
    return 0;
}

static int
dummy_flow_put(const struct dpif_offload *offload_, struct netdev *netdev,
               struct dpif_offload_flow_put *put,
               void **previous_flow_reference)
{
    struct dummy_offload *offload = dummy_offload_cast(offload_);
    struct dummy_offloaded_flow *off_flow;
    struct dummy_offload_port *port;
    bool modify = true;
    int error = 0;

    port = dummy_offload_get_port_by_netdev(offload_, netdev);
    if (!port) {
        error = ENODEV;
        goto exit;
    }

    ovs_mutex_lock(&port->port_mutex);

    off_flow = dummy_find_offloaded_flow_and_update(
        port, put->ufid, put->pmd_id, put->flow_reference,
        previous_flow_reference);

    if (!off_flow) {
        /* Create new offloaded flow. */
        uint32_t mark = dummy_allocate_flow_mark(offload);

        if (mark == INVALID_FLOW_MARK) {
            error = ENOSPC;
            goto exit_unlock;
        }

        off_flow = dummy_add_flow(port, put->ufid, put->pmd_id,
                                  put->flow_reference, mark);
        modify = false;
        *previous_flow_reference = NULL;
    }
    memcpy(&off_flow->match, put->match, sizeof *put->match);

    /* As we have per-netdev 'offloaded_flows', we don't need to match
     * the 'in_port' for received packets.  This will also allow offloading
     * for packets passed to 'receive' command without specifying the
     * 'in_port'. */
    off_flow->match.wc.masks.in_port.odp_port = 0;

    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "%s: flow put[%s]: ", netdev_get_name(netdev),
                      modify ? "modify" : "create");
        odp_format_ufid(put->ufid, &ds);
        ds_put_cstr(&ds, " flow match: ");
        match_format(put->match, NULL, &ds, OFP_DEFAULT_PRIORITY);
        ds_put_format(&ds, ", mark: %"PRIu32, off_flow->mark);

        VLOG_DBG("%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

exit_unlock:
    ovs_mutex_unlock(&port->port_mutex);

exit:
    if (put->stats) {
        memset(put->stats, 0, sizeof *put->stats);
    }

    dummy_offload_log_operation(modify ? "modify" : "add", error, put->ufid);
    return error;
}

static int
dummy_flow_del(const struct dpif_offload *offload_, struct netdev *netdev,
               struct dpif_offload_flow_del *del)
{
    struct dummy_offload *offload = dummy_offload_cast(offload_);
    struct dummy_offloaded_flow *off_flow;
    uint32_t mark = INVALID_FLOW_MARK;
    struct dummy_offload_port *port;
    const char *error = NULL;

    port = dummy_offload_get_port_by_netdev(offload_, netdev);
    if (!port) {
        error = "No such (net)device.";
        goto exit;
    }

    ovs_mutex_lock(&port->port_mutex);

    off_flow = dummy_find_offloaded_flow(port, del->ufid);
    if (!off_flow) {
        error = "No such flow.";
        goto exit_unlock;
    }

    if (!dummy_del_flow_pmd_data(port, off_flow, del->pmd_id,
                                 del->flow_reference)) {
        error = "No such flow with pmd_id and reference.";
        goto exit_unlock;
    }

    mark = off_flow->mark;
    if (!hmap_count(&off_flow->pmd_id_map)) {
        dummy_free_flow_mark(offload, mark);
        dummy_free_flow(port, off_flow, true);
    }

exit_unlock:
    ovs_mutex_unlock(&port->port_mutex);

exit:
    if (error || VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "%s: ", netdev_get_name(netdev));
        if (error) {
            ds_put_cstr(&ds, "failed to ");
        }
        ds_put_cstr(&ds, "flow del: ");
        odp_format_ufid(del->ufid, &ds);
        if (error) {
            ds_put_format(&ds, " error: %s", error);
        } else {
            ds_put_format(&ds, " mark: %"PRIu32, mark);
        }
        VLOG(error ? VLL_WARN : VLL_DBG, "%s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    if (del->stats) {
        memset(del->stats, 0, sizeof *del->stats);
    }

    dummy_offload_log_operation("delete", error ? -1 : 0, del->ufid);
    return error ? ENOENT : 0;
}

static bool
dummy_flow_stats(const struct dpif_offload *offload_, struct netdev *netdev,
                 const ovs_u128 *ufid, struct dpif_flow_stats *stats,
                 struct dpif_flow_attrs *attrs)
{
    struct dummy_offloaded_flow *off_flow = NULL;
    struct dummy_offload_port *port;

    port = dummy_offload_get_port_by_netdev(offload_, netdev);
    if (!port) {
        return false;
    }

    ovs_mutex_lock(&port->port_mutex);
    off_flow = dummy_find_offloaded_flow(port, ufid);
    ovs_mutex_unlock(&port->port_mutex);

    memset(stats, 0, sizeof *stats);
    attrs->offloaded = off_flow ? true : false;
    attrs->dp_layer = "ovs"; /* 'ovs', since this is a partial offload. */
    attrs->dp_extra_info = NULL;

    return off_flow ? true : false;
}

static void
dummy_register_flow_unreference_cb(const struct dpif_offload *offload_,
                                   dpif_offload_flow_unreference_cb *cb)
{
    struct dummy_offload *offload = dummy_offload_cast(offload_);

    offload->unreference_cb = cb;
}

static void
dummy_flow_unreference(struct dummy_offload *offload, unsigned pmd_id,
                       void *flow_reference)
{
    if (offload->unreference_cb) {
        offload->unreference_cb(pmd_id, flow_reference);
    }
}

void
dummy_netdev_simulate_offload(struct netdev *netdev, struct dp_packet *packet,
                              struct flow *flow)
{
    const struct dpif_offload *offload = ovsrcu_get(
        const struct dpif_offload *, &netdev->dpif_offload);
    struct dummy_offloaded_flow *data;
    struct dummy_offload_port *port;
    struct flow packet_flow;

    if (!offload || strcmp(dpif_offload_type(offload), "dummy")) {
        return;
    }

    port = dummy_offload_get_port_by_netdev(offload, netdev);
    if (!port) {
        return;
    }

    if (!flow) {
        flow = &packet_flow;
        flow_extract(packet, flow);
    }

    ovs_mutex_lock(&port->port_mutex);
    HMAP_FOR_EACH (data, node, &port->offloaded_flows) {
        if (flow_equal_except(flow, &data->match.flow, &data->match.wc)) {

            dp_packet_set_flow_mark(packet, data->mark);

            if (VLOG_IS_DBG_ENABLED()) {
                struct ds ds = DS_EMPTY_INITIALIZER;

                ds_put_format(&ds, "%s: packet: ",
                              netdev_get_name(netdev));
                /* 'flow' does not contain proper port number here.
                 * Let's just clear it as it's wildcarded anyway. */
                flow->in_port.ofp_port = 0;
                flow_format(&ds, flow, NULL);

                ds_put_cstr(&ds, " matches with flow: ");
                odp_format_ufid(&data->ufid, &ds);
                ds_put_cstr(&ds, " ");
                match_format(&data->match, NULL, &ds, OFP_DEFAULT_PRIORITY);
                ds_put_format(&ds, " with mark: %"PRIu32, data->mark);

                VLOG_DBG("%s", ds_cstr(&ds));
                ds_destroy(&ds);
            }
            break;
        }
    }
    ovs_mutex_unlock(&port->port_mutex);
}

#define DEFINE_DPIF_DUMMY_CLASS(NAME, TYPE_STR)                             \
    struct dpif_offload_class NAME = {                                      \
        .type = TYPE_STR,                                                   \
        .impl_type = DPIF_OFFLOAD_IMPL_FLOWS_DPIF_SYNCED,                   \
        .supported_dpif_types = (const char *const[]) {"dummy", NULL},      \
        .open = dummy_offload_open,                                         \
        .close = dummy_offload_close,                                       \
        .set_config = dummy_offload_set_config,                             \
        .get_debug = dummy_offload_get_debug,                               \
        .get_global_stats = dummy_offload_get_global_stats,                 \
        .can_offload = dummy_can_offload,                                   \
        .port_add = dummy_offload_port_add,                                 \
        .port_del = dummy_offload_port_del,                                 \
        .get_netdev = dummy_offload_get_netdev,                             \
        .netdev_hw_post_process = dummy_offload_hw_post_process,            \
        .netdev_flow_put = dummy_flow_put,                                  \
        .netdev_flow_del = dummy_flow_del,                                  \
        .netdev_flow_stats = dummy_flow_stats,                              \
        .register_flow_unreference_cb = dummy_register_flow_unreference_cb, \
}

DEFINE_DPIF_DUMMY_CLASS(dpif_offload_dummy_class, "dummy");
DEFINE_DPIF_DUMMY_CLASS(dpif_offload_dummy_x_class, "dummy_x");
