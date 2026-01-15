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
#include "netdev-offload-dpdk.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "util.h"

#include "openvswitch/json.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_dpdk);

#define DEFAULT_OFFLOAD_THREAD_NB 1
#define MAX_OFFLOAD_THREAD_NB 10

static unsigned int offload_thread_nb = DEFAULT_OFFLOAD_THREAD_NB;

/* dpif offload interface for the dpdk rte_flow implementation. */
struct dpif_offload_dpdk {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

static struct dpif_offload_dpdk *
dpif_offload_dpdk_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_dpdk_class);
    return CONTAINER_OF(offload, struct dpif_offload_dpdk, offload);
}

static int
dpif_offload_dpdk_enable_offload(struct dpif_offload *offload_,
                                 struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, offload_);
    return 0;
}

static int
dpif_offload_dpdk_cleanup_offload(struct dpif_offload *offload_ OVS_UNUSED,
                                  struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, NULL);
    return 0;
}

static int
dpif_offload_dpdk_port_add(struct dpif_offload *offload_,
                           struct netdev *netdev, odp_port_t port_no)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port = xmalloc(sizeof *port);

    if (dpif_offload_port_mgr_add(offload->port_mgr, port, netdev,
                                  port_no, false)) {
        if (dpif_offload_enabled()) {
            return dpif_offload_dpdk_enable_offload(offload_, port);
        }
        return 0;
    }

    free(port);
    return EEXIST;
}

static void
dpif_offload_dpdk_free_port(struct dpif_offload_port_mgr_port *port)
{
    netdev_close(port->netdev);
    free(port);
}

static int
dpif_offload_dpdk_port_del(struct dpif_offload *offload_, odp_port_t port_no)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port;
    int ret = 0;

    port = dpif_offload_port_mgr_remove(offload->port_mgr, port_no);
    if (port) {
        if (dpif_offload_enabled()) {
            ret = dpif_offload_dpdk_cleanup_offload(offload_, port);
        }
        ovsrcu_postpone(dpif_offload_dpdk_free_port, port);
    }
    return ret;
}

static int
dpif_offload_dpdk_port_dump_start(const struct dpif_offload *offload_,
                                  void **statep)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    return dpif_offload_port_mgr_port_dump_start(offload->port_mgr, statep);
}

static int
dpif_offload_dpdk_port_dump_next(const struct dpif_offload *offload_,
                                 void *state,
                                 struct dpif_offload_port *port)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    return dpif_offload_port_mgr_port_dump_next(offload->port_mgr, state,
                                                port);
}

static int
dpif_offload_dpdk_port_dump_done(const struct dpif_offload *offload_,
                                 void *state)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    return dpif_offload_port_mgr_port_dump_done(offload->port_mgr, state);
}

static struct netdev *
dpif_offload_dpdk_get_netdev(struct dpif_offload *offload_, odp_port_t port_no)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port;

    port = dpif_offload_port_mgr_find_by_odp_port(offload->port_mgr, port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

static int
dpif_offload_dpdk_open(const struct dpif_offload_class *offload_class,
                       struct dpif *dpif, struct dpif_offload **offload_)
{
    struct dpif_offload_dpdk *offload;

    offload = xmalloc(sizeof *offload);

    dpif_offload_init(&offload->offload, offload_class, dpif);
    offload->port_mgr = dpif_offload_port_mgr_init();
    offload->once_enable = (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;

    *offload_ = &offload->offload;
    return 0;
}

static void
dpif_offload_dpdk_close(struct dpif_offload *offload_)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port;

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
        dpif_offload_dpdk_port_del(offload_, port->port_no);
    }

    dpif_offload_port_mgr_uninit(offload->port_mgr);
    ovsthread_once_destroy(&offload->once_enable);
    free(offload);
}

/* XXX: External reference, will be removed after full integration. */
void dpdk_offload_thread_set_thread_nb(unsigned int thread_nb);

static void
dpif_offload_dpdk_set_config(struct dpif_offload *offload_,
                             const struct smap *other_cfg)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload->once_enable)) {
            struct dpif_offload_port_mgr_port *port;

            offload_thread_nb = smap_get_ullong(other_cfg,
                                                "n-offload-threads",
                                                DEFAULT_OFFLOAD_THREAD_NB);
            if (offload_thread_nb == 0 ||
                offload_thread_nb > MAX_OFFLOAD_THREAD_NB) {
                VLOG_WARN("netdev: Invalid number of threads requested: %u",
                          offload_thread_nb);
                offload_thread_nb = DEFAULT_OFFLOAD_THREAD_NB;
            }

            if (smap_get(other_cfg, "n-offload-threads")) {
                VLOG_INFO("Flow API using %u thread%s",
                          offload_thread_nb,
                          offload_thread_nb > 1 ? "s" : "");
            }

            dpdk_offload_thread_set_thread_nb(offload_thread_nb);

            DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
                dpif_offload_dpdk_enable_offload(offload_, port);
            }

            ovsthread_once_done(&offload->once_enable);
        }
    }
}

static void
dpif_offload_dpdk_get_debug(const struct dpif_offload *offload_, struct ds *ds,
                            struct json *json)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    if (json) {
        struct json *json_ports = json_object_create();
        struct dpif_offload_port_mgr_port *port;

        DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
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
        struct dpif_offload_port_mgr_port *port;

        DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
            ds_put_format(ds, "  - %s: port_no: %u\n",
                          netdev_get_name(port->netdev), port->port_no);
        }
    }
}

static bool
dpif_offload_dpdk_can_offload(struct dpif_offload *offload OVS_UNUSED,
                              struct netdev *netdev)
{
    if (netdev_vport_is_vport_class(netdev->netdev_class)
        && strcmp(netdev_get_dpif_type(netdev), "netdev")) {
        VLOG_DBG("%s: vport doesn't belong to the netdev datapath, skipping",
                 netdev_get_name(netdev));
        return false;
    }

    return netdev_dpdk_flow_api_supported(netdev, true);
}

static uint64_t
dpif_offload_dpdk_flow_count(const struct dpif_offload *offload_)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);
    struct dpif_offload_port_mgr_port *port;
    uint64_t total = 0;

    if (!dpif_offload_enabled()) {
        return 0;
    }

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload->port_mgr) {
        total += netdev_offload_dpdk_flow_count(port->netdev);
    }

    return total;
}

static int
dpif_offload_dpdk_netdev_flow_flush(const struct dpif_offload *offload
                                    OVS_UNUSED, struct netdev *netdev)
{
    return netdev_offload_dpdk_flow_flush(netdev);
}

static int
dpif_offload_dpdk_netdev_hw_post_process(
    const struct dpif_offload *offload_ OVS_UNUSED, struct netdev *netdev,
    struct dp_packet *packet)
{
    return netdev_offload_dpdk_hw_miss_packet_recover(netdev, packet);
}

struct dpif_offload_class dpif_offload_dpdk_class = {
    .type = "dpdk",
    .impl_type = DPIF_OFFLOAD_IMPL_FLOWS_DPIF_SYNCED,
    .supported_dpif_types = (const char *const[]) {"netdev", NULL},
    .open = dpif_offload_dpdk_open,
    .close = dpif_offload_dpdk_close,
    .set_config = dpif_offload_dpdk_set_config,
    .get_debug = dpif_offload_dpdk_get_debug,
    .can_offload = dpif_offload_dpdk_can_offload,
    .port_add = dpif_offload_dpdk_port_add,
    .port_del = dpif_offload_dpdk_port_del,
    .port_dump_start = dpif_offload_dpdk_port_dump_start,
    .port_dump_next = dpif_offload_dpdk_port_dump_next,
    .port_dump_done = dpif_offload_dpdk_port_dump_done,
    .flow_count = dpif_offload_dpdk_flow_count,
    .get_netdev = dpif_offload_dpdk_get_netdev,
    .netdev_flow_flush = dpif_offload_dpdk_netdev_flow_flush,
    .netdev_hw_post_process = dpif_offload_dpdk_netdev_hw_post_process,
};
