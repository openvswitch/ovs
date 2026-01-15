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
#include "netdev-provider.h"
#include "util.h"

#include "openvswitch/json.h"

struct dpif_offload_dummy {
    struct dpif_offload offload;
    struct dpif_offload_port_mgr *port_mgr;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

static struct dpif_offload_dummy *
dpif_offload_dummy_cast(const struct dpif_offload *offload)
{
    return CONTAINER_OF(offload, struct dpif_offload_dummy, offload);
}

static void
dpif_offload_dummy_enable_offload(struct dpif_offload *dpif_offload,
                                  struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, dpif_offload);
}

static void
dpif_offload_dummy_cleanup_offload(struct dpif_offload_port_mgr_port *port)
{
    dpif_offload_set_netdev_offload(port->netdev, NULL);
}

static int
dpif_offload_dummy_port_add(struct dpif_offload *dpif_offload,
                            struct netdev *netdev, odp_port_t port_no)
{
    struct dpif_offload_port_mgr_port *port = xmalloc(sizeof *port);
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);
    if (dpif_offload_port_mgr_add(offload_dummy->port_mgr, port, netdev,
                                  port_no, false)) {

        if (dpif_offload_enabled()) {
            dpif_offload_dummy_enable_offload(dpif_offload, port);
        }
        return 0;
    }

    free(port);
    return EEXIST;
}

static void
dpif_offload_dummy_free_port(struct dpif_offload_port_mgr_port *port)
{
    netdev_close(port->netdev);
    free(port);
}

static int
dpif_offload_dummy_port_del(struct dpif_offload *dpif_offload,
                            odp_port_t port_no)
{
    struct dpif_offload_dummy *offload_dummy;
    struct dpif_offload_port_mgr_port *port;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);

    port = dpif_offload_port_mgr_remove(offload_dummy->port_mgr, port_no);
    if (port) {
        if (dpif_offload_enabled()) {
            dpif_offload_dummy_cleanup_offload(port);
        }
        ovsrcu_postpone(dpif_offload_dummy_free_port, port);
    }
    return 0;
}

static struct netdev *
dpif_offload_dummy_get_netdev(struct dpif_offload *dpif_offload,
                              odp_port_t port_no)
{
    struct dpif_offload_dummy *offload_dummy;
    struct dpif_offload_port_mgr_port *port;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);

    port = dpif_offload_port_mgr_find_by_odp_port(offload_dummy->port_mgr,
                                                  port_no);
    if (!port) {
        return NULL;
    }

    return port->netdev;
}

static int
dpif_offload_dummy_open(const struct dpif_offload_class *offload_class,
                        struct dpif *dpif, struct dpif_offload **dpif_offload)
{
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = xmalloc(sizeof *offload_dummy);

    dpif_offload_init(&offload_dummy->offload, offload_class, dpif);
    offload_dummy->port_mgr = dpif_offload_port_mgr_init();
    offload_dummy->once_enable =
        (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;

    *dpif_offload = &offload_dummy->offload;
    return 0;
}

static void
dpif_offload_dummy_close(struct dpif_offload *dpif_offload)
{
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);

    /* The ofproto layer may not call dpif_port_del() for all ports,
     * especially internal ones, so we need to clean up any remaining ports. */
    struct dpif_offload_port_mgr_port *port;

    DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload_dummy->port_mgr) {
        dpif_offload_dummy_port_del(dpif_offload, port->port_no);
    }

    dpif_offload_port_mgr_uninit(offload_dummy->port_mgr);
    ovsthread_once_destroy(&offload_dummy->once_enable);
    free(offload_dummy);
}

static void
dpif_offload_dummy_set_config(struct dpif_offload *dpif_offload,
                              const struct smap *other_cfg)
{
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = dpif_offload_dummy_cast(dpif_offload);

    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload_dummy->once_enable)) {
            struct dpif_offload_port_mgr_port *port;

            DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port,
                                                 offload_dummy->port_mgr) {
                dpif_offload_dummy_enable_offload(dpif_offload, port);
            }

            ovsthread_once_done(&offload_dummy->once_enable);
        }
    }
}

static void
dpif_offload_dummy_get_debug(const struct dpif_offload *offload, struct ds *ds,
                             struct json *json)
{
    struct dpif_offload_dummy *offload_dummy;

    offload_dummy = dpif_offload_dummy_cast(offload);

    if (json) {
        struct json *json_ports = json_object_create();
        struct dpif_offload_port_mgr_port *port;

        DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload_dummy->port_mgr) {
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

        DPIF_OFFLOAD_PORT_MGR_PORT_FOR_EACH (port, offload_dummy->port_mgr) {
            ds_put_format(ds, "  - %s: port_no: %u\n",
                          netdev_get_name(port->netdev), port->port_no);
        }
    }
}

static bool
dpif_offload_dummy_can_offload(struct dpif_offload *dpif_offload OVS_UNUSED,
                               struct netdev *netdev)
{
    return is_dummy_netdev_class(netdev->netdev_class);
}

#define DEFINE_DPIF_DUMMY_CLASS(NAME, TYPE_STR)                        \
    struct dpif_offload_class NAME = {                                 \
        .type = TYPE_STR,                                              \
        .supported_dpif_types = (const char *const[]) {"dummy", NULL}, \
        .open = dpif_offload_dummy_open,                               \
        .close = dpif_offload_dummy_close,                             \
        .set_config = dpif_offload_dummy_set_config,                   \
        .get_debug = dpif_offload_dummy_get_debug,                     \
        .can_offload = dpif_offload_dummy_can_offload,                 \
        .port_add = dpif_offload_dummy_port_add,                       \
        .port_del = dpif_offload_dummy_port_del,                       \
        .get_netdev = dpif_offload_dummy_get_netdev,                   \
    }

DEFINE_DPIF_DUMMY_CLASS(dpif_offload_dummy_class, "dummy");
DEFINE_DPIF_DUMMY_CLASS(dpif_offload_dummy_x_class, "dummy_x");
