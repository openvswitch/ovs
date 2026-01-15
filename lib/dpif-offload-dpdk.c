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

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "util.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_offload_dpdk);

#define DEFAULT_OFFLOAD_THREAD_NB 1
#define MAX_OFFLOAD_THREAD_NB 10

static unsigned int offload_thread_nb = DEFAULT_OFFLOAD_THREAD_NB;

/* dpif offload interface for the dpdk rte_flow implementation. */
struct dpif_offload_dpdk {
    struct dpif_offload offload;

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
dpif_offload_dpdk_open(const struct dpif_offload_class *offload_class,
                       struct dpif *dpif, struct dpif_offload **offload_)
{
    struct dpif_offload_dpdk *offload;

    offload = xmalloc(sizeof *offload);

    dpif_offload_init(&offload->offload, offload_class, dpif);
    offload->once_enable = (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;

    *offload_ = &offload->offload;
    return 0;
}

static void
dpif_offload_dpdk_close(struct dpif_offload *offload_)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    ovsthread_once_destroy(&offload->once_enable);
    free(offload);
}

static void
dpif_offload_dpdk_set_config(struct dpif_offload *offload_,
                             const struct smap *other_cfg)
{
    struct dpif_offload_dpdk *offload = dpif_offload_dpdk_cast(offload_);

    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload->once_enable)) {

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

            ovsthread_once_done(&offload->once_enable);
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

struct dpif_offload_class dpif_offload_dpdk_class = {
    .type = "dpdk",
    .supported_dpif_types = (const char *const[]) {"netdev", NULL},
    .open = dpif_offload_dpdk_open,
    .close = dpif_offload_dpdk_close,
    .set_config = dpif_offload_dpdk_set_config,
    .can_offload = dpif_offload_dpdk_can_offload,
};

/* XXX: Temporary functions below, which will be removed once fully
 *      refactored. */
unsigned int dpif_offload_dpdk_get_thread_nb(void);
unsigned int dpif_offload_dpdk_get_thread_nb(void)
{
    return offload_thread_nb;
}
