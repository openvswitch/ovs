/*
 * Copyright (c) 2010, 2011, 2013, 2015 Nicira, Inc.
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

#ifndef NETDEV_VPORT_PRIVATE_H
#define NETDEV_VPORT_PRAVITE_H 1

#include <stdbool.h>
#include <stddef.h>
#include "compiler.h"
#include "netdev.h"
#include "netdev-provider.h"
#include "ovs-thread.h"

struct netdev_vport {
    struct netdev up;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    struct eth_addr etheraddr;
    struct netdev_stats stats;

    /* Tunnels. */
    struct netdev_tunnel_config tnl_cfg;
    char egress_iface[IFNAMSIZ];
    bool carrier_status;

    /* Patch Ports. */
    char *peer;
};

int netdev_vport_construct(struct netdev *);

static bool
is_vport_class(const struct netdev_class *class)
{
    return class->construct == netdev_vport_construct;
}

static inline struct netdev_vport *
netdev_vport_cast(const struct netdev *netdev)
{
    ovs_assert(is_vport_class(netdev_get_class(netdev)));
    return CONTAINER_OF(netdev, struct netdev_vport, up);
}

#endif
