/*
 * Copyright (c) 2017 Red Hat, Inc.
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

#ifndef DPIF_NETLINK_RTNL_H
#define DPIF_NETLINK_RTNL_H 1

#include <errno.h>

#include "netdev.h"

/* Declare these to keep sparse happy. */
int dpif_netlink_rtnl_port_create(struct netdev *netdev);
int dpif_netlink_rtnl_port_destroy(const char *name, const char *type);

bool dpif_netlink_rtnl_probe_oot_tunnels(void);

#ifndef __linux__
/* Dummy implementations for non Linux builds. */

static inline int
dpif_netlink_rtnl_port_create(struct netdev *netdev OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static inline int
dpif_netlink_rtnl_port_destroy(const char *name OVS_UNUSED,
                               const char *type OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static inline bool
dpif_netlink_rtnl_probe_oot_tunnels(void)
{
    return true;
}

#endif

#endif /* DPIF_NETLINK_RTNL_H */
