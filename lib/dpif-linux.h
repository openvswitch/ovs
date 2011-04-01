/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

#ifndef DPIF_LINUX_H
#define DPIF_LINUX_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openvswitch/datapath-protocol.h"

struct ofpbuf;

struct dpif_linux_vport {
    /* Generic Netlink header. */
    uint8_t cmd;

    /* odp_vport header. */
    int dp_ifindex;
    uint32_t port_no;                      /* UINT32_MAX if unknown. */
    enum odp_vport_type type;

    /* Attributes. */
    const char *name;                      /* ODP_VPORT_ATTR_NAME. */
    const struct rtnl_link_stats64 *stats; /* ODP_VPORT_ATTR_STATS. */
    const uint8_t *address;                /* ODP_VPORT_ATTR_ADDRESS. */
    int mtu;                               /* ODP_VPORT_ATTR_MTU. */
    const struct nlattr *options;          /* ODP_VPORT_ATTR_OPTIONS. */
    size_t options_len;
    int ifindex;                           /* ODP_VPORT_ATTR_IFINDEX. */
    int iflink;                            /* ODP_VPORT_ATTR_IFLINK. */
};

void dpif_linux_vport_init(struct dpif_linux_vport *);

int dpif_linux_vport_transact(const struct dpif_linux_vport *request,
                              struct dpif_linux_vport *reply,
                              struct ofpbuf **bufp);
int dpif_linux_vport_get(const char *name, struct dpif_linux_vport *reply,
                         struct ofpbuf **bufp);

bool dpif_linux_is_internal_device(const char *name);

int dpif_linux_vport_send(int dp_ifindex, uint32_t port_no,
                          const void *data, size_t size);

#endif /* dpif-linux.h */
