/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#ifndef NETDEV_DPDK_H
#define NETDEV_DPDK_H

#include <config.h>

#include "openvswitch/compiler.h"

struct dp_packet;
struct netdev;

#ifdef DPDK_NETDEV

struct rte_flow;
struct rte_flow_error;
struct rte_flow_attr;
struct rte_flow_item;
struct rte_flow_action;
struct rte_flow_query_count;

void netdev_dpdk_register(void);
void free_dpdk_buf(struct dp_packet *);

bool netdev_dpdk_flow_api_supported(struct netdev *);

int
netdev_dpdk_rte_flow_destroy(struct netdev *netdev,
                             struct rte_flow *rte_flow,
                             struct rte_flow_error *error);
struct rte_flow *
netdev_dpdk_rte_flow_create(struct netdev *netdev,
                            const struct rte_flow_attr *attr,
                            const struct rte_flow_item *items,
                            const struct rte_flow_action *actions,
                            struct rte_flow_error *error);
int
netdev_dpdk_rte_flow_query_count(struct netdev *netdev,
                                 struct rte_flow *rte_flow,
                                 struct rte_flow_query_count *query,
                                 struct rte_flow_error *error);
int
netdev_dpdk_get_port_id(struct netdev *netdev);

#else

static inline void
netdev_dpdk_register(void)
{
    /* Nothing */
}
static inline void
free_dpdk_buf(struct dp_packet *buf OVS_UNUSED)
{
    /* Nothing */
}

#endif

#endif /* netdev-dpdk.h */
