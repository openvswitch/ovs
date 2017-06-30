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

#include "openvswitch/compiler.h"
#include "openvswitch/types.h"

struct dp_packet;
struct netdev;
struct dp_netdev;
struct rte_flow_attr;
struct rte_flow_item;
struct rte_flow_action;
struct rte_flow_error;

#ifdef DPDK_NETDEV
#include <rte_flow.h>

int dpdk_netdev_is_dpdk_port(struct dp_netdev *dp, odp_port_t in_port);
void netdev_dpdk_register(void);
void free_dpdk_buf(struct dp_packet *);
struct rte_flow*
netdev_dpdk_rte_flow_validate(struct netdev *netdev,
                              struct rte_flow_attr *attr,
                              struct rte_flow_item *item,
                              struct rte_flow_action *action,
                              struct rte_flow_error *error);
void
netdev_dpdk_get_pipeline(__attribute__ ((unused))const struct netdev *netdev,
                         struct dp_packet *packet,
                         void *pipeline_res);
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
