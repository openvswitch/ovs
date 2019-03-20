/*
 * Copyright (c) 2019 Mellanox Technologies, Ltd.
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

#ifndef NETDEV_VPORT_OFFLOADS_H
#define NETDEV_VPORT_OFFLOADS_H 1

#include "openvswitch/types.h"

struct netdev;
struct match;
struct nlattr;
struct offload_info;
struct dpif_flow_stats;

/* Thread-safety
 * =============
 *
 * Below API is NOT thread safe in following terms:
 *
 *  - The caller must be sure that none of these functions will be called
 *    simultaneously.  Even for different 'netdev's.
 *
 *  - The caller must be sure that 'netdev' will not be destructed/deallocated.
 *
 *  - The caller must be sure that 'netdev' configuration will not be changed.
 *    For example, simultaneous call of 'netdev_reconfigure()' for the same
 *    'netdev' is forbidden.
 *
 * For current implementation all above restrictions could be fulfilled by
 * taking the datapath 'port_mutex' in lib/dpif-netdev.c.  */

int netdev_rte_offloads_flow_put(struct netdev *netdev, struct match *match,
                                 struct nlattr *actions, size_t actions_len,
                                 const ovs_u128 *ufid,
                                 struct offload_info *info,
                                 struct dpif_flow_stats *stats);
int netdev_rte_offloads_flow_del(struct netdev *netdev, const ovs_u128 *ufid,
                                 struct dpif_flow_stats *stats);

#define DPDK_FLOW_OFFLOAD_API                   \
    .flow_put = netdev_rte_offloads_flow_put,   \
    .flow_del = netdev_rte_offloads_flow_del

#endif /* netdev-rte-offloads.h */
