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

 #ifndef NETDEV_OFFLOAD_DPDK_H
 #define NETDEV_OFFLOAD_DPDK_H

/* Forward declarations of private structures. */
struct netdev;
struct offload_info;

/* Netdev-specific offload functions.  These should only be used by the
 * associated dpif offload provider. */
int netdev_offload_dpdk_init(struct netdev *);
void netdev_offload_dpdk_uninit(struct netdev *);
int netdev_offload_dpdk_flow_flush(struct netdev *);
uint64_t netdev_offload_dpdk_flow_count(struct netdev *);
int netdev_offload_dpdk_hw_miss_packet_recover(struct netdev *,
                                               struct dp_packet *);
#ifdef DPDK_NETDEV
int netdev_offload_dpdk_flow_put(struct netdev *, struct match *,
                                 struct nlattr *actions, size_t actions_len,
                                 const ovs_u128 *ufid, struct offload_info *,
                                 struct dpif_flow_stats *);
int netdev_offload_dpdk_flow_del(struct netdev *, const ovs_u128 *ufid,
                                 struct dpif_flow_stats *);
int netdev_offload_dpdk_flow_get(struct netdev *, struct match *,
                                 struct nlattr **actions, const ovs_u128 *ufid,
                                 struct dpif_flow_stats *,
                                 struct dpif_flow_attrs *, struct ofpbuf *buf);
#else
static inline int
netdev_offload_dpdk_flow_put(struct netdev *netdev OVS_UNUSED,
                              struct match *match OVS_UNUSED,
                              struct nlattr *actions OVS_UNUSED,
                              size_t actions_len OVS_UNUSED,
                              const ovs_u128 *ufid OVS_UNUSED,
                              struct offload_info *info OVS_UNUSED,
                              struct dpif_flow_stats *stats OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static inline int
netdev_offload_dpdk_flow_del(struct netdev *netdev OVS_UNUSED,
                             const ovs_u128 *ufid OVS_UNUSED,
                             struct dpif_flow_stats *stats OVS_UNUSED)
{
    return EOPNOTSUPP;
}

static inline int
netdev_offload_dpdk_flow_get(struct netdev *netdev OVS_UNUSED,
                             struct match *match OVS_UNUSED,
                             struct nlattr **actions OVS_UNUSED,
                             const ovs_u128 *ufid OVS_UNUSED,
                             struct dpif_flow_stats *stats OVS_UNUSED,
                             struct dpif_flow_attrs *attrs OVS_UNUSED,
                             struct ofpbuf *buf OVS_UNUSED)
{
    return EOPNOTSUPP;
}
#endif /* #ifdef DPDK_NETDEV */

#endif /* NETDEV_OFFLOAD_DPDK_H */
