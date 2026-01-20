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

#ifndef DPIF_OFFLOAD_DPDK_PRIVATE_H
#define DPIF_OFFLOAD_DPDK_PRIVATE_H

/* Forward declarations of private structures. */
struct dpdk_offload;
struct netdev;

/* DPIF offload dpdk implementation-specific functions.  These should only be
 * used by the associated netdev offload provider, i.e.,
 * dpif-offload-dpdk-netdev. */
unsigned int dpdk_offload_thread_id(void);
void dpdk_flow_unreference(struct dpdk_offload *offload, unsigned pmd_id,
                           void *flow_reference);
uint32_t dpdk_allocate_flow_mark(struct dpdk_offload *);
void dpdk_free_flow_mark(struct dpdk_offload *, uint32_t flow_mark);
struct netdev *dpdk_offload_get_netdev(const struct dpdk_offload *,
                                       odp_port_t port_no);
void dpdk_offload_traverse_ports(
    const struct dpdk_offload *offload,
    bool (*cb)(struct netdev *, odp_port_t, void *), void *aux);

/* dpif-offload-dpdk-netdev specific offload functions.  These should only be
 * used by the associated dpif offload provider, i.e., dpif-offload-dpdk. */
int dpdk_netdev_offload_init(struct netdev *,
                             unsigned int offload_thread_count);
void dpdk_netdev_offload_uninit(struct netdev *);
int dpdk_netdev_flow_flush(struct dpdk_offload *, struct netdev *);
uint64_t dpdk_netdev_flow_count(struct netdev *,
                                unsigned int offload_thread_count);
uint64_t dpdk_netdev_flow_count_by_thread(struct netdev *, unsigned int tid);
int dpdk_netdev_hw_miss_packet_recover(struct dpdk_offload *, struct netdev *,
                                       unsigned pmd_id, struct dp_packet *,
                                       void **flow_reference);
int dpdk_netdev_flow_put(struct dpdk_offload *, unsigned pmd_id,
                         void *flow_reference, struct netdev *, struct match *,
                         struct nlattr *actions, size_t actions_len,
                         const ovs_u128 *ufid, odp_port_t orig_in_port,
                         void **previous_flow_reference,
                         struct dpif_flow_stats *);
int dpdk_netdev_flow_del(struct dpdk_offload *, struct netdev *,
                         unsigned pmd_id, const ovs_u128 *ufid,
                         void *flow_reference, struct dpif_flow_stats *);
int dpdk_netdev_flow_get(struct netdev *, struct match *,
                         struct nlattr **actions, const ovs_u128 *ufid,
                         struct dpif_flow_stats *, struct dpif_flow_attrs *,
                         struct ofpbuf *buf);

#endif /* DPIF_OFFLOAD_DPDK_PRIVATE_H */
