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
struct dpif_offload_dpdk;
struct netdev;

/* DPIF offload dpdk implementation-specific functions.  These should only be
 * used by the associated netdev offload provider, i.e.,
 * dpif-offload-dpdk-netdev. */
unsigned int dpdk_offload_thread_id(void);
void dpif_offload_dpdk_flow_unreference(struct dpif_offload_dpdk *offload,
                                        unsigned pmd_id, void *flow_reference);
uint32_t dpif_offload_dpdk_allocate_flow_mark(struct dpif_offload_dpdk *);
void dpif_offload_dpdk_free_flow_mark(struct dpif_offload_dpdk *,
                                      uint32_t flow_mark);
struct netdev *dpif_offload_dpdk_get_netdev(
    const struct dpif_offload_dpdk *, odp_port_t port_no);
void dpif_offload_dpdk_traverse_ports(
    const struct dpif_offload_dpdk *offload,
    bool (*cb)(struct netdev *, odp_port_t, void *), void *aux);


/* dpif-offload-dpdk-netdev specific offload functions.  These should only be
 * used by the associated dpif offload provider, i.e., dpif-offload-dpdk. */
int netdev_offload_dpdk_init(struct netdev *,
                             unsigned int offload_thread_count);
void netdev_offload_dpdk_uninit(struct netdev *);
int netdev_offload_dpdk_flow_flush(struct dpif_offload_dpdk *,
                                   struct netdev *);
uint64_t netdev_offload_dpdk_flow_count(struct netdev *,
                                        unsigned int offload_thread_count);
uint64_t netdev_offload_dpdk_flow_count_by_thread(struct netdev *,
                                                  unsigned int tid);
int netdev_offload_dpdk_hw_miss_packet_recover(struct dpif_offload_dpdk *,
                                               struct netdev *,
                                               unsigned pmd_id,
                                               struct dp_packet *,
                                               void **flow_reference);
int netdev_offload_dpdk_flow_put(struct dpif_offload_dpdk *,
                                 unsigned pmd_id, void *flow_reference,
                                 struct netdev *, struct match *,
                                 struct nlattr *actions, size_t actions_len,
                                 const ovs_u128 *ufid, odp_port_t orig_in_port,
                                 void **previous_flow_reference,
                                 struct dpif_flow_stats *);
int netdev_offload_dpdk_flow_del(struct dpif_offload_dpdk *,
                                 struct netdev *, unsigned pmd_id,
                                 const ovs_u128 *ufid,
                                 void *flow_reference,
                                 struct dpif_flow_stats *);
int netdev_offload_dpdk_flow_get(struct netdev *, struct match *,
                                 struct nlattr **actions, const ovs_u128 *ufid,
                                 struct dpif_flow_stats *,
                                 struct dpif_flow_attrs *, struct ofpbuf *buf);

#endif /* DPIF_OFFLOAD_DPDK_PRIVATE_H */
