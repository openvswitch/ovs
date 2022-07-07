/*
 * Copyright (c) 2021 Intel Corporation.
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

#ifndef DPIF_NETDEV_PRIVATE_DPIF_H
#define DPIF_NETDEV_PRIVATE_DPIF_H 1

#include "openvswitch/types.h"

/* Forward declarations to avoid including files. */
struct dp_netdev_pmd_thread;
struct dp_packet_batch;
struct ds;

/* Typedef for DPIF functions.
 * Returns whether all packets were processed successfully.
 */
typedef int32_t (*dp_netdev_input_func)(struct dp_netdev_pmd_thread *pmd,
                                        struct dp_packet_batch *packets,
                                        odp_port_t port_no);

/* Probe a DPIF implementation. This allows the implementation to validate CPU
 * ISA availability. Returns -ENOTSUP if not available, returns 0 if valid to
 * use.
 */
typedef int32_t (*dp_netdev_input_func_probe)(void);

/* Structure describing each available DPIF implementation. */
struct dpif_netdev_impl_info_t {
    /* Function pointer to execute to have this DPIF implementation run. */
    dp_netdev_input_func input_func;
    /* Function pointer to execute to check the CPU ISA is available to run. If
     * not necessary, it must be set to NULL which implies that it is always
     * valid to use. */
    dp_netdev_input_func_probe probe;
    /* Name used to select this DPIF implementation. */
    const char *name;
};

/* This function returns all available implementations to the caller. */
void
dp_netdev_impl_get(struct ds *reply, struct dp_netdev_pmd_thread **pmd_list,
                   size_t n);

/* Returns the default DPIF which is first ./configure selected, but can be
 * overridden at runtime. */
dp_netdev_input_func dp_netdev_impl_get_default(void);

/* Overrides the default DPIF with the user set DPIF. */
int32_t dp_netdev_impl_set_default_by_name(const char *name);

bool
dp_netdev_simple_match_enabled(const struct dp_netdev_pmd_thread *pmd,
                               odp_port_t in_port);

uint64_t
dp_netdev_simple_match_mark(odp_port_t in_port, ovs_be16 dl_type,
                            uint8_t nw_frag, ovs_be16 vlan_tci);
struct dp_netdev_flow *
dp_netdev_simple_match_lookup(const struct dp_netdev_pmd_thread *pmd,
                              odp_port_t in_port, ovs_be16 dl_type,
                              uint8_t nw_frag, ovs_be16 vlan_tci);

/* Available DPIF implementations below. */
int32_t
dp_netdev_input(struct dp_netdev_pmd_thread *pmd,
                struct dp_packet_batch *packets,
                odp_port_t in_port);

/* AVX512 enabled DPIF implementation function. */
int32_t
dp_netdev_input_outer_avx512(struct dp_netdev_pmd_thread *pmd,
                             struct dp_packet_batch *packets,
                             odp_port_t in_port);

#endif /* netdev-private.h */
