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

#ifndef NETDEV_VPORT_NATIVE_TNL_H
#define NETDEV_VPORT_NATIVE_TNL_H 1

#include <stdbool.h>
#include <stddef.h>
#include "compiler.h"
#include "dp-packet.h"
#include "packets.h"
#include "unixctl.h"

struct netdev;
struct ovs_action_push_tnl;
struct netdev_tnl_build_header_params;

int
netdev_gre_build_header(const struct netdev *netdev,
                        struct ovs_action_push_tnl *data,
                        const struct netdev_tnl_build_header_params *params);

void
netdev_gre_push_header(struct dp_packet *packet,
                       const struct ovs_action_push_tnl *data);
struct dp_packet *
netdev_gre_pop_header(struct dp_packet *packet);

void
netdev_tnl_push_udp_header(struct dp_packet *packet,
                           const struct ovs_action_push_tnl *data);
int
netdev_geneve_build_header(const struct netdev *netdev,
                           struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params);

struct dp_packet *
netdev_geneve_pop_header(struct dp_packet *packet);

int
netdev_vxlan_build_header(const struct netdev *netdev,
                          struct ovs_action_push_tnl *data,
                          const struct netdev_tnl_build_header_params *params);

struct dp_packet *
netdev_vxlan_pop_header(struct dp_packet *packet);

static inline bool
netdev_tnl_is_header_ipv6(const void *header)
{
    const struct eth_header *eth;
    eth = header;
    return eth->eth_type == htons(ETH_TYPE_IPV6);
}

static inline struct ip_header *
netdev_tnl_ip_hdr(void *eth)
{
    return (void *)((char *)eth + sizeof (struct eth_header));
}

static inline struct ovs_16aligned_ip6_hdr *
netdev_tnl_ipv6_hdr(void *eth)
{
    return (void *)((char *)eth + sizeof (struct eth_header));
}

void *
netdev_tnl_ip_build_header(struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params,
                           uint8_t next_proto);

extern uint16_t tnl_udp_port_min;
extern uint16_t tnl_udp_port_max;

static inline ovs_be16
netdev_tnl_get_src_port(struct dp_packet *packet)
{
    uint32_t hash;

    hash = dp_packet_get_rss_hash(packet);

    return htons((((uint64_t) hash * (tnl_udp_port_max - tnl_udp_port_min)) >> 32) +
                 tnl_udp_port_min);
}

void *
netdev_tnl_ip_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl,
                             unsigned int *hlen);
void *
netdev_tnl_push_ip_header(struct dp_packet *packet,
                          const void *header, int size, int *ip_tot_size);
void
netdev_tnl_egress_port_range(struct unixctl_conn *conn, int argc,
                             const char *argv[], void *aux OVS_UNUSED);
#endif
