/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#ifndef OPENVSWITCH_PACKETS_H
#define OPENVSWITCH_PACKETS_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include "openvswitch/tun-metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Tunnel information used in flow key and metadata. */
struct flow_tnl {
    ovs_be32 ip_dst;
    struct in6_addr ipv6_dst;
    ovs_be32 ip_src;
    struct in6_addr ipv6_src;
    ovs_be64 tun_id;
    uint16_t flags;
    uint8_t ip_tos;
    uint8_t ip_ttl;
    ovs_be16 tp_src;
    ovs_be16 tp_dst;
    ovs_be16 gbp_id;
    uint8_t  gbp_flags;
    uint8_t erspan_ver;
    uint32_t erspan_idx;
    uint8_t erspan_dir;
    uint8_t erspan_hwid;
    uint8_t pad1[6];     /* Pad to 64 bits. */
    struct tun_metadata metadata;
};

/* Some flags are exposed through OpenFlow while others are used only
 * internally. */

/* Public flags */
#define FLOW_TNL_F_OAM (1 << 0)

#define FLOW_TNL_PUB_F_MASK ((1 << 1) - 1)

/* Private flags */
#define FLOW_TNL_F_DONT_FRAGMENT (1 << 1)
#define FLOW_TNL_F_CSUM (1 << 2)
#define FLOW_TNL_F_KEY (1 << 3)

#define FLOW_TNL_F_MASK ((1 << 4) - 1)

/* Unfortunately, a "struct flow" sometimes has to handle OpenFlow port
 * numbers and other times datapath (dpif) port numbers.  This union allows
 * access to both. */
union flow_in_port {
    odp_port_t odp_port;
    ofp_port_t ofp_port;
};

union flow_vlan_hdr {
    ovs_be32 qtag;
    struct {
        ovs_be16 tpid;  /* ETH_TYPE_VLAN_DOT1Q or ETH_TYPE_DOT1AD */
        ovs_be16 tci;
    };
};

struct ovs_key_nsh {
    uint8_t flags;
    uint8_t ttl;
    uint8_t mdtype;
    uint8_t np;
    ovs_be32 path_hdr;
    ovs_be32 context[4];
};

/* NSH flags */
#define FLOW_NSH_F_OAM (1 << 0)
#define FLOW_NSH_F_CTX (1 << 1)

#define FLOW_NSH_F_MASK ((1 << 2) - 1)

#ifdef __cplusplus
}
#endif

#endif /* packets.h */
