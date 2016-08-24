/*
 * Copyright (c) 2008, 2011 Nicira, Inc.
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

#ifndef DHCP_H
#define DHCP_H 1

#include <stdint.h>
#include "packets.h"
#include "util.h"

/* Ports used by DHCP. */
#define DHCP_SERVER_PORT        67       /* Port used by DHCP server. */
#define DHCP_CLIENT_PORT        68       /* Port used by DHCP client. */

#define DHCP_MAGIC_COOKIE 0x63825363

#define DHCP_HEADER_LEN 236
struct dhcp_header {
    uint8_t op;                 /* DHCP_BOOTREQUEST or DHCP_BOOTREPLY. */
    uint8_t htype;              /* ARP_HRD_ETHERNET (typically). */
    uint8_t hlen;               /* ETH_ADDR_LEN (typically). */
    uint8_t hops;               /* Hop count; set to 0 by client. */
    ovs_be32 xid;               /* Transaction ID. */
    ovs_be16 secs;              /* Since client started address acquisition. */
    ovs_be16 flags;             /* DHCP_FLAGS_*. */
    ovs_be32 ciaddr;            /* Client IP, if it has a lease for one. */
    ovs_be32 yiaddr;            /* Client ("your") IP address. */
    ovs_be32 siaddr;            /* Next server IP address. */
    ovs_be32 giaddr;            /* Relay agent IP address. */
    uint8_t chaddr[16];         /* Client hardware address. */
    char sname[64];             /* Optional server host name. */
    char file[128];             /* Boot file name. */
    /* Followed by variable-length options field. */
};
BUILD_ASSERT_DECL(DHCP_HEADER_LEN == sizeof(struct dhcp_header));

#define DHCP_OP_REQUEST    1
#define DHCP_OP_REPLY      2

#define DHCP_MSG_DISCOVER  1
#define DHCP_MSG_OFFER     2
#define DHCP_MSG_REQUEST   3
#define DHCP_MSG_ACK       5

#define DHCP_OPT_MSG_TYPE  53
#define DHCP_OPT_END       255

#endif /* dhcp.h */
