/*
 * Copyright (c) 2011 Nicira, Inc.
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

#ifndef __CHECKER__
#error "Use this header only with sparse.  It is not a correct implementation."
#endif

#ifndef __NETINET_IN_SPARSE
#define __NETINET_IN_SPARSE 1

#include "openvswitch/types.h"
#include <inttypes.h>
#include <sys/socket.h>

typedef ovs_be16 in_port_t;
typedef ovs_be32 in_addr_t;

struct in_addr {
    in_addr_t s_addr;
};

struct sockaddr_in {
    sa_family_t sin_family;
    in_port_t sin_port;
    struct in_addr sin_addr;
};

struct in6_addr {
    union {
        uint8_t u_s6_addr[16];
    } u;
};

#define s6_addr u.u_s6_addr

extern const struct in6_addr in6addr_any;

#define IPPROTO_IP 0
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ICMP 1
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_AH 51
#define IPPROTO_ICMPV6 58
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60

/* All the IP options documented in Linux ip(7). */
#define IP_ADD_MEMBERSHIP 0
#define IP_DROP_MEMBERSHIP 1
#define IP_HDRINCL 2
#define IP_MTU 3
#define IP_MTU_DISCOVER 4
#define IP_MULTICAST_IF 5
#define IP_MULTICAST_LOOP 6
#define IP_MULTICAST_TTL 7
#define IP_NODEFRAG 8
#define IP_OPTIONS 9
#define IP_PKTINFO 10
#define IP_RECVERR 11
#define IP_RECVOPTS 12
#define IP_RECVTOS 13
#define IP_RECVTTL 14
#define IP_RETOPTS 15
#define IP_ROUTER_ALERT 16
#define IP_TOS 17
#define IP_TTL 18

#define INADDR_ANY              0x00000000
#define INADDR_BROADCAST        0xffffffff
#define INADDR_NONE             0xffffffff

#define INET6_ADDRSTRLEN 46

static inline ovs_be32 htonl(uint32_t x)
{
    return (OVS_FORCE ovs_be32) x;
}

static inline ovs_be16 htons(uint16_t x)
{
    return (OVS_FORCE ovs_be16) x;
}

static inline uint32_t ntohl(ovs_be32 x)
{
    return (OVS_FORCE uint32_t) x;
}

static inline uint16_t ntohs(ovs_be16 x)
{
    return (OVS_FORCE uint16_t) x;
}

in_addr_t inet_addr(const char *);
int inet_aton (const char *, struct in_addr *);
char *inet_ntoa(struct in_addr);
const char *inet_ntop(int, const void *, char *, socklen_t);
int inet_pton(int, const char *, void *);

#endif /* <netinet/in.h> sparse */
