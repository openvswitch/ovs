/*
 * Copyright (c) 2011, 2013, 2014, 2015, 2017 Nicira, Inc.
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

#define NETINET_IN_H_INCLUDED 1

#ifndef SYS_TYPES_H_INCLUDED
#error "Must include <sys/types.h> before <netinet/in.h> for FreeBSD support"
#endif

#ifndef _NETINET_IN_H
#define _NETINET_IN_H 1

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

/* Ditto, for IPv6.  */
struct sockaddr_in6 {
    sa_family_t sin6_family;
    in_port_t sin6_port;        /* Transport layer port # */
    uint32_t sin6_flowinfo;     /* IPv6 flow information */
    struct in6_addr sin6_addr;  /* IPv6 address */
    uint32_t sin6_scope_id;     /* IPv6 scope-id */
};

#define IPPROTO_IP 0
#define IPPROTO_IPV6  41
#define IPPROTO_HOPOPTS 0
#define IPPROTO_ICMP 1
#define IPPROTO_IGMP 2
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ROUTING 43
#define IPPROTO_FRAGMENT 44
#define IPPROTO_GRE 47
#define IPPROTO_ESP 50
#define IPPROTO_AH 51
#define IPPROTO_ICMPV6 58
#define IPPROTO_NONE 59
#define IPPROTO_DSTOPTS 60
#define IPPROTO_SCTP 132

#define IPPORT_FTP 21
#define IPPORT_TFTP 69

/* All the IP options documented in Linux ip(7). */
#define IP_ADD_MEMBERSHIP 35
#define IP_DROP_MEMBERSHIP 36
#define IP_HDRINCL 3
#define IP_MTU 14
#define IP_MTU_DISCOVER 10
#define IP_MULTICAST_IF 32
#define IP_MULTICAST_LOOP 34
#define IP_MULTICAST_TTL 33
#define IP_NODEFRAG 22
#define IP_OPTIONS 4
#define IP_PKTINFO 8
#define IP_RECVERR 11
#define IP_RECVOPTS 6
#define IP_RECVTOS 13
#define IP_RECVTTL 12
#define IP_RETOPTS 7
#define IP_ROUTER_ALERT 5
#define IP_TOS 1
#define IP_TTL 2

#define INADDR_ANY              0x00000000
#define INADDR_BROADCAST        0xffffffff
#define INADDR_LOOPBACK         0x7f000001
#define INADDR_NONE             0xffffffff

#define IN6_IS_ADDR_V4MAPPED(X)                 \
    ((X)->s6_addr[0] == 0 &&                    \
     (X)->s6_addr[1] == 0 &&                    \
     (X)->s6_addr[2] == 0 &&                    \
     (X)->s6_addr[3] == 0 &&                    \
     (X)->s6_addr[4] == 0 &&                    \
     (X)->s6_addr[5] == 0 &&                    \
     (X)->s6_addr[6] == 0 &&                    \
     (X)->s6_addr[7] == 0 &&                    \
     (X)->s6_addr[8] == 0 &&                    \
     (X)->s6_addr[9] == 0 &&                    \
     (X)->s6_addr[10] == 0xff &&                \
     (X)->s6_addr[11] == 0xff)

#define IN6_IS_ADDR_MC_LINKLOCAL(a)                 \
    (((const uint8_t *) (a))[0] == 0xff &&          \
     (((const uint8_t *) (a))[1] & 0xf) == 0x2)

# define IN6_ARE_ADDR_EQUAL(a,b)                                          \
    ((((const uint32_t *) (a))[0] == ((const uint32_t *) (b))[0]) &&      \
     (((const uint32_t *) (a))[1] == ((const uint32_t *) (b))[1]) &&      \
     (((const uint32_t *) (a))[2] == ((const uint32_t *) (b))[2]) &&      \
     (((const uint32_t *) (a))[3] == ((const uint32_t *) (b))[3]))

#define INET_ADDRSTRLEN 16
#define INET6_ADDRSTRLEN 46

#define IPV6_TCLASS   67

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
const char *inet_ntop(int, const void *, char *, socklen_t);
int inet_pton(int, const char *, void *);

#endif /* <netinet/in.h> */
