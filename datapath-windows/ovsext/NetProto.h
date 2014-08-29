/*
 * Copyright (c) 2014 VMware, Inc.
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

#ifndef __NET_PROTO_H_
#define __NET_PROTO_H_ 1

#include "precomp.h"
#include "Ethernet.h"

#define ETH_ADDR_LENGTH    6
/*
 * There is a more inclusive definition of ethernet header (Eth_Header) in
 * OvsEth.h that is used for packet parsing. For simple cases, , use the following definition.
 */
typedef struct EthHdr {
    UINT8       Destination[ETH_ADDR_LENGTH];
    UINT8       Source[ETH_ADDR_LENGTH];
    UINT16      Type;
} EthHdr, *PEthHdr;

#define IPV4                    4
#define IPV6                    6

#define IP_HDR_MIN_LENGTH      20
#define TCP_HDR_MIN_LENGTH     20
#define TCP_CSUM_OFFSET        16
#define UDP_CSUM_OFFSET        6
#define ICMP_CSUM_OFFSET       2
#define INET_CSUM_LENGTH       (sizeof(UINT16))

#define IP4_UNITS_TO_BYTES(x) ((x) << 2)
#define IP4_BYTES_TO_UNITS(x) ((x) >> 2)

// length unit for ip->ihl, tcp->doff
typedef UINT32 IP4UnitLength;

#define IP4_LENGTH_UNIT               (sizeof(IP4UnitLength))
#define IP4_HDR_MIN_LENGTH_IN_UNITS   (IP_HDR_MIN_LENGTH / IP4_LENGTH_UNIT)
#define TCP_HDR_MIN_LENGTH_IN_UNITS   (TCP_HDR_MIN_LENGTH / IP4_LENGTH_UNIT)

#define IP4_IHL_NO_OPTIONS            IP4_HDR_MIN_LENGTH_IN_UNITS
#define IP4_HDR_LEN(iph)              IP4_UNITS_TO_BYTES((iph)->ihl)

// length unit for ip->frag_off
typedef UINT64 IP4FragUnitLength;

#define IP4_FRAG_UNIT_LENGTH          (sizeof(IP4FragUnitLength))

// length UINT for ipv6 header length.
typedef UINT64 IP6UnitLength;

#define TCP_HDR_LEN(tcph)             IP4_UNITS_TO_BYTES((tcph)->doff)
#define TCP_DATA_LENGTH(iph, tcph)    (ntohs(iph->tot_len) -                \
                                       IP4_HDR_LEN(iph) - TCP_HDR_LEN(tcph))

#define TCP_DATA_OFFSET_NO_OPTIONS    TCP_HDR_MIN_LENGTH_IN_UNITS
#define TCP_DATA_OFFSET_WITH_TIMESTAMP 8

/*
 * This is the maximum value for the length field in the IP header. The meaning
 * varies with IP protocols:
 *    IPv4: the total ip length (including ip header and extention)
 *    IPv6: the IP payload length (including IP extensions)
 */
#define IP_MAX_PACKET          0xFFFF

#define IPPROTO_ICMP    1
#define IPPROTO_IGMP    2
#define IPPROTO_UDP     17
#define IPPROTO_GRE     47
#define IPPROTO_TCP     6
#define IPPROTO_RSVD    0xff

#define IPPROTO_HOPOPTS         0               /* Hop-by-hop option header */
#define IPPROTO_IPV6            41              /* IPv6 in IPv6 */
#define IPPROTO_ROUTING         43              /* Routing header */
#define IPPROTO_FRAGMENT        44              /* Fragmentation/reassembly header */
#define IPPROTO_GRE             47              /* General Routing Encapsulation */
#define IPPROTO_ESP             50              /* Encap. Security Payload */
#define IPPROTO_AH              51              /* Authentication header */
#define IPPROTO_ICMPV6          58              /* ICMP for IPv6 */
#define IPPROTO_NONE            59              /* No next header */
#define IPPROTO_DSTOPTS         60              /* Destination options header */
#define IPPROTO_ETHERIP         97              /* etherIp tunneled protocol */

/* ICMPv6 types. */
#define ND_NEIGHBOR_SOLICIT 135     /* neighbor solicitation */
#define ND_NEIGHBOR_ADVERT  136     /* neighbor advertisment */

/* IPv6 Neighbor discovery option header. */
#define ND_OPT_SOURCE_LINKADDR  1
#define ND_OPT_TARGET_LINKADDR  2

/* Collides with MS definition (opposite order) */
#define IP6F_OFF_HOST_ORDER_MASK 0xfff8

#define ARPOP_REQUEST   1       /* ARP request.  */
#define ARPOP_REPLY     2       /* ARP reply.    */
#define RARPOP_REQUEST  3       /* RARP request. */
#define RARPOP_REPLY    4       /* RARP reply.   */

                                        /* all ARP NBO's assume short ar_op */
#define ARPOP_REQUEST_NBO  0x0100       /* NBO ARP request.   */
#define ARPOP_REPLY_NBO    0x0200       /* NBO ARP reply.     */
#define RARPOP_REQUEST_NBO 0x0300       /* NBO RARP request.  */
#define RARPOP_REPLY_NBO   0x0300       /* NBO RARP reply.    */

#define ICMP_ECHO          8    /* Echo Request */
#define ICMP_ECHOREPLY     0    /* Echo Reply */
#define ICMP_DEST_UNREACH  3    /* Destination Unreachable */

/* IGMP related constants */
#define IGMP_UNKNOWN    0x00    /* For IGMP packets where we don't know the type */
                                /* Eg: Fragmented packets without the header */

/* Constants from RFC 3376 */
#define IGMP_QUERY      0x11    /* IGMP Host Membership Query.    */
#define IGMP_V1REPORT   0x12    /* IGMPv1 Host Membership Report. */
#define IGMP_V2REPORT   0x16    /* IGMPv2 Host Membership Report. */
#define IGMP_V3REPORT   0x22    /* IGMPv3 Host Membership Report. */
#define IGMP_V2LEAVE    0x17    /* IGMPv2 Leave.                  */

/* Constants from RFC 2710  and RFC 3810 */
#define MLD_QUERY       0x82    /* Multicast Listener Query.      */
#define MLD_V1REPORT    0x83    /* Multicast Listener V1 Report.  */
#define MLD_V2REPORT    0x8F    /* Multicast Listener V2 Report.  */
#define MLD_DONE        0x84    /* Multicast Listener Done.       */

/* IPv4 offset flags */
#define IP_CE           0x8000          /* Flag: "Congestion"           */
#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

#define IP_OFFSET_NBO   0xFF1F          /* "Fragment Offset" part, NBO   */
#define IP_DF_NBO       0x0040          /* NBO version of don't fragment */
#define IP_MF_NBO       0x0020          /* NBO version of more fragments */

#define IPOPT_RTRALT    0x94

/* IP Explicit Congestion Notification bits (TOS field) */
#define IP_ECN_NOT_ECT 0
#define IP_ECN_ECT_1   1
#define IP_ECN_ECT_0   2
#define IP_ECN_CE      3
#define IP_ECN_MASK    3

/* TCP options */
#define TCP_OPT_NOP              1       /* Padding */
#define TCP_OPT_EOL              0       /* End of options */
#define TCP_OPT_MSS              2       /* Segment size negotiating */
#define TCP_OPT_WINDOW           3       /* Window scaling */
#define TCP_OPT_SACK_PERM        4       /* SACK Permitted */
#define TCP_OPT_SACK             5       /* SACK Block */
#define TCP_OPT_TIMESTAMP        8       /* Better RTT estimations/PAWS */
#define TCP_OPT_MD5SIG           19      /* MD5 Signature (RFC2385) */

#define TCP_OPT_LEN_MSS          4
#define TCP_OPT_LEN_WINDOW       3
#define TCP_OPT_LEN_SACK_PERM    2
#define TCP_OPT_LEN_TIMESTAMP    10
#define TCP_OPT_LEN_MD5SIG       18

#define SOCKET_IPPROTO_HOPOPTS IPPROTO_HOPOPTS
#define SOCKET_IPPROTO_ROUTING IPPROTO_ROUTING
#define SOCKET_IPPROTO_FRAGMENT IPPROTO_FRAGMENT
#define SOCKET_IPPROTO_AH IPPROTO_AH
#define SOCKET_IPPROTO_ICMPV6 IPPROTO_ICMPV6
#define SOCKET_IPPROTO_NONE IPPROTO_NONE
#define SOCKET_IPPROTO_DSTOPTS IPPROTO_DSTOPTS
#define SOCKET_IPPROTO_EON  80
#define SOCKET_IPPROTO_ETHERIP IPPROTO_ETHERIP
#define SOCKET_IPPROTO_ENCAP 98
#define SOCKET_IPPROTO_PIM 103
#define SOCKET_IPPROTO_IPCOMP 108
#define SOCKET_IPPROTO_CARP 112
#define SOCKET_IPPROTO_PFSYNC 240
#define SOCKET_IPPROTO_RAW IPPROTO_RSVD

typedef union _OVS_PACKET_HDR_INFO {
    struct {
        UINT16 l3Offset;
        UINT16 l4Offset;
        union {
            UINT16 l7Offset;
            UINT16 l4PayLoad;
        };
        UINT16 isIPv4:1;
        UINT16 isIPv6:1;
        UINT16 isTcp:1;
        UINT16 isUdp:1;
        UINT16 tcpCsumNeeded:1;
        UINT16 udpCsumNeeded:1;
        UINT16 udpCsumZero:1;
        UINT16 pad:9;
    } ;
    UINT64 value;
} OVS_PACKET_HDR_INFO, *POVS_PACKET_HDR_INFO;

typedef struct IPHdr {
   UINT8    ihl:4,
            version:4;
   UINT8    tos;
   UINT16   tot_len;
   UINT16   id;
   UINT16   frag_off;
   UINT8    ttl;
   UINT8    protocol;
   UINT16   check;
   UINT32   saddr;
   UINT32   daddr;
} IPHdr;


 /*
 * IPv6 fixed header
 *
 * BEWARE, it is incorrect. The first 4 bits of flow_lbl
 * are glued to priority now, forming "class".
 */

typedef struct IPv6Hdr {
    UINT8    priority:4,
             version:4;
    UINT8    flow_lbl[3];

    UINT16   payload_len;
    UINT8    nexthdr;
    UINT8    hop_limit;

    struct in6_addr saddr;
    struct in6_addr daddr;
} IPv6Hdr;

// Generic IPv6 extension header
typedef struct IPv6ExtHdr {
    UINT8        nextHeader; // type of the next header
    UINT8        hdrExtLen;  // length of header extensions (beyond 8 bytes)
    UINT16       optPad1;
    UINT32       optPad2;
} IPv6ExtHdr;

typedef struct IPv6FragHdr {
    UINT8 nextHeader;
    UINT8 reserved;
    UINT16 offlg;
    UINT32 ident;
} IPv6FragHdr;

typedef struct IPv6NdOptHdr {
    UINT8 type;
    UINT8 len;
} IPv6NdOptHdr;

typedef struct ICMPHdr {
   UINT8    type;
   UINT8    code;
   UINT16   checksum;
} ICMPHdr;

typedef struct ICMPEcho {
   UINT16       id;
   UINT16       seq;
} ICMPEcho;

typedef struct UDPHdr {
   UINT16    source;
   UINT16    dest;
   UINT16    len;
   UINT16    check;
} UDPHdr;

typedef struct TCPHdr {
   UINT16    source;
   UINT16    dest;
   UINT32    seq;
   UINT32    ack_seq;
   UINT16    res1:4,
             doff:4,
             fin:1,
             syn:1,
             rst:1,
             psh:1,
             ack:1,
             urg:1,
             ece:1,
             cwr:1;
   UINT16    window;
   UINT16    check;
   UINT16    urg_ptr;
} TCPHdr;

typedef struct PseudoHdr {
   UINT32   sourceIPAddr;
   UINT32   destIPAddr;
   UINT8    zero;
   UINT8    protocol;
   UINT16   length;
} PseudoHdr;

typedef struct PseudoHdrIPv6 {
   UINT8    sourceIPAddr[16];
   UINT8    destIPAddr[16];
   UINT8    zero;
   UINT8    protocol;
   UINT16   length;
} PseudoHdrIPv6;


struct ArpHdr {
   UINT16   ar_hrd;                /* Format of hardware address.  */
   UINT16   ar_pro;                /* Format of protocol address.  */
   UINT8    ar_hln;                /* Length of hardware address.  */
   UINT8    ar_pln;                /* Length of protocol address.  */
   UINT16   ar_op;                 /* ARP opcode (command).  */
};

typedef struct EtherArp {
   struct ArpHdr ea_hdr;          /* fixed-size header */
   Eth_Address   arp_sha;         /* sender hardware address */
   UINT8         arp_spa[4];      /* sender protocol address */
   Eth_Address   arp_tha;         /* target hardware address */
   UINT8         arp_tpa[4];      /* target protocol address */
} EtherArp;

typedef struct IGMPHdr {
   UINT8    type;
   UINT8    maxResponseTime;
   UINT16   csum;
   UINT8    groupAddr[4];
} IGMPHdr;

typedef struct IGMPV3Trailer {
   UINT8  qrv:3,
            s:1,
         resv:4;
   UINT8 qqic;
   UINT16 numSources;
} IGMPV3Trailer;

typedef struct IPOpt {
   UINT8 type;
   UINT8 length;
   UINT16 value;
} IPOpt;

/*
 * IP protocol types
 */
#define SOCKET_IPPROTO_IP    0
#define SOCKET_IPPROTO_ICMP  1
#define SOCKET_IPPROTO_TCP   6
#define SOCKET_IPPROTO_UDP   17
#define SOCKET_IPPROTO_GRE   47

#endif /* __NET_PROTO_H_ */
