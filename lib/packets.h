/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef PACKETS_H
#define PACKETS_H 1

#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include "compiler.h"
#include "openvswitch/types.h"
#include "random.h"
#include "hash.h"
#include "util.h"

struct ofpbuf;
struct ds;

/* Tunnel information used in flow key and metadata. */
struct flow_tnl {
    ovs_be64 tun_id;
    ovs_be32 ip_src;
    ovs_be32 ip_dst;
    uint16_t flags;
    uint8_t ip_tos;
    uint8_t ip_ttl;
};

/* Unfortunately, a "struct flow" sometimes has to handle OpenFlow port
 * numbers and other times datapath (dpif) port numbers.  This union allows
 * access to both. */
union flow_in_port {
    odp_port_t odp_port;
    ofp_port_t ofp_port;
};

/* Datapath packet metadata */
struct pkt_metadata {
    uint32_t recirc_id;         /* Recirculation id carried with the
                                   recirculating packets. 0 for packets
                                   received from the wire. */
    uint32_t dp_hash;           /* hash value computed by the recirculation
                                   action. */
    struct flow_tnl tunnel;     /* Encapsulating tunnel parameters. */
    uint32_t skb_priority;      /* Packet priority for QoS. */
    uint32_t pkt_mark;          /* Packet mark. */
    union flow_in_port in_port; /* Input port. */
};

#define PKT_METADATA_INITIALIZER(PORT) \
    (struct pkt_metadata){ 0, 0, { 0, 0, 0, 0, 0, 0}, 0, 0, {(PORT)} }

bool dpid_from_string(const char *s, uint64_t *dpidp);

#define ETH_ADDR_LEN           6

static const uint8_t eth_addr_broadcast[ETH_ADDR_LEN] OVS_UNUSED
    = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static const uint8_t eth_addr_stp[ETH_ADDR_LEN] OVS_UNUSED
    = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x00 };

static const uint8_t eth_addr_lacp[ETH_ADDR_LEN] OVS_UNUSED
    = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 };

static const uint8_t eth_addr_bfd[ETH_ADDR_LEN] OVS_UNUSED
    = { 0x00, 0x23, 0x20, 0x00, 0x00, 0x01 };

static inline bool eth_addr_is_broadcast(const uint8_t ea[6])
{
    return (ea[0] & ea[1] & ea[2] & ea[3] & ea[4] & ea[5]) == 0xff;
}

static inline bool eth_addr_is_multicast(const uint8_t ea[6])
{
    return ea[0] & 1;
}
static inline bool eth_addr_is_local(const uint8_t ea[6])
{
    /* Local if it is either a locally administered address or a Nicira random
     * address. */
    return ea[0] & 2
       || (ea[0] == 0x00 && ea[1] == 0x23 && ea[2] == 0x20 && ea[3] & 0x80);
}
static inline bool eth_addr_is_zero(const uint8_t ea[6])
{
    return !(ea[0] | ea[1] | ea[2] | ea[3] | ea[4] | ea[5]);
}

static inline int eth_mask_is_exact(const uint8_t ea[ETH_ADDR_LEN])
{
    return (ea[0] & ea[1] & ea[2] & ea[3] & ea[4] & ea[5]) == 0xff;
}

static inline int eth_addr_compare_3way(const uint8_t a[ETH_ADDR_LEN],
                                        const uint8_t b[ETH_ADDR_LEN])
{
    return memcmp(a, b, ETH_ADDR_LEN);
}
static inline bool eth_addr_equals(const uint8_t a[ETH_ADDR_LEN],
                                   const uint8_t b[ETH_ADDR_LEN])
{
    return !eth_addr_compare_3way(a, b);
}
static inline bool eth_addr_equal_except(const uint8_t a[ETH_ADDR_LEN],
                                    const uint8_t b[ETH_ADDR_LEN],
                                    const uint8_t mask[ETH_ADDR_LEN])
{
    return !(((a[0] ^ b[0]) & mask[0])
             || ((a[1] ^ b[1]) & mask[1])
             || ((a[2] ^ b[2]) & mask[2])
             || ((a[3] ^ b[3]) & mask[3])
             || ((a[4] ^ b[4]) & mask[4])
             || ((a[5] ^ b[5]) & mask[5]));
}
static inline uint64_t eth_addr_to_uint64(const uint8_t ea[ETH_ADDR_LEN])
{
    return (((uint64_t) ea[0] << 40)
            | ((uint64_t) ea[1] << 32)
            | ((uint64_t) ea[2] << 24)
            | ((uint64_t) ea[3] << 16)
            | ((uint64_t) ea[4] << 8)
            | ea[5]);
}
static inline uint64_t eth_addr_vlan_to_uint64(const uint8_t ea[ETH_ADDR_LEN],
                                               uint16_t vlan)
{
    return (((uint64_t)vlan << 48) | eth_addr_to_uint64(ea));
}
static inline void eth_addr_from_uint64(uint64_t x, uint8_t ea[ETH_ADDR_LEN])
{
    ea[0] = x >> 40;
    ea[1] = x >> 32;
    ea[2] = x >> 24;
    ea[3] = x >> 16;
    ea[4] = x >> 8;
    ea[5] = x;
}
static inline void eth_addr_mark_random(uint8_t ea[ETH_ADDR_LEN])
{
    ea[0] &= ~1;                /* Unicast. */
    ea[0] |= 2;                 /* Private. */
}
static inline void eth_addr_random(uint8_t ea[ETH_ADDR_LEN])
{
    random_bytes(ea, ETH_ADDR_LEN);
    eth_addr_mark_random(ea);
}
static inline void eth_addr_nicira_random(uint8_t ea[ETH_ADDR_LEN])
{
    eth_addr_random(ea);

    /* Set the OUI to the Nicira one. */
    ea[0] = 0x00;
    ea[1] = 0x23;
    ea[2] = 0x20;

    /* Set the top bit to indicate random Nicira address. */
    ea[3] |= 0x80;
}
static inline uint32_t hash_mac(const uint8_t ea[ETH_ADDR_LEN],
                                const uint16_t vlan, const uint32_t basis)
{
    return hash_uint64_basis(eth_addr_vlan_to_uint64(ea, vlan), basis);
}

bool eth_addr_is_reserved(const uint8_t ea[ETH_ADDR_LEN]);
bool eth_addr_from_string(const char *, uint8_t ea[ETH_ADDR_LEN]);

void compose_rarp(struct ofpbuf *, const uint8_t eth_src[ETH_ADDR_LEN]);

void eth_push_vlan(struct ofpbuf *, ovs_be16 tpid, ovs_be16 tci);
void eth_pop_vlan(struct ofpbuf *);

const char *eth_from_hex(const char *hex, struct ofpbuf **packetp);
void eth_format_masked(const uint8_t eth[ETH_ADDR_LEN],
                       const uint8_t mask[ETH_ADDR_LEN], struct ds *s);
void eth_addr_bitand(const uint8_t src[ETH_ADDR_LEN],
                     const uint8_t mask[ETH_ADDR_LEN],
                     uint8_t dst[ETH_ADDR_LEN]);

void set_mpls_lse(struct ofpbuf *, ovs_be32 label);
void push_mpls(struct ofpbuf *packet, ovs_be16 ethtype, ovs_be32 lse);
void pop_mpls(struct ofpbuf *, ovs_be16 ethtype);

void set_mpls_lse_ttl(ovs_be32 *lse, uint8_t ttl);
void set_mpls_lse_tc(ovs_be32 *lse, uint8_t tc);
void set_mpls_lse_label(ovs_be32 *lse, ovs_be32 label);
void set_mpls_lse_bos(ovs_be32 *lse, uint8_t bos);
ovs_be32 set_mpls_lse_values(uint8_t ttl, uint8_t tc, uint8_t bos,
                             ovs_be32 label);

/* Example:
 *
 * uint8_t mac[ETH_ADDR_LEN];
 *    [...]
 * printf("The Ethernet address is "ETH_ADDR_FMT"\n", ETH_ADDR_ARGS(mac));
 *
 */
#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

/* Example:
 *
 * char *string = "1 00:11:22:33:44:55 2";
 * uint8_t mac[ETH_ADDR_LEN];
 * int a, b;
 *
 * if (ovs_scan(string, "%d"ETH_ADDR_SCAN_FMT"%d",
 *              &a, ETH_ADDR_SCAN_ARGS(mac), &b)) {
 *     ...
 * }
 */
#define ETH_ADDR_SCAN_FMT "%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8":%"SCNx8
#define ETH_ADDR_SCAN_ARGS(ea) \
        &(ea)[0], &(ea)[1], &(ea)[2], &(ea)[3], &(ea)[4], &(ea)[5]

#define ETH_TYPE_IP            0x0800
#define ETH_TYPE_ARP           0x0806
#define ETH_TYPE_VLAN_8021Q    0x8100
#define ETH_TYPE_VLAN          ETH_TYPE_VLAN_8021Q
#define ETH_TYPE_VLAN_8021AD   0x88a8
#define ETH_TYPE_IPV6          0x86dd
#define ETH_TYPE_LACP          0x8809
#define ETH_TYPE_RARP          0x8035
#define ETH_TYPE_MPLS          0x8847
#define ETH_TYPE_MPLS_MCAST    0x8848

static inline bool eth_type_mpls(ovs_be16 eth_type)
{
    return eth_type == htons(ETH_TYPE_MPLS) ||
        eth_type == htons(ETH_TYPE_MPLS_MCAST);
}

/* Minimum value for an Ethernet type.  Values below this are IEEE 802.2 frame
 * lengths. */
#define ETH_TYPE_MIN           0x600

#define ETH_HEADER_LEN 14
#define ETH_PAYLOAD_MIN 46
#define ETH_PAYLOAD_MAX 1500
#define ETH_TOTAL_MIN (ETH_HEADER_LEN + ETH_PAYLOAD_MIN)
#define ETH_TOTAL_MAX (ETH_HEADER_LEN + ETH_PAYLOAD_MAX)
#define ETH_VLAN_TOTAL_MAX (ETH_HEADER_LEN + VLAN_HEADER_LEN + ETH_PAYLOAD_MAX)
OVS_PACKED(
struct eth_header {
    uint8_t eth_dst[ETH_ADDR_LEN];
    uint8_t eth_src[ETH_ADDR_LEN];
    ovs_be16 eth_type;
});
BUILD_ASSERT_DECL(ETH_HEADER_LEN == sizeof(struct eth_header));

#define LLC_DSAP_SNAP 0xaa
#define LLC_SSAP_SNAP 0xaa
#define LLC_CNTL_SNAP 3

#define LLC_HEADER_LEN 3
OVS_PACKED(
struct llc_header {
    uint8_t llc_dsap;
    uint8_t llc_ssap;
    uint8_t llc_cntl;
});
BUILD_ASSERT_DECL(LLC_HEADER_LEN == sizeof(struct llc_header));

#define SNAP_ORG_ETHERNET "\0\0" /* The compiler adds a null byte, so
                                    sizeof(SNAP_ORG_ETHERNET) == 3. */
#define SNAP_HEADER_LEN 5
OVS_PACKED(
struct snap_header {
    uint8_t snap_org[3];
    ovs_be16 snap_type;
});
BUILD_ASSERT_DECL(SNAP_HEADER_LEN == sizeof(struct snap_header));

#define LLC_SNAP_HEADER_LEN (LLC_HEADER_LEN + SNAP_HEADER_LEN)
OVS_PACKED(
struct llc_snap_header {
    struct llc_header llc;
    struct snap_header snap;
});
BUILD_ASSERT_DECL(LLC_SNAP_HEADER_LEN == sizeof(struct llc_snap_header));

#define VLAN_VID_MASK 0x0fff
#define VLAN_VID_SHIFT 0

#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13

#define VLAN_CFI 0x1000
#define VLAN_CFI_SHIFT 12

/* Given the vlan_tci field from an 802.1Q header, in network byte order,
 * returns the VLAN ID in host byte order. */
static inline uint16_t
vlan_tci_to_vid(ovs_be16 vlan_tci)
{
    return (ntohs(vlan_tci) & VLAN_VID_MASK) >> VLAN_VID_SHIFT;
}

/* Given the vlan_tci field from an 802.1Q header, in network byte order,
 * returns the priority code point (PCP) in host byte order. */
static inline int
vlan_tci_to_pcp(ovs_be16 vlan_tci)
{
    return (ntohs(vlan_tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;
}

/* Given the vlan_tci field from an 802.1Q header, in network byte order,
 * returns the Canonical Format Indicator (CFI). */
static inline int
vlan_tci_to_cfi(ovs_be16 vlan_tci)
{
    return (vlan_tci & htons(VLAN_CFI)) != 0;
}

#define VLAN_HEADER_LEN 4
struct vlan_header {
    ovs_be16 vlan_tci;          /* Lowest 12 bits are VLAN ID. */
    ovs_be16 vlan_next_type;
};
BUILD_ASSERT_DECL(VLAN_HEADER_LEN == sizeof(struct vlan_header));

#define VLAN_ETH_HEADER_LEN (ETH_HEADER_LEN + VLAN_HEADER_LEN)
OVS_PACKED(
struct vlan_eth_header {
    uint8_t veth_dst[ETH_ADDR_LEN];
    uint8_t veth_src[ETH_ADDR_LEN];
    ovs_be16 veth_type;         /* Always htons(ETH_TYPE_VLAN). */
    ovs_be16 veth_tci;          /* Lowest 12 bits are VLAN ID. */
    ovs_be16 veth_next_type;
});
BUILD_ASSERT_DECL(VLAN_ETH_HEADER_LEN == sizeof(struct vlan_eth_header));

/* MPLS related definitions */
#define MPLS_TTL_MASK       0x000000ff
#define MPLS_TTL_SHIFT      0

#define MPLS_BOS_MASK       0x00000100
#define MPLS_BOS_SHIFT      8

#define MPLS_TC_MASK        0x00000e00
#define MPLS_TC_SHIFT       9

#define MPLS_LABEL_MASK     0xfffff000
#define MPLS_LABEL_SHIFT    12

#define MPLS_HLEN           4

struct mpls_hdr {
    ovs_16aligned_be32 mpls_lse;
};
BUILD_ASSERT_DECL(MPLS_HLEN == sizeof(struct mpls_hdr));

/* Given a mpls label stack entry in network byte order
 * return mpls label in host byte order */
static inline uint32_t
mpls_lse_to_label(ovs_be32 mpls_lse)
{
    return (ntohl(mpls_lse) & MPLS_LABEL_MASK) >> MPLS_LABEL_SHIFT;
}

/* Given a mpls label stack entry in network byte order
 * return mpls tc */
static inline uint8_t
mpls_lse_to_tc(ovs_be32 mpls_lse)
{
    return (ntohl(mpls_lse) & MPLS_TC_MASK) >> MPLS_TC_SHIFT;
}

/* Given a mpls label stack entry in network byte order
 * return mpls ttl */
static inline uint8_t
mpls_lse_to_ttl(ovs_be32 mpls_lse)
{
    return (ntohl(mpls_lse) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
}

/* Set TTL in mpls lse. */
static inline void
flow_set_mpls_lse_ttl(ovs_be32 *mpls_lse, uint8_t ttl)
{
    *mpls_lse &= ~htonl(MPLS_TTL_MASK);
    *mpls_lse |= htonl(ttl << MPLS_TTL_SHIFT);
}

/* Given a mpls label stack entry in network byte order
 * return mpls BoS bit  */
static inline uint8_t
mpls_lse_to_bos(ovs_be32 mpls_lse)
{
    return (mpls_lse & htonl(MPLS_BOS_MASK)) != 0;
}

#define IP_FMT "%"PRIu32".%"PRIu32".%"PRIu32".%"PRIu32
#define IP_ARGS(ip)                             \
    ntohl(ip) >> 24,                            \
    (ntohl(ip) >> 16) & 0xff,                   \
    (ntohl(ip) >> 8) & 0xff,                    \
    ntohl(ip) & 0xff

/* Example:
 *
 * char *string = "1 33.44.55.66 2";
 * ovs_be32 ip;
 * int a, b;
 *
 * if (ovs_scan(string, "%d"IP_SCAN_FMT"%d", &a, IP_SCAN_ARGS(&ip), &b)) {
 *     ...
 * }
 */
#define IP_SCAN_FMT "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8
#define IP_SCAN_ARGS(ip)                                    \
        ((void) (ovs_be32) *(ip), &((uint8_t *) ip)[0]),    \
        &((uint8_t *) ip)[1],                               \
        &((uint8_t *) ip)[2],                               \
        &((uint8_t *) ip)[3]

/* Returns true if 'netmask' is a CIDR netmask, that is, if it consists of N
 * high-order 1-bits and 32-N low-order 0-bits. */
static inline bool
ip_is_cidr(ovs_be32 netmask)
{
    uint32_t x = ~ntohl(netmask);
    return !(x & (x + 1));
}
static inline bool
ip_is_multicast(ovs_be32 ip)
{
    return (ip & htonl(0xf0000000)) == htonl(0xe0000000);
}
int ip_count_cidr_bits(ovs_be32 netmask);
void ip_format_masked(ovs_be32 ip, ovs_be32 mask, struct ds *);

#define IP_VER(ip_ihl_ver) ((ip_ihl_ver) >> 4)
#define IP_IHL(ip_ihl_ver) ((ip_ihl_ver) & 15)
#define IP_IHL_VER(ihl, ver) (((ver) << 4) | (ihl))

#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP 132
#endif

/* TOS fields. */
#define IP_ECN_NOT_ECT 0x0
#define IP_ECN_ECT_1 0x01
#define IP_ECN_ECT_0 0x02
#define IP_ECN_CE 0x03
#define IP_ECN_MASK 0x03
#define IP_DSCP_MASK 0xfc

#define IP_VERSION 4

#define IP_DONT_FRAGMENT  0x4000 /* Don't fragment. */
#define IP_MORE_FRAGMENTS 0x2000 /* More fragments. */
#define IP_FRAG_OFF_MASK  0x1fff /* Fragment offset. */
#define IP_IS_FRAGMENT(ip_frag_off) \
        ((ip_frag_off) & htons(IP_MORE_FRAGMENTS | IP_FRAG_OFF_MASK))

#define IP_HEADER_LEN 20
struct ip_header {
    uint8_t ip_ihl_ver;
    uint8_t ip_tos;
    ovs_be16 ip_tot_len;
    ovs_be16 ip_id;
    ovs_be16 ip_frag_off;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    ovs_be16 ip_csum;
    ovs_16aligned_be32 ip_src;
    ovs_16aligned_be32 ip_dst;
};
BUILD_ASSERT_DECL(IP_HEADER_LEN == sizeof(struct ip_header));

#define ICMP_HEADER_LEN 8
struct icmp_header {
    uint8_t icmp_type;
    uint8_t icmp_code;
    ovs_be16 icmp_csum;
    union {
        struct {
            ovs_be16 id;
            ovs_be16 seq;
        } echo;
        struct {
            ovs_be16 empty;
            ovs_be16 mtu;
        } frag;
        ovs_16aligned_be32 gateway;
    } icmp_fields;
    uint8_t icmp_data[0];
};
BUILD_ASSERT_DECL(ICMP_HEADER_LEN == sizeof(struct icmp_header));

#define SCTP_HEADER_LEN 12
struct sctp_header {
    ovs_be16 sctp_src;
    ovs_be16 sctp_dst;
    ovs_16aligned_be32 sctp_vtag;
    ovs_16aligned_be32 sctp_csum;
};
BUILD_ASSERT_DECL(SCTP_HEADER_LEN == sizeof(struct sctp_header));

#define UDP_HEADER_LEN 8
struct udp_header {
    ovs_be16 udp_src;
    ovs_be16 udp_dst;
    ovs_be16 udp_len;
    ovs_be16 udp_csum;
};
BUILD_ASSERT_DECL(UDP_HEADER_LEN == sizeof(struct udp_header));

#define TCP_FIN 0x001
#define TCP_SYN 0x002
#define TCP_RST 0x004
#define TCP_PSH 0x008
#define TCP_ACK 0x010
#define TCP_URG 0x020
#define TCP_ECE 0x040
#define TCP_CWR 0x080
#define TCP_NS  0x100

#define TCP_CTL(flags, offset) (htons((flags) | ((offset) << 12)))
#define TCP_FLAGS(tcp_ctl) (ntohs(tcp_ctl) & 0x0fff)
#define TCP_FLAGS_BE16(tcp_ctl) ((tcp_ctl) & htons(0x0fff))
#define TCP_OFFSET(tcp_ctl) (ntohs(tcp_ctl) >> 12)

#define TCP_HEADER_LEN 20
struct tcp_header {
    ovs_be16 tcp_src;
    ovs_be16 tcp_dst;
    ovs_16aligned_be32 tcp_seq;
    ovs_16aligned_be32 tcp_ack;
    ovs_be16 tcp_ctl;
    ovs_be16 tcp_winsz;
    ovs_be16 tcp_csum;
    ovs_be16 tcp_urg;
};
BUILD_ASSERT_DECL(TCP_HEADER_LEN == sizeof(struct tcp_header));

#define ARP_HRD_ETHERNET 1
#define ARP_PRO_IP 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2
#define ARP_OP_RARP 3

#define ARP_ETH_HEADER_LEN 28
struct arp_eth_header {
    /* Generic members. */
    ovs_be16 ar_hrd;           /* Hardware type. */
    ovs_be16 ar_pro;           /* Protocol type. */
    uint8_t ar_hln;            /* Hardware address length. */
    uint8_t ar_pln;            /* Protocol address length. */
    ovs_be16 ar_op;            /* Opcode. */

    /* Ethernet+IPv4 specific members. */
    uint8_t ar_sha[ETH_ADDR_LEN]; /* Sender hardware address. */
    ovs_16aligned_be32 ar_spa;           /* Sender protocol address. */
    uint8_t ar_tha[ETH_ADDR_LEN]; /* Target hardware address. */
    ovs_16aligned_be32 ar_tpa;           /* Target protocol address. */
};
BUILD_ASSERT_DECL(ARP_ETH_HEADER_LEN == sizeof(struct arp_eth_header));

/* Like struct in6_addr, but whereas that struct requires 32-bit alignment on
 * most implementations, this one only requires 16-bit alignment. */
union ovs_16aligned_in6_addr {
    ovs_be16 be16[8];
    ovs_16aligned_be32 be32[4];
};

/* Like struct in6_hdr, but whereas that struct requires 32-bit alignment, this
 * one only requires 16-bit alignment. */
struct ovs_16aligned_ip6_hdr {
    union {
        struct ovs_16aligned_ip6_hdrctl {
            ovs_16aligned_be32 ip6_un1_flow;
            ovs_be16 ip6_un1_plen;
            uint8_t ip6_un1_nxt;
            uint8_t ip6_un1_hlim;
        } ip6_un1;
        uint8_t ip6_un2_vfc;
    } ip6_ctlun;
    union ovs_16aligned_in6_addr ip6_src;
    union ovs_16aligned_in6_addr ip6_dst;
};

/* Like struct in6_frag, but whereas that struct requires 32-bit alignment,
 * this one only requires 16-bit alignment. */
struct ovs_16aligned_ip6_frag {
    uint8_t ip6f_nxt;
    uint8_t ip6f_reserved;
    ovs_be16 ip6f_offlg;
    ovs_16aligned_be32 ip6f_ident;
};

/* The IPv6 flow label is in the lower 20 bits of the first 32-bit word. */
#define IPV6_LABEL_MASK 0x000fffff

/* Example:
 *
 * char *string = "1 ::1 2";
 * char ipv6_s[IPV6_SCAN_LEN + 1];
 * struct in6_addr ipv6;
 *
 * if (ovs_scan(string, "%d"IPV6_SCAN_FMT"%d", &a, ipv6_s, &b)
 *     && inet_pton(AF_INET6, ipv6_s, &ipv6) == 1) {
 *     ...
 * }
 */
#define IPV6_SCAN_FMT "%46[0123456789abcdefABCDEF:.]"
#define IPV6_SCAN_LEN 46

extern const struct in6_addr in6addr_exact;
#define IN6ADDR_EXACT_INIT { { { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff, \
                                 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff } } }

static inline bool ipv6_addr_equals(const struct in6_addr *a,
                                    const struct in6_addr *b)
{
#ifdef IN6_ARE_ADDR_EQUAL
    return IN6_ARE_ADDR_EQUAL(a, b);
#else
    return !memcmp(a, b, sizeof(*a));
#endif
}

static inline bool ipv6_mask_is_any(const struct in6_addr *mask) {
    return ipv6_addr_equals(mask, &in6addr_any);
}

static inline bool ipv6_mask_is_exact(const struct in6_addr *mask) {
    return ipv6_addr_equals(mask, &in6addr_exact);
}

static inline bool dl_type_is_ip_any(ovs_be16 dl_type)
{
    return dl_type == htons(ETH_TYPE_IP)
        || dl_type == htons(ETH_TYPE_IPV6);
}

void format_ipv6_addr(char *addr_str, const struct in6_addr *addr);
void print_ipv6_addr(struct ds *string, const struct in6_addr *addr);
void print_ipv6_masked(struct ds *string, const struct in6_addr *addr,
                       const struct in6_addr *mask);
struct in6_addr ipv6_addr_bitand(const struct in6_addr *src,
                                 const struct in6_addr *mask);
struct in6_addr ipv6_create_mask(int mask);
int ipv6_count_cidr_bits(const struct in6_addr *netmask);
bool ipv6_is_cidr(const struct in6_addr *netmask);

void *eth_compose(struct ofpbuf *, const uint8_t eth_dst[ETH_ADDR_LEN],
                  const uint8_t eth_src[ETH_ADDR_LEN], uint16_t eth_type,
                  size_t size);
void *snap_compose(struct ofpbuf *, const uint8_t eth_dst[ETH_ADDR_LEN],
                   const uint8_t eth_src[ETH_ADDR_LEN],
                   unsigned int oui, uint16_t snap_type, size_t size);
void packet_set_ipv4(struct ofpbuf *, ovs_be32 src, ovs_be32 dst, uint8_t tos,
                     uint8_t ttl);
void packet_set_ipv6(struct ofpbuf *, uint8_t proto, const ovs_be32 src[4],
                     const ovs_be32 dst[4], uint8_t tc,
                     ovs_be32 fl, uint8_t hlmit);
void packet_set_tcp_port(struct ofpbuf *, ovs_be16 src, ovs_be16 dst);
void packet_set_udp_port(struct ofpbuf *, ovs_be16 src, ovs_be16 dst);
void packet_set_sctp_port(struct ofpbuf *, ovs_be16 src, ovs_be16 dst);

void packet_format_tcp_flags(struct ds *, uint16_t);
const char *packet_tcp_flag_to_string(uint32_t flag);

#endif /* packets.h */
