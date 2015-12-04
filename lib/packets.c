/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include <config.h>
#include "packets.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include "byte-order.h"
#include "csum.h"
#include "crc32c.h"
#include "flow.h"
#include "hmap.h"
#include "dynamic-string.h"
#include "ovs-thread.h"
#include "odp-util.h"
#include "dp-packet.h"
#include "unaligned.h"

const struct in6_addr in6addr_exact = IN6ADDR_EXACT_INIT;
const struct in6_addr in6addr_all_hosts = IN6ADDR_ALL_HOSTS_INIT;

struct in6_addr
flow_tnl_dst(const struct flow_tnl *tnl)
{
    return tnl->ip_dst ? in6_addr_mapped_ipv4(tnl->ip_dst) : tnl->ipv6_dst;
}

struct in6_addr
flow_tnl_src(const struct flow_tnl *tnl)
{
    return tnl->ip_src ? in6_addr_mapped_ipv4(tnl->ip_src) : tnl->ipv6_src;
}

/* Parses 's' as a 16-digit hexadecimal number representing a datapath ID.  On
 * success stores the dpid into '*dpidp' and returns true, on failure stores 0
 * into '*dpidp' and returns false.
 *
 * Rejects an all-zeros dpid as invalid. */
bool
dpid_from_string(const char *s, uint64_t *dpidp)
{
    *dpidp = (strlen(s) == 16 && strspn(s, "0123456789abcdefABCDEF") == 16
              ? strtoull(s, NULL, 16)
              : 0);
    return *dpidp != 0;
}

/* Returns true if 'ea' is a reserved address, that a bridge must never
 * forward, false otherwise.
 *
 * If you change this function's behavior, please update corresponding
 * documentation in vswitch.xml at the same time. */
bool
eth_addr_is_reserved(const struct eth_addr ea)
{
    struct eth_addr_node {
        struct hmap_node hmap_node;
        const uint64_t ea64;
    };

    static struct eth_addr_node nodes[] = {
        /* STP, IEEE pause frames, and other reserved protocols. */
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000000ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000001ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000002ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000003ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000004ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000005ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000006ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000007ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000008ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c2000009ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000aULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000bULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000cULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000dULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000eULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x0180c200000fULL },

        /* Extreme protocols. */
        { HMAP_NODE_NULL_INITIALIZER, 0x00e02b000000ULL }, /* EDP. */
        { HMAP_NODE_NULL_INITIALIZER, 0x00e02b000004ULL }, /* EAPS. */
        { HMAP_NODE_NULL_INITIALIZER, 0x00e02b000006ULL }, /* EAPS. */

        /* Cisco protocols. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000c000000ULL }, /* ISL. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccccULL }, /* PAgP, UDLD, CDP,
                                                            * DTP, VTP. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000ccccccdULL }, /* PVST+. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000ccdcdcdULL }, /* STP Uplink Fast,
                                                            * FlexLink. */

        /* Cisco CFM. */
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc0ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc1ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc2ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc3ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc4ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc5ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc6ULL },
        { HMAP_NODE_NULL_INITIALIZER, 0x01000cccccc7ULL },
    };

    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    struct eth_addr_node *node;
    static struct hmap addrs;
    uint64_t ea64;

    if (ovsthread_once_start(&once)) {
        hmap_init(&addrs);
        for (node = nodes; node < &nodes[ARRAY_SIZE(nodes)]; node++) {
            hmap_insert(&addrs, &node->hmap_node, hash_uint64(node->ea64));
        }
        ovsthread_once_done(&once);
    }

    ea64 = eth_addr_to_uint64(ea);
    HMAP_FOR_EACH_IN_BUCKET (node, hmap_node, hash_uint64(ea64), &addrs) {
        if (node->ea64 == ea64) {
            return true;
        }
    }
    return false;
}

bool
eth_addr_from_string(const char *s, struct eth_addr *ea)
{
    if (ovs_scan(s, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(*ea))) {
        return true;
    } else {
        *ea = eth_addr_zero;
        return false;
    }
}

/* Fills 'b' with a Reverse ARP packet with Ethernet source address 'eth_src'.
 * This function is used by Open vSwitch to compose packets in cases where
 * context is important but content doesn't (or shouldn't) matter.
 *
 * The returned packet has enough headroom to insert an 802.1Q VLAN header if
 * desired. */
void
compose_rarp(struct dp_packet *b, const struct eth_addr eth_src)
{
    struct eth_header *eth;
    struct arp_eth_header *arp;

    dp_packet_clear(b);
    dp_packet_prealloc_tailroom(b, 2 + ETH_HEADER_LEN + VLAN_HEADER_LEN
                             + ARP_ETH_HEADER_LEN);
    dp_packet_reserve(b, 2 + VLAN_HEADER_LEN);
    eth = dp_packet_put_uninit(b, sizeof *eth);
    eth->eth_dst = eth_addr_broadcast;
    eth->eth_src = eth_src;
    eth->eth_type = htons(ETH_TYPE_RARP);

    arp = dp_packet_put_uninit(b, sizeof *arp);
    arp->ar_hrd = htons(ARP_HRD_ETHERNET);
    arp->ar_pro = htons(ARP_PRO_IP);
    arp->ar_hln = sizeof arp->ar_sha;
    arp->ar_pln = sizeof arp->ar_spa;
    arp->ar_op = htons(ARP_OP_RARP);
    arp->ar_sha = eth_src;
    put_16aligned_be32(&arp->ar_spa, htonl(0));
    arp->ar_tha = eth_src;
    put_16aligned_be32(&arp->ar_tpa, htonl(0));

    dp_packet_reset_offsets(b);
    dp_packet_set_l3(b, arp);
}

/* Insert VLAN header according to given TCI. Packet passed must be Ethernet
 * packet.  Ignores the CFI bit of 'tci' using 0 instead.
 *
 * Also adjusts the layer offsets accordingly. */
void
eth_push_vlan(struct dp_packet *packet, ovs_be16 tpid, ovs_be16 tci)
{
    struct vlan_eth_header *veh;

    /* Insert new 802.1Q header. */
    veh = dp_packet_resize_l2(packet, VLAN_HEADER_LEN);
    memmove(veh, (char *)veh + VLAN_HEADER_LEN, 2 * ETH_ADDR_LEN);
    veh->veth_type = tpid;
    veh->veth_tci = tci & htons(~VLAN_CFI);
}

/* Removes outermost VLAN header (if any is present) from 'packet'.
 *
 * 'packet->l2_5' should initially point to 'packet''s outer-most VLAN header
 * or may be NULL if there are no VLAN headers. */
void
eth_pop_vlan(struct dp_packet *packet)
{
    struct vlan_eth_header *veh = dp_packet_l2(packet);

    if (veh && dp_packet_size(packet) >= sizeof *veh
        && eth_type_vlan(veh->veth_type)) {

        memmove((char *)veh + VLAN_HEADER_LEN, veh, 2 * ETH_ADDR_LEN);
        dp_packet_resize_l2(packet, -VLAN_HEADER_LEN);
    }
}

/* Set ethertype of the packet. */
static void
set_ethertype(struct dp_packet *packet, ovs_be16 eth_type)
{
    struct eth_header *eh = dp_packet_l2(packet);

    if (!eh) {
        return;
    }

    if (eth_type_vlan(eh->eth_type)) {
        ovs_be16 *p;
        char *l2_5 = dp_packet_l2_5(packet);

        p = ALIGNED_CAST(ovs_be16 *,
                         (l2_5 ? l2_5 : (char *)dp_packet_l3(packet)) - 2);
        *p = eth_type;
    } else {
        eh->eth_type = eth_type;
    }
}

static bool is_mpls(struct dp_packet *packet)
{
    return packet->l2_5_ofs != UINT16_MAX;
}

/* Set time to live (TTL) of an MPLS label stack entry (LSE). */
void
set_mpls_lse_ttl(ovs_be32 *lse, uint8_t ttl)
{
    *lse &= ~htonl(MPLS_TTL_MASK);
    *lse |= htonl((ttl << MPLS_TTL_SHIFT) & MPLS_TTL_MASK);
}

/* Set traffic class (TC) of an MPLS label stack entry (LSE). */
void
set_mpls_lse_tc(ovs_be32 *lse, uint8_t tc)
{
    *lse &= ~htonl(MPLS_TC_MASK);
    *lse |= htonl((tc << MPLS_TC_SHIFT) & MPLS_TC_MASK);
}

/* Set label of an MPLS label stack entry (LSE). */
void
set_mpls_lse_label(ovs_be32 *lse, ovs_be32 label)
{
    *lse &= ~htonl(MPLS_LABEL_MASK);
    *lse |= htonl((ntohl(label) << MPLS_LABEL_SHIFT) & MPLS_LABEL_MASK);
}

/* Set bottom of stack (BoS) bit of an MPLS label stack entry (LSE). */
void
set_mpls_lse_bos(ovs_be32 *lse, uint8_t bos)
{
    *lse &= ~htonl(MPLS_BOS_MASK);
    *lse |= htonl((bos << MPLS_BOS_SHIFT) & MPLS_BOS_MASK);
}

/* Compose an MPLS label stack entry (LSE) from its components:
 * label, traffic class (TC), time to live (TTL) and
 * bottom of stack (BoS) bit. */
ovs_be32
set_mpls_lse_values(uint8_t ttl, uint8_t tc, uint8_t bos, ovs_be32 label)
{
    ovs_be32 lse = htonl(0);
    set_mpls_lse_ttl(&lse, ttl);
    set_mpls_lse_tc(&lse, tc);
    set_mpls_lse_bos(&lse, bos);
    set_mpls_lse_label(&lse, label);
    return lse;
}

/* Set MPLS label stack entry to outermost MPLS header.*/
void
set_mpls_lse(struct dp_packet *packet, ovs_be32 mpls_lse)
{
    /* Packet type should be MPLS to set label stack entry. */
    if (is_mpls(packet)) {
        struct mpls_hdr *mh = dp_packet_l2_5(packet);

        /* Update mpls label stack entry. */
        put_16aligned_be32(&mh->mpls_lse, mpls_lse);
    }
}

/* Push MPLS label stack entry 'lse' onto 'packet' as the outermost MPLS
 * header.  If 'packet' does not already have any MPLS labels, then its
 * Ethertype is changed to 'ethtype' (which must be an MPLS Ethertype). */
void
push_mpls(struct dp_packet *packet, ovs_be16 ethtype, ovs_be32 lse)
{
    char * header;
    size_t len;

    if (!eth_type_mpls(ethtype)) {
        return;
    }

    if (!is_mpls(packet)) {
        /* Set MPLS label stack offset. */
        packet->l2_5_ofs = packet->l3_ofs;
    }

    set_ethertype(packet, ethtype);

    /* Push new MPLS shim header onto packet. */
    len = packet->l2_5_ofs;
    header = dp_packet_resize_l2_5(packet, MPLS_HLEN);
    memmove(header, header + MPLS_HLEN, len);
    memcpy(header + len, &lse, sizeof lse);
}

/* If 'packet' is an MPLS packet, removes its outermost MPLS label stack entry.
 * If the label that was removed was the only MPLS label, changes 'packet''s
 * Ethertype to 'ethtype' (which ordinarily should not be an MPLS
 * Ethertype). */
void
pop_mpls(struct dp_packet *packet, ovs_be16 ethtype)
{
    if (is_mpls(packet)) {
        struct mpls_hdr *mh = dp_packet_l2_5(packet);
        size_t len = packet->l2_5_ofs;

        set_ethertype(packet, ethtype);
        if (get_16aligned_be32(&mh->mpls_lse) & htonl(MPLS_BOS_MASK)) {
            dp_packet_set_l2_5(packet, NULL);
        }
        /* Shift the l2 header forward. */
        memmove((char*)dp_packet_data(packet) + MPLS_HLEN, dp_packet_data(packet), len);
        dp_packet_resize_l2_5(packet, -MPLS_HLEN);
    }
}

/* Converts hex digits in 'hex' to an Ethernet packet in '*packetp'.  The
 * caller must free '*packetp'.  On success, returns NULL.  On failure, returns
 * an error message and stores NULL in '*packetp'.
 *
 * Aligns the L3 header of '*packetp' on a 32-bit boundary. */
const char *
eth_from_hex(const char *hex, struct dp_packet **packetp)
{
    struct dp_packet *packet;

    /* Use 2 bytes of headroom to 32-bit align the L3 header. */
    packet = *packetp = dp_packet_new_with_headroom(strlen(hex) / 2, 2);

    if (dp_packet_put_hex(packet, hex, NULL)[0] != '\0') {
        dp_packet_delete(packet);
        *packetp = NULL;
        return "Trailing garbage in packet data";
    }

    if (dp_packet_size(packet) < ETH_HEADER_LEN) {
        dp_packet_delete(packet);
        *packetp = NULL;
        return "Packet data too short for Ethernet";
    }

    return NULL;
}

void
eth_format_masked(const struct eth_addr eth,
                  const struct eth_addr *mask, struct ds *s)
{
    ds_put_format(s, ETH_ADDR_FMT, ETH_ADDR_ARGS(eth));
    if (mask && !eth_mask_is_exact(*mask)) {
        ds_put_format(s, "/"ETH_ADDR_FMT, ETH_ADDR_ARGS(*mask));
    }
}

/* Given the IP netmask 'netmask', returns the number of bits of the IP address
 * that it specifies, that is, the number of 1-bits in 'netmask'.
 *
 * If 'netmask' is not a CIDR netmask (see ip_is_cidr()), the return value will
 * still be in the valid range but isn't otherwise meaningful. */
int
ip_count_cidr_bits(ovs_be32 netmask)
{
    return 32 - ctz32(ntohl(netmask));
}

void
ip_format_masked(ovs_be32 ip, ovs_be32 mask, struct ds *s)
{
    ds_put_format(s, IP_FMT, IP_ARGS(ip));
    if (mask != OVS_BE32_MAX) {
        if (ip_is_cidr(mask)) {
            ds_put_format(s, "/%d", ip_count_cidr_bits(mask));
        } else {
            ds_put_format(s, "/"IP_FMT, IP_ARGS(mask));
        }
    }
}

/* Parses string 's', which must be an IP address with an optional netmask or
 * CIDR prefix length.  Stores the IP address into '*ip' and the netmask into
 * '*mask'.  (If 's' does not contain a netmask, 255.255.255.255 is
 * assumed.)
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ip_parse_masked(const char *s, ovs_be32 *ip, ovs_be32 *mask)
{
    int prefix;
    int n;

    if (ovs_scan(s, IP_SCAN_FMT"/"IP_SCAN_FMT"%n",
                 IP_SCAN_ARGS(ip), IP_SCAN_ARGS(mask), &n) && !s[n]) {
        /* OK. */
    } else if (ovs_scan(s, IP_SCAN_FMT"/%d%n", IP_SCAN_ARGS(ip), &prefix, &n)
               && !s[n]) {
        if (prefix <= 0 || prefix > 32) {
            return xasprintf("%s: network prefix bits not between 0 and "
                             "32", s);
        }
        *mask = be32_prefix_mask(prefix);
    } else if (ovs_scan(s, IP_SCAN_FMT"%n", IP_SCAN_ARGS(ip), &n) && !s[n]) {
        *mask = OVS_BE32_MAX;
    } else {
        return xasprintf("%s: invalid IP address", s);
    }
    return NULL;
}

void
ipv6_format_addr(const struct in6_addr *addr, struct ds *s)
{
    char *dst;

    ds_reserve(s, s->length + INET6_ADDRSTRLEN);

    dst = s->string + s->length;
    inet_ntop(AF_INET6, addr, dst, INET6_ADDRSTRLEN);
    s->length += strlen(dst);
}

void
ipv6_format_mapped(const struct in6_addr *addr, struct ds *s)
{
    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        ds_put_format(s, IP_FMT, addr->s6_addr[12], addr->s6_addr[13],
                                 addr->s6_addr[14], addr->s6_addr[15]);
    } else {
        ipv6_format_addr(addr, s);
    }
}

void
ipv6_format_masked(const struct in6_addr *addr, const struct in6_addr *mask,
                   struct ds *s)
{
    ipv6_format_addr(addr, s);
    if (mask && !ipv6_mask_is_exact(mask)) {
        if (ipv6_is_cidr(mask)) {
            int cidr_bits = ipv6_count_cidr_bits(mask);
            ds_put_format(s, "/%d", cidr_bits);
        } else {
            ds_put_char(s, '/');
            ipv6_format_addr(mask, s);
        }
    }
}

/* Stores the string representation of the IPv6 address 'addr' into the
 * character array 'addr_str', which must be at least INET6_ADDRSTRLEN
 * bytes long. If addr is IPv4-mapped, store an IPv4 dotted-decimal string. */
const char *
ipv6_string_mapped(char *addr_str, const struct in6_addr *addr)
{
    ovs_be32 ip;
    ip = in6_addr_get_mapped_ipv4(addr);
    if (ip) {
        return inet_ntop(AF_INET, &ip, addr_str, INET6_ADDRSTRLEN);
    } else {
        return inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
    }
}

struct in6_addr ipv6_addr_bitand(const struct in6_addr *a,
                                 const struct in6_addr *b)
{
    int i;
    struct in6_addr dst;

#ifdef s6_addr32
    for (i=0; i<4; i++) {
        dst.s6_addr32[i] = a->s6_addr32[i] & b->s6_addr32[i];
    }
#else
    for (i=0; i<16; i++) {
        dst.s6_addr[i] = a->s6_addr[i] & b->s6_addr[i];
    }
#endif

    return dst;
}

/* Returns an in6_addr consisting of 'mask' high-order 1-bits and 128-N
 * low-order 0-bits. */
struct in6_addr
ipv6_create_mask(int mask)
{
    struct in6_addr netmask;
    uint8_t *netmaskp = &netmask.s6_addr[0];

    memset(&netmask, 0, sizeof netmask);
    while (mask > 8) {
        *netmaskp = 0xff;
        netmaskp++;
        mask -= 8;
    }

    if (mask) {
        *netmaskp = 0xff << (8 - mask);
    }

    return netmask;
}

/* Given the IPv6 netmask 'netmask', returns the number of bits of the IPv6
 * address that it specifies, that is, the number of 1-bits in 'netmask'.
 * 'netmask' must be a CIDR netmask (see ipv6_is_cidr()).
 *
 * If 'netmask' is not a CIDR netmask (see ipv6_is_cidr()), the return value
 * will still be in the valid range but isn't otherwise meaningful. */
int
ipv6_count_cidr_bits(const struct in6_addr *netmask)
{
    int i;
    int count = 0;
    const uint8_t *netmaskp = &netmask->s6_addr[0];

    for (i=0; i<16; i++) {
        if (netmaskp[i] == 0xff) {
            count += 8;
        } else {
            uint8_t nm;

            for(nm = netmaskp[i]; nm; nm <<= 1) {
                count++;
            }
            break;
        }

    }

    return count;
}

/* Returns true if 'netmask' is a CIDR netmask, that is, if it consists of N
 * high-order 1-bits and 128-N low-order 0-bits. */
bool
ipv6_is_cidr(const struct in6_addr *netmask)
{
    const uint8_t *netmaskp = &netmask->s6_addr[0];
    int i;

    for (i=0; i<16; i++) {
        if (netmaskp[i] != 0xff) {
            uint8_t x = ~netmaskp[i];
            if (x & (x + 1)) {
                return false;
            }
            while (++i < 16) {
                if (netmaskp[i]) {
                    return false;
                }
            }
        }
    }

    return true;
}

/* Parses string 's', which must be an IPv6 address with an optional
 * CIDR prefix length.  Stores the IP address into '*ipv6' and the CIDR
 * prefix in '*prefix'.  (If 's' does not contain a CIDR length, all-ones
 * is assumed.)
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_masked(const char *s, struct in6_addr *ipv6, struct in6_addr *mask)
{
    char ipv6_s[IPV6_SCAN_LEN + 1];
    char mask_s[IPV6_SCAN_LEN + 1];
    int prefix;
    int n;

    if (ovs_scan(s, IPV6_SCAN_FMT"/"IPV6_SCAN_FMT"%n", ipv6_s, mask_s, &n)
        && inet_pton(AF_INET6, ipv6_s, ipv6) == 1
        && inet_pton(AF_INET6, mask_s, mask) == 1
        && !s[n]) {
        /* OK. */
    } else if (ovs_scan(s, IPV6_SCAN_FMT"/%d%n", ipv6_s, &prefix, &n)
        && inet_pton(AF_INET6, ipv6_s, ipv6) == 1
        && !s[n]) {
        if (prefix <= 0 || prefix > 128) {
            return xasprintf("%s: prefix bits not between 0 and 128", s);
        }
        *mask = ipv6_create_mask(prefix);
    } else if (ovs_scan(s, IPV6_SCAN_FMT"%n", ipv6_s, &n)
               && inet_pton(AF_INET6, ipv6_s, ipv6) == 1
               && !s[n]) {
        *mask = in6addr_exact;
    } else {
        return xasprintf("%s: invalid IP address", s);
    }
    return NULL;
}

/* Populates 'b' with an Ethernet II packet headed with the given 'eth_dst',
 * 'eth_src' and 'eth_type' parameters.  A payload of 'size' bytes is allocated
 * in 'b' and returned.  This payload may be populated with appropriate
 * information by the caller.  Sets 'b''s 'frame' pointer and 'l3' offset to
 * the Ethernet header and payload respectively.  Aligns b->l3 on a 32-bit
 * boundary.
 *
 * The returned packet has enough headroom to insert an 802.1Q VLAN header if
 * desired. */
void *
eth_compose(struct dp_packet *b, const struct eth_addr eth_dst,
            const struct eth_addr eth_src, uint16_t eth_type,
            size_t size)
{
    void *data;
    struct eth_header *eth;

    dp_packet_clear(b);

    /* The magic 2 here ensures that the L3 header (when it is added later)
     * will be 32-bit aligned. */
    dp_packet_prealloc_tailroom(b, 2 + ETH_HEADER_LEN + VLAN_HEADER_LEN + size);
    dp_packet_reserve(b, 2 + VLAN_HEADER_LEN);
    eth = dp_packet_put_uninit(b, ETH_HEADER_LEN);
    data = dp_packet_put_uninit(b, size);

    eth->eth_dst = eth_dst;
    eth->eth_src = eth_src;
    eth->eth_type = htons(eth_type);

    dp_packet_reset_offsets(b);
    dp_packet_set_l3(b, data);

    return data;
}

static void
packet_set_ipv4_addr(struct dp_packet *packet,
                     ovs_16aligned_be32 *addr, ovs_be32 new_addr)
{
    struct ip_header *nh = dp_packet_l3(packet);
    ovs_be32 old_addr = get_16aligned_be32(addr);
    size_t l4_size = dp_packet_l4_size(packet);

    if (nh->ip_proto == IPPROTO_TCP && l4_size >= TCP_HEADER_LEN) {
        struct tcp_header *th = dp_packet_l4(packet);

        th->tcp_csum = recalc_csum32(th->tcp_csum, old_addr, new_addr);
    } else if (nh->ip_proto == IPPROTO_UDP && l4_size >= UDP_HEADER_LEN ) {
        struct udp_header *uh = dp_packet_l4(packet);

        if (uh->udp_csum) {
            uh->udp_csum = recalc_csum32(uh->udp_csum, old_addr, new_addr);
            if (!uh->udp_csum) {
                uh->udp_csum = htons(0xffff);
            }
        }
    }
    nh->ip_csum = recalc_csum32(nh->ip_csum, old_addr, new_addr);
    put_16aligned_be32(addr, new_addr);
}

/* Returns true, if packet contains at least one routing header where
 * segements_left > 0.
 *
 * This function assumes that L3 and L4 offsets are set in the packet. */
static bool
packet_rh_present(struct dp_packet *packet)
{
    const struct ovs_16aligned_ip6_hdr *nh;
    int nexthdr;
    size_t len;
    size_t remaining;
    uint8_t *data = dp_packet_l3(packet);

    remaining = packet->l4_ofs - packet->l3_ofs;

    if (remaining < sizeof *nh) {
        return false;
    }
    nh = ALIGNED_CAST(struct ovs_16aligned_ip6_hdr *, data);
    data += sizeof *nh;
    remaining -= sizeof *nh;
    nexthdr = nh->ip6_nxt;

    while (1) {
        if ((nexthdr != IPPROTO_HOPOPTS)
                && (nexthdr != IPPROTO_ROUTING)
                && (nexthdr != IPPROTO_DSTOPTS)
                && (nexthdr != IPPROTO_AH)
                && (nexthdr != IPPROTO_FRAGMENT)) {
            /* It's either a terminal header (e.g., TCP, UDP) or one we
             * don't understand.  In either case, we're done with the
             * packet, so use it to fill in 'nw_proto'. */
            break;
        }

        /* We only verify that at least 8 bytes of the next header are
         * available, but many of these headers are longer.  Ensure that
         * accesses within the extension header are within those first 8
         * bytes. All extension headers are required to be at least 8
         * bytes. */
        if (remaining < 8) {
            return false;
        }

        if (nexthdr == IPPROTO_AH) {
            /* A standard AH definition isn't available, but the fields
             * we care about are in the same location as the generic
             * option header--only the header length is calculated
             * differently. */
            const struct ip6_ext *ext_hdr = (struct ip6_ext *)data;

            nexthdr = ext_hdr->ip6e_nxt;
            len = (ext_hdr->ip6e_len + 2) * 4;
        } else if (nexthdr == IPPROTO_FRAGMENT) {
            const struct ovs_16aligned_ip6_frag *frag_hdr
                = ALIGNED_CAST(struct ovs_16aligned_ip6_frag *, data);

            nexthdr = frag_hdr->ip6f_nxt;
            len = sizeof *frag_hdr;
        } else if (nexthdr == IPPROTO_ROUTING) {
            const struct ip6_rthdr *rh = (struct ip6_rthdr *)data;

            if (rh->ip6r_segleft > 0) {
                return true;
            }

            nexthdr = rh->ip6r_nxt;
            len = (rh->ip6r_len + 1) * 8;
        } else {
            const struct ip6_ext *ext_hdr = (struct ip6_ext *)data;

            nexthdr = ext_hdr->ip6e_nxt;
            len = (ext_hdr->ip6e_len + 1) * 8;
        }

        if (remaining < len) {
            return false;
        }
        remaining -= len;
        data += len;
    }

    return false;
}

static void
packet_update_csum128(struct dp_packet *packet, uint8_t proto,
                     ovs_16aligned_be32 addr[4], const ovs_be32 new_addr[4])
{
    size_t l4_size = dp_packet_l4_size(packet);

    if (proto == IPPROTO_TCP && l4_size >= TCP_HEADER_LEN) {
        struct tcp_header *th = dp_packet_l4(packet);

        th->tcp_csum = recalc_csum128(th->tcp_csum, addr, new_addr);
    } else if (proto == IPPROTO_UDP && l4_size >= UDP_HEADER_LEN) {
        struct udp_header *uh = dp_packet_l4(packet);

        if (uh->udp_csum) {
            uh->udp_csum = recalc_csum128(uh->udp_csum, addr, new_addr);
            if (!uh->udp_csum) {
                uh->udp_csum = htons(0xffff);
            }
        }
    } else if (proto == IPPROTO_ICMPV6 &&
               l4_size >= sizeof(struct icmp6_header)) {
        struct icmp6_header *icmp = dp_packet_l4(packet);

        icmp->icmp6_cksum = recalc_csum128(icmp->icmp6_cksum, addr, new_addr);
    }
}

static void
packet_set_ipv6_addr(struct dp_packet *packet, uint8_t proto,
                     ovs_16aligned_be32 addr[4], const ovs_be32 new_addr[4],
                     bool recalculate_csum)
{
    if (recalculate_csum) {
        packet_update_csum128(packet, proto, addr, new_addr);
    }
    memcpy(addr, new_addr, sizeof(ovs_be32[4]));
}

static void
packet_set_ipv6_flow_label(ovs_16aligned_be32 *flow_label, ovs_be32 flow_key)
{
    ovs_be32 old_label = get_16aligned_be32(flow_label);
    ovs_be32 new_label = (old_label & htonl(~IPV6_LABEL_MASK)) | flow_key;
    put_16aligned_be32(flow_label, new_label);
}

static void
packet_set_ipv6_tc(ovs_16aligned_be32 *flow_label, uint8_t tc)
{
    ovs_be32 old_label = get_16aligned_be32(flow_label);
    ovs_be32 new_label = (old_label & htonl(0xF00FFFFF)) | htonl(tc << 20);
    put_16aligned_be32(flow_label, new_label);
}

/* Modifies the IPv4 header fields of 'packet' to be consistent with 'src',
 * 'dst', 'tos', and 'ttl'.  Updates 'packet''s L4 checksums as appropriate.
 * 'packet' must contain a valid IPv4 packet with correctly populated l[347]
 * markers. */
void
packet_set_ipv4(struct dp_packet *packet, ovs_be32 src, ovs_be32 dst,
                uint8_t tos, uint8_t ttl)
{
    struct ip_header *nh = dp_packet_l3(packet);

    if (get_16aligned_be32(&nh->ip_src) != src) {
        packet_set_ipv4_addr(packet, &nh->ip_src, src);
    }

    if (get_16aligned_be32(&nh->ip_dst) != dst) {
        packet_set_ipv4_addr(packet, &nh->ip_dst, dst);
    }

    if (nh->ip_tos != tos) {
        uint8_t *field = &nh->ip_tos;

        nh->ip_csum = recalc_csum16(nh->ip_csum, htons((uint16_t) *field),
                                    htons((uint16_t) tos));
        *field = tos;
    }

    if (nh->ip_ttl != ttl) {
        uint8_t *field = &nh->ip_ttl;

        nh->ip_csum = recalc_csum16(nh->ip_csum, htons(*field << 8),
                                    htons(ttl << 8));
        *field = ttl;
    }
}

/* Modifies the IPv6 header fields of 'packet' to be consistent with 'src',
 * 'dst', 'traffic class', and 'next hop'.  Updates 'packet''s L4 checksums as
 * appropriate. 'packet' must contain a valid IPv6 packet with correctly
 * populated l[34] offsets. */
void
packet_set_ipv6(struct dp_packet *packet, uint8_t proto, const ovs_be32 src[4],
                const ovs_be32 dst[4], uint8_t key_tc, ovs_be32 key_fl,
                uint8_t key_hl)
{
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(packet);

    if (memcmp(&nh->ip6_src, src, sizeof(ovs_be32[4]))) {
        packet_set_ipv6_addr(packet, proto, nh->ip6_src.be32, src, true);
    }

    if (memcmp(&nh->ip6_dst, dst, sizeof(ovs_be32[4]))) {
        packet_set_ipv6_addr(packet, proto, nh->ip6_dst.be32, dst,
                             !packet_rh_present(packet));
    }

    packet_set_ipv6_tc(&nh->ip6_flow, key_tc);

    packet_set_ipv6_flow_label(&nh->ip6_flow, key_fl);

    nh->ip6_hlim = key_hl;
}

static void
packet_set_port(ovs_be16 *port, ovs_be16 new_port, ovs_be16 *csum)
{
    if (*port != new_port) {
        *csum = recalc_csum16(*csum, *port, new_port);
        *port = new_port;
    }
}

/* Sets the TCP source and destination port ('src' and 'dst' respectively) of
 * the TCP header contained in 'packet'.  'packet' must be a valid TCP packet
 * with its l4 offset properly populated. */
void
packet_set_tcp_port(struct dp_packet *packet, ovs_be16 src, ovs_be16 dst)
{
    struct tcp_header *th = dp_packet_l4(packet);

    packet_set_port(&th->tcp_src, src, &th->tcp_csum);
    packet_set_port(&th->tcp_dst, dst, &th->tcp_csum);
}

/* Sets the UDP source and destination port ('src' and 'dst' respectively) of
 * the UDP header contained in 'packet'.  'packet' must be a valid UDP packet
 * with its l4 offset properly populated. */
void
packet_set_udp_port(struct dp_packet *packet, ovs_be16 src, ovs_be16 dst)
{
    struct udp_header *uh = dp_packet_l4(packet);

    if (uh->udp_csum) {
        packet_set_port(&uh->udp_src, src, &uh->udp_csum);
        packet_set_port(&uh->udp_dst, dst, &uh->udp_csum);

        if (!uh->udp_csum) {
            uh->udp_csum = htons(0xffff);
        }
    } else {
        uh->udp_src = src;
        uh->udp_dst = dst;
    }
}

/* Sets the SCTP source and destination port ('src' and 'dst' respectively) of
 * the SCTP header contained in 'packet'.  'packet' must be a valid SCTP packet
 * with its l4 offset properly populated. */
void
packet_set_sctp_port(struct dp_packet *packet, ovs_be16 src, ovs_be16 dst)
{
    struct sctp_header *sh = dp_packet_l4(packet);
    ovs_be32 old_csum, old_correct_csum, new_csum;
    uint16_t tp_len = dp_packet_l4_size(packet);

    old_csum = get_16aligned_be32(&sh->sctp_csum);
    put_16aligned_be32(&sh->sctp_csum, 0);
    old_correct_csum = crc32c((void *)sh, tp_len);

    sh->sctp_src = src;
    sh->sctp_dst = dst;

    new_csum = crc32c((void *)sh, tp_len);
    put_16aligned_be32(&sh->sctp_csum, old_csum ^ old_correct_csum ^ new_csum);
}

/* Sets the ICMP type and code of the ICMP header contained in 'packet'.
 * 'packet' must be a valid ICMP packet with its l4 offset properly
 * populated. */
void
packet_set_icmp(struct dp_packet *packet, uint8_t type, uint8_t code)
{
    struct icmp_header *ih = dp_packet_l4(packet);
    ovs_be16 orig_tc = htons(ih->icmp_type << 8 | ih->icmp_code);
    ovs_be16 new_tc = htons(type << 8 | code);

    if (orig_tc != new_tc) {
        ih->icmp_type = type;
        ih->icmp_code = code;

        ih->icmp_csum = recalc_csum16(ih->icmp_csum, orig_tc, new_tc);
    }
}

void
packet_set_nd(struct dp_packet *packet, const ovs_be32 target[4],
              const struct eth_addr sll, const struct eth_addr tll) {
    struct ovs_nd_msg *ns;
    struct ovs_nd_opt *nd_opt;
    int bytes_remain = dp_packet_l4_size(packet);

    if (OVS_UNLIKELY(bytes_remain < sizeof(*ns))) {
        return;
    }

    ns = dp_packet_l4(packet);
    nd_opt = &ns->options[0];
    bytes_remain -= sizeof(*ns);

    if (memcmp(&ns->target, target, sizeof(ovs_be32[4]))) {
        packet_set_ipv6_addr(packet, IPPROTO_ICMPV6,
                             ns->target.be32,
                             target, true);
    }

    while (bytes_remain >= ND_OPT_LEN && nd_opt->nd_opt_len != 0) {
        if (nd_opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR
            && nd_opt->nd_opt_len == 1) {
            if (!eth_addr_equals(nd_opt->nd_opt_mac, sll)) {
                ovs_be16 *csum = &(ns->icmph.icmp6_cksum);

                *csum = recalc_csum48(*csum, nd_opt->nd_opt_mac, sll);
                nd_opt->nd_opt_mac = sll;
            }

            /* A packet can only contain one SLL or TLL option */
            break;
        } else if (nd_opt->nd_opt_type == ND_OPT_TARGET_LINKADDR
                   && nd_opt->nd_opt_len == 1) {
            if (!eth_addr_equals(nd_opt->nd_opt_mac, tll)) {
                ovs_be16 *csum = &(ns->icmph.icmp6_cksum);

                *csum = recalc_csum48(*csum, nd_opt->nd_opt_mac, tll);
                nd_opt->nd_opt_mac = tll;
            }

            /* A packet can only contain one SLL or TLL option */
            break;
        }

        nd_opt += nd_opt->nd_opt_len;
        bytes_remain -= nd_opt->nd_opt_len * ND_OPT_LEN;
    }
}

const char *
packet_tcp_flag_to_string(uint32_t flag)
{
    switch (flag) {
    case TCP_FIN:
        return "fin";
    case TCP_SYN:
        return "syn";
    case TCP_RST:
        return "rst";
    case TCP_PSH:
        return "psh";
    case TCP_ACK:
        return "ack";
    case TCP_URG:
        return "urg";
    case TCP_ECE:
        return "ece";
    case TCP_CWR:
        return "cwr";
    case TCP_NS:
        return "ns";
    case 0x200:
        return "[200]";
    case 0x400:
        return "[400]";
    case 0x800:
        return "[800]";
    default:
        return NULL;
    }
}

/* Appends a string representation of the TCP flags value 'tcp_flags'
 * (e.g. from struct flow.tcp_flags or obtained via TCP_FLAGS) to 's', in the
 * format used by tcpdump. */
void
packet_format_tcp_flags(struct ds *s, uint16_t tcp_flags)
{
    if (!tcp_flags) {
        ds_put_cstr(s, "none");
        return;
    }

    if (tcp_flags & TCP_SYN) {
        ds_put_char(s, 'S');
    }
    if (tcp_flags & TCP_FIN) {
        ds_put_char(s, 'F');
    }
    if (tcp_flags & TCP_PSH) {
        ds_put_char(s, 'P');
    }
    if (tcp_flags & TCP_RST) {
        ds_put_char(s, 'R');
    }
    if (tcp_flags & TCP_URG) {
        ds_put_char(s, 'U');
    }
    if (tcp_flags & TCP_ACK) {
        ds_put_char(s, '.');
    }
    if (tcp_flags & TCP_ECE) {
        ds_put_cstr(s, "E");
    }
    if (tcp_flags & TCP_CWR) {
        ds_put_cstr(s, "C");
    }
    if (tcp_flags & TCP_NS) {
        ds_put_cstr(s, "N");
    }
    if (tcp_flags & 0x200) {
        ds_put_cstr(s, "[200]");
    }
    if (tcp_flags & 0x400) {
        ds_put_cstr(s, "[400]");
    }
    if (tcp_flags & 0x800) {
        ds_put_cstr(s, "[800]");
    }
}

#define ARP_PACKET_SIZE  (2 + ETH_HEADER_LEN + VLAN_HEADER_LEN + \
                          ARP_ETH_HEADER_LEN)

/* Clears 'b' and replaces its contents by an ARP frame with the specified
 * 'arp_op', 'arp_sha', 'arp_tha', 'arp_spa', and 'arp_tpa'.  The outer
 * Ethernet frame is initialized with Ethernet source 'arp_sha' and destination
 * 'arp_tha', except that destination ff:ff:ff:ff:ff:ff is used instead if
 * 'broadcast' is true. */
void
compose_arp(struct dp_packet *b, uint16_t arp_op,
            const struct eth_addr arp_sha, const struct eth_addr arp_tha,
            bool broadcast, ovs_be32 arp_spa, ovs_be32 arp_tpa)
{
    struct eth_header *eth;
    struct arp_eth_header *arp;

    dp_packet_clear(b);
    dp_packet_prealloc_tailroom(b, ARP_PACKET_SIZE);
    dp_packet_reserve(b, 2 + VLAN_HEADER_LEN);

    eth = dp_packet_put_uninit(b, sizeof *eth);
    eth->eth_dst = broadcast ? eth_addr_broadcast : arp_tha;
    eth->eth_src = arp_sha;
    eth->eth_type = htons(ETH_TYPE_ARP);

    arp = dp_packet_put_uninit(b, sizeof *arp);
    arp->ar_hrd = htons(ARP_HRD_ETHERNET);
    arp->ar_pro = htons(ARP_PRO_IP);
    arp->ar_hln = sizeof arp->ar_sha;
    arp->ar_pln = sizeof arp->ar_spa;
    arp->ar_op = htons(arp_op);
    arp->ar_sha = arp_sha;
    arp->ar_tha = arp_tha;

    put_16aligned_be32(&arp->ar_spa, arp_spa);
    put_16aligned_be32(&arp->ar_tpa, arp_tpa);

    dp_packet_reset_offsets(b);
    dp_packet_set_l3(b, arp);
}

void
compose_nd(struct dp_packet *b, const struct eth_addr eth_src,
           struct in6_addr * ipv6_src, struct in6_addr * ipv6_dst)
{
    struct in6_addr sn_addr;
    struct eth_addr eth_dst;
    struct ovs_nd_msg *ns;
    struct ovs_nd_opt *nd_opt;

    in6_addr_solicited_node(&sn_addr, ipv6_dst);
    ipv6_multicast_to_ethernet(&eth_dst, &sn_addr);

    eth_compose(b, eth_dst, eth_src, ETH_TYPE_IPV6,
                IPV6_HEADER_LEN + ICMP6_HEADER_LEN + ND_OPT_LEN);
    packet_set_ipv6(b, IPPROTO_ICMPV6,
                    ALIGNED_CAST(ovs_be32 *, ipv6_src->s6_addr),
                    ALIGNED_CAST(ovs_be32 *, sn_addr.s6_addr),
                    0, 0, 255);

    ns = dp_packet_l4(b);
    nd_opt = &ns->options[0];

    ns->icmph.icmp6_type = ND_NEIGHBOR_SOLICIT;
    ns->icmph.icmp6_code = 0;

    nd_opt->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    packet_set_nd(b, ALIGNED_CAST(ovs_be32 *, ipv6_dst->s6_addr),
                  eth_src, eth_addr_zero);
}

uint32_t
packet_csum_pseudoheader(const struct ip_header *ip)
{
    uint32_t partial = 0;

    partial = csum_add32(partial, get_16aligned_be32(&ip->ip_src));
    partial = csum_add32(partial, get_16aligned_be32(&ip->ip_dst));
    partial = csum_add16(partial, htons(ip->ip_proto));
    partial = csum_add16(partial, htons(ntohs(ip->ip_tot_len) -
                                        IP_IHL(ip->ip_ihl_ver) * 4));

    return partial;
}

#ifndef __CHECKER__
uint32_t
packet_csum_pseudoheader6(const struct ovs_16aligned_ip6_hdr *ip6)
{
    uint32_t partial = 0;

    partial = csum_add32(partial, get_16aligned_be32(&(ip6->ip6_src.be32[0])));
    partial = csum_add32(partial, get_16aligned_be32(&(ip6->ip6_src.be32[1])));
    partial = csum_add32(partial, get_16aligned_be32(&(ip6->ip6_src.be32[2])));
    partial = csum_add32(partial, get_16aligned_be32(&(ip6->ip6_src.be32[3])));
    partial = csum_add32(partial, get_16aligned_be32(&(ip6->ip6_dst.be32[0])));
    partial = csum_add32(partial, get_16aligned_be32(&(ip6->ip6_dst.be32[1])));
    partial = csum_add32(partial, get_16aligned_be32(&(ip6->ip6_dst.be32[2])));
    partial = csum_add32(partial, get_16aligned_be32(&(ip6->ip6_dst.be32[3])));

    partial = csum_add16(partial, 0);
    partial = csum_add16(partial, ip6->ip6_plen);
    partial = csum_add16(partial, 0);
    partial = csum_add16(partial, ip6->ip6_nxt);

    return partial;
}
#endif
