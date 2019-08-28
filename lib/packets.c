/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2015, 2016 Nicira, Inc.
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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <stdlib.h>
#include <netdb.h>
#include "byte-order.h"
#include "csum.h"
#include "crc32c.h"
#include "flow.h"
#include "openvswitch/hmap.h"
#include "openvswitch/dynamic-string.h"
#include "ovs-thread.h"
#include "odp-util.h"
#include "dp-packet.h"
#include "unaligned.h"

const struct in6_addr in6addr_exact = IN6ADDR_EXACT_INIT;
const struct in6_addr in6addr_all_hosts = IN6ADDR_ALL_HOSTS_INIT;
const struct in6_addr in6addr_all_routers = IN6ADDR_ALL_ROUTERS_INIT;

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

/* Returns true if 's' consists entirely of hex digits, false otherwise. */
static bool
is_all_hex(const char *s)
{
    return s[strspn(s, "0123456789abcdefABCDEF")] == '\0';
}

/* Parses 's' as a 16-digit hexadecimal number representing a datapath ID.  On
 * success stores the dpid into '*dpidp' and returns true, on failure stores 0
 * into '*dpidp' and returns false.
 *
 * Rejects an all-zeros dpid as invalid. */
bool
dpid_from_string(const char *s, uint64_t *dpidp)
{
    size_t len = strlen(s);
    *dpidp = ((len == 16 && is_all_hex(s))
              || (len <= 18 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')
                  && is_all_hex(s + 2))
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

/* Attempts to parse 's' as an Ethernet address.  If successful, stores the
 * address in 'ea' and returns true, otherwise zeros 'ea' and returns
 * false.  This function checks trailing characters. */
bool
eth_addr_from_string(const char *s, struct eth_addr *ea)
{
    int n = 0;
    if (ovs_scan(s, ETH_ADDR_SCAN_FMT"%n", ETH_ADDR_SCAN_ARGS(*ea), &n)
        && !s[n]) {
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
    b->packet_type = htonl(PT_ETH);
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
    struct vlan_eth_header *veh = dp_packet_eth(packet);

    if (veh && dp_packet_size(packet) >= sizeof *veh
        && eth_type_vlan(veh->veth_type)) {

        memmove((char *)veh + VLAN_HEADER_LEN, veh, 2 * ETH_ADDR_LEN);
        dp_packet_resize_l2(packet, -VLAN_HEADER_LEN);
    }
}

/* Push Ethernet header onto 'packet' assuming it is layer 3 */
void
push_eth(struct dp_packet *packet, const struct eth_addr *dst,
         const struct eth_addr *src)
{
    struct eth_header *eh;

    ovs_assert(packet->packet_type != htonl(PT_ETH));
    eh = dp_packet_resize_l2(packet, ETH_HEADER_LEN);
    eh->eth_dst = *dst;
    eh->eth_src = *src;
    eh->eth_type = pt_ns_type_be(packet->packet_type);
    packet->packet_type = htonl(PT_ETH);
}

/* Removes Ethernet header, including VLAN header, from 'packet'.
 *
 * Previous to calling this function, 'ofpbuf_l3(packet)' must not be NULL */
void
pop_eth(struct dp_packet *packet)
{
    char *l2_5 = dp_packet_l2_5(packet);
    char *l3 = dp_packet_l3(packet);
    ovs_be16 ethertype;
    int increment;

    ovs_assert(packet->packet_type == htonl(PT_ETH));
    ovs_assert(l3 != NULL);

    if (l2_5) {
        increment = packet->l2_5_ofs;
        ethertype = *(ALIGNED_CAST(ovs_be16 *, (l2_5 - 2)));
    } else {
        increment = packet->l3_ofs;
        ethertype = *(ALIGNED_CAST(ovs_be16 *, (l3 - 2)));
    }

    dp_packet_resize_l2(packet, -increment);
    packet->packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE, ntohs(ethertype));
}

/* Set ethertype of the packet. */
static void
set_ethertype(struct dp_packet *packet, ovs_be16 eth_type)
{
    struct eth_header *eh = dp_packet_eth(packet);

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

        /* Invalidate offload flags as they are not valid after
         * decapsulation of MPLS header. */
        dp_packet_reset_offload(packet);
    }
}

void
push_nsh(struct dp_packet *packet, const struct nsh_hdr *nsh_hdr_src)
{
    struct nsh_hdr *nsh;
    size_t length = nsh_hdr_len(nsh_hdr_src);
    uint8_t next_proto;

    switch (ntohl(packet->packet_type)) {
        case PT_ETH:
            next_proto = NSH_P_ETHERNET;
            break;
        case PT_IPV4:
            next_proto = NSH_P_IPV4;
            break;
        case PT_IPV6:
            next_proto = NSH_P_IPV6;
            break;
        case PT_NSH:
            next_proto = NSH_P_NSH;
            break;
        default:
            OVS_NOT_REACHED();
    }

    nsh = (struct nsh_hdr *) dp_packet_push_uninit(packet, length);
    memcpy(nsh, nsh_hdr_src, length);
    nsh->next_proto = next_proto;
    packet->packet_type = htonl(PT_NSH);
    dp_packet_reset_offsets(packet);
    packet->l3_ofs = 0;
}

bool
pop_nsh(struct dp_packet *packet)
{
    struct nsh_hdr *nsh = (struct nsh_hdr *) dp_packet_l3(packet);
    size_t length;
    uint32_t next_pt;

    if (packet->packet_type == htonl(PT_NSH) && nsh) {
        switch (nsh->next_proto) {
            case NSH_P_ETHERNET:
                next_pt = PT_ETH;
                break;
            case NSH_P_IPV4:
                next_pt = PT_IPV4;
                break;
            case NSH_P_IPV6:
                next_pt = PT_IPV6;
                break;
            case NSH_P_NSH:
                next_pt = PT_NSH;
                break;
            default:
                /* Unknown inner packet type. Drop packet. */
                return false;
        }

        length = nsh_hdr_len(nsh);
        dp_packet_reset_packet(packet, length);
        packet->packet_type = htonl(next_pt);
        /* Packet must be recirculated for further processing. */
    }
    return true;
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

/* Parses string 's', which must be an IP address.  Stores the IP address into
 * '*ip'.  Returns true if successful, otherwise false. */
bool
ip_parse(const char *s, ovs_be32 *ip)
{
    return inet_pton(AF_INET, s, ip) == 1;
}

/* Parses string 's', which must be an IP address with a port number
 * with ":" as a separator (e.g.: 192.168.1.2:80).
 * Stores the IP address into '*ip' and port number to '*port'.
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ip_parse_port(const char *s, ovs_be32 *ip, ovs_be16 *port)
{
    int n = 0;
    if (ovs_scan(s, IP_PORT_SCAN_FMT"%n", IP_PORT_SCAN_ARGS(ip, port), &n)
        && !s[n]) {
        return NULL;
    }

    return xasprintf("%s: invalid IP address or port number", s);
}

/* Parses string 's', which must be an IP address with an optional netmask or
 * CIDR prefix length.  Stores the IP address into '*ip', netmask into '*mask',
 * (255.255.255.255, if 's' lacks a netmask), and number of scanned characters
 * into '*n'.
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ip_parse_masked_len(const char *s, int *n, ovs_be32 *ip,
                    ovs_be32 *mask)
{
    int prefix;

    if (ovs_scan_len(s, n, IP_SCAN_FMT"/"IP_SCAN_FMT,
                 IP_SCAN_ARGS(ip), IP_SCAN_ARGS(mask))) {
        /* OK. */
    } else if (ovs_scan_len(s, n, IP_SCAN_FMT"/%d",
                            IP_SCAN_ARGS(ip), &prefix)) {
        if (prefix < 0 || prefix > 32) {
            return xasprintf("%s: IPv4 network prefix bits not between 0 and "
                              "32, inclusive", s);
        }
        *mask = be32_prefix_mask(prefix);
    } else if (ovs_scan_len(s, n, IP_SCAN_FMT, IP_SCAN_ARGS(ip))) {
        *mask = OVS_BE32_MAX;
    } else {
        return xasprintf("%s: invalid IP address", s);
    }
    return NULL;
}

/* This function is similar to ip_parse_masked_len(), but doesn't return the
 * number of scanned characters and expects 's' to end after the ip/(optional)
 * mask.
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ip_parse_masked(const char *s, ovs_be32 *ip, ovs_be32 *mask)
{
    int n = 0;

    char *error = ip_parse_masked_len(s, &n, ip, mask);
    if (!error && s[n]) {
        return xasprintf("%s: invalid IP address", s);
    }
    return error;
}

/* Similar to ip_parse_masked_len(), but the mask, if present, must be a CIDR
 * mask and is returned as a prefix len in '*plen'. */
char * OVS_WARN_UNUSED_RESULT
ip_parse_cidr_len(const char *s, int *n, ovs_be32 *ip, unsigned int *plen)
{
    ovs_be32 mask;
    char *error;

    error = ip_parse_masked_len(s, n, ip, &mask);
    if (error) {
        return error;
    }

    if (!ip_is_cidr(mask)) {
        return xasprintf("%s: CIDR network required", s);
    }
    *plen = ip_count_cidr_bits(mask);
    return NULL;
}

/* Similar to ip_parse_cidr_len(), but doesn't return the number of scanned
 * characters and expects 's' to be NULL terminated at the end of the
 * ip/(optional) cidr. */
char * OVS_WARN_UNUSED_RESULT
ip_parse_cidr(const char *s, ovs_be32 *ip, unsigned int *plen)
{
    int n = 0;

    char *error = ip_parse_cidr_len(s, &n, ip, plen);
    if (!error && s[n]) {
        return xasprintf("%s: invalid IP address", s);
    }
    return error;
}

/* Parses string 's', which must be an IPv6 address.  Stores the IPv6 address
 * into '*ip'.  Returns true if successful, otherwise false. */
bool
ipv6_parse(const char *s, struct in6_addr *ip)
{
    return inet_pton(AF_INET6, s, ip) == 1;
}

/* Parses string 's', which must be an IPv6 address with an optional netmask or
 * CIDR prefix length.  Stores the IPv6 address into '*ip' and the netmask into
 * '*mask' (if 's' does not contain a netmask, all-one-bits is assumed), and
 * number of scanned characters into '*n'.
 *
 * Returns NULL if successful, otherwise an error message that the caller must
 * free(). */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_masked_len(const char *s, int *n, struct in6_addr *ip,
                      struct in6_addr *mask)
{
    char ipv6_s[IPV6_SCAN_LEN + 1];
    int prefix;

    if (ovs_scan_len(s, n, " "IPV6_SCAN_FMT, ipv6_s)
        && ipv6_parse(ipv6_s, ip)) {
        if (ovs_scan_len(s, n, "/%d", &prefix)) {
            if (prefix < 0 || prefix > 128) {
                return xasprintf("%s: IPv6 network prefix bits not between 0 "
                                 "and 128, inclusive", s);
            }
            *mask = ipv6_create_mask(prefix);
        } else if (ovs_scan_len(s, n, "/"IPV6_SCAN_FMT, ipv6_s)) {
             if (!ipv6_parse(ipv6_s, mask)) {
                 return xasprintf("%s: Invalid IPv6 mask", s);
             }
            /* OK. */
        } else {
            /* OK. No mask. */
            *mask = in6addr_exact;
        }
        return NULL;
    }
    return xasprintf("%s: invalid IPv6 address", s);
}

/* This function is similar to ipv6_parse_masked_len(), but doesn't return the
 * number of scanned characters and expects 's' to end following the
 * ipv6/(optional) mask. */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_masked(const char *s, struct in6_addr *ip, struct in6_addr *mask)
{
    int n = 0;

    char *error = ipv6_parse_masked_len(s, &n, ip, mask);
    if (!error && s[n]) {
        return xasprintf("%s: invalid IPv6 address", s);
    }
    return error;
}

/* Similar to ipv6_parse_masked_len(), but the mask, if present, must be a CIDR
 * mask and is returned as a prefix length in '*plen'. */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_cidr_len(const char *s, int *n, struct in6_addr *ip,
                    unsigned int *plen)
{
    struct in6_addr mask;
    char *error;

    error = ipv6_parse_masked_len(s, n, ip, &mask);
    if (error) {
        return error;
    }

    if (!ipv6_is_cidr(&mask)) {
        return xasprintf("%s: IPv6 CIDR network required", s);
    }
    *plen = ipv6_count_cidr_bits(&mask);
    return NULL;
}

/* Similar to ipv6_parse_cidr_len(), but doesn't return the number of scanned
 * characters and expects 's' to end after the ipv6/(optional) cidr. */
char * OVS_WARN_UNUSED_RESULT
ipv6_parse_cidr(const char *s, struct in6_addr *ip, unsigned int *plen)
{
    int n = 0;

    char *error = ipv6_parse_cidr_len(s, &n, ip, plen);
    if (!error && s[n]) {
        return xasprintf("%s: invalid IPv6 address", s);
    }
    return error;
}

/* Stores the string representation of the IPv6 address 'addr' into the
 * character array 'addr_str', which must be at least INET6_ADDRSTRLEN
 * bytes long. */
void
ipv6_format_addr(const struct in6_addr *addr, struct ds *s)
{
    char *dst;

    ds_reserve(s, s->length + INET6_ADDRSTRLEN);

    dst = s->string + s->length;
    inet_ntop(AF_INET6, addr, dst, INET6_ADDRSTRLEN);
    s->length += strlen(dst);
}

/* Same as print_ipv6_addr, but optionally encloses the address in square
 * brackets. */
void
ipv6_format_addr_bracket(const struct in6_addr *addr, struct ds *s,
                         bool bracket)
{
    if (bracket) {
        ds_put_char(s, '[');
    }
    ipv6_format_addr(addr, s);
    if (bracket) {
        ds_put_char(s, ']');
    }
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

#ifdef s6_addr32
#define s6_addrX s6_addr32
#define IPV6_FOR_EACH(VAR) for (int VAR = 0; VAR < 4; VAR++)
#else
#define s6_addrX s6_addr
#define IPV6_FOR_EACH(VAR) for (int VAR = 0; VAR < 16; VAR++)
#endif

struct in6_addr
ipv6_addr_bitand(const struct in6_addr *a, const struct in6_addr *b)
{
   struct in6_addr dst;
   IPV6_FOR_EACH (i) {
       dst.s6_addrX[i] = a->s6_addrX[i] & b->s6_addrX[i];
   }
   return dst;
}

struct in6_addr
ipv6_addr_bitxor(const struct in6_addr *a, const struct in6_addr *b)
{
   struct in6_addr dst;
   IPV6_FOR_EACH (i) {
       dst.s6_addrX[i] = a->s6_addrX[i] ^ b->s6_addrX[i];
   }
   return dst;
}

bool
ipv6_is_zero(const struct in6_addr *a)
{
   IPV6_FOR_EACH (i) {
       if (a->s6_addrX[i]) {
           return false;
       }
   }
   return true;
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
    data = dp_packet_put_zeros(b, size);

    eth->eth_dst = eth_dst;
    eth->eth_src = eth_src;
    eth->eth_type = htons(eth_type);

    b->packet_type = htonl(PT_ETH);
    dp_packet_reset_offsets(b);
    dp_packet_set_l3(b, data);

    return data;
}

void
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
packet_rh_present(struct dp_packet *packet, uint8_t *nexthdr)
{
    const struct ovs_16aligned_ip6_hdr *nh;
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
    *nexthdr = nh->ip6_nxt;

    while (1) {
        if ((*nexthdr != IPPROTO_HOPOPTS)
                && (*nexthdr != IPPROTO_ROUTING)
                && (*nexthdr != IPPROTO_DSTOPTS)
                && (*nexthdr != IPPROTO_AH)
                && (*nexthdr != IPPROTO_FRAGMENT)) {
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

        if (*nexthdr == IPPROTO_AH) {
            /* A standard AH definition isn't available, but the fields
             * we care about are in the same location as the generic
             * option header--only the header length is calculated
             * differently. */
            const struct ip6_ext *ext_hdr = (struct ip6_ext *)data;

            *nexthdr = ext_hdr->ip6e_nxt;
            len = (ext_hdr->ip6e_len + 2) * 4;
        } else if (*nexthdr == IPPROTO_FRAGMENT) {
            const struct ovs_16aligned_ip6_frag *frag_hdr
                = ALIGNED_CAST(struct ovs_16aligned_ip6_frag *, data);

            *nexthdr = frag_hdr->ip6f_nxt;
            len = sizeof *frag_hdr;
        } else if (*nexthdr == IPPROTO_ROUTING) {
            const struct ip6_rthdr *rh = (struct ip6_rthdr *)data;

            if (rh->ip6r_segleft > 0) {
                return true;
            }

            *nexthdr = rh->ip6r_nxt;
            len = (rh->ip6r_len + 1) * 8;
        } else {
            const struct ip6_ext *ext_hdr = (struct ip6_ext *)data;

            *nexthdr = ext_hdr->ip6e_nxt;
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
                      ovs_16aligned_be32 addr[4],
                      const struct in6_addr *new_addr)
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

void
packet_set_ipv6_addr(struct dp_packet *packet, uint8_t proto,
                     ovs_16aligned_be32 addr[4],
                     const struct in6_addr *new_addr,
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
packet_set_ipv6(struct dp_packet *packet, const struct in6_addr *src,
                const struct in6_addr *dst, uint8_t key_tc, ovs_be32 key_fl,
                uint8_t key_hl)
{
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(packet);
    uint8_t proto = 0;
    bool rh_present;

    rh_present = packet_rh_present(packet, &proto);

    if (memcmp(&nh->ip6_src, src, sizeof(ovs_be32[4]))) {
        packet_set_ipv6_addr(packet, proto, nh->ip6_src.be32, src, true);
    }

    if (memcmp(&nh->ip6_dst, dst, sizeof(ovs_be32[4]))) {
        packet_set_ipv6_addr(packet, proto, nh->ip6_dst.be32, dst,
                             !rh_present);
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

/* Sets the IGMP type to IGMP_HOST_MEMBERSHIP_QUERY and populates the
 * v3 query header fields in 'packet'. 'packet' must be a valid IGMPv3
 * query packet with its l4 offset properly populated.
 */
void
packet_set_igmp3_query(struct dp_packet *packet, uint8_t max_resp,
                       ovs_be32 group, bool srs, uint8_t qrv, uint8_t qqic)
{
    struct igmpv3_query_header *igh = dp_packet_l4(packet);
    ovs_be16 orig_type_max_resp =
        htons(igh->type << 8 | igh->max_resp);
    ovs_be16 new_type_max_resp =
        htons(IGMP_HOST_MEMBERSHIP_QUERY << 8 | max_resp);

    if (orig_type_max_resp != new_type_max_resp) {
        igh->type = IGMP_HOST_MEMBERSHIP_QUERY;
        igh->max_resp = max_resp;
        igh->csum = recalc_csum16(igh->csum, orig_type_max_resp,
                                  new_type_max_resp);
    }

    ovs_be32 old_group = get_16aligned_be32(&igh->group);

    if (old_group != group) {
        put_16aligned_be32(&igh->group, group);
        igh->csum = recalc_csum32(igh->csum, old_group, group);
    }

    /* See RFC 3376 4.1.6. */
    if (qrv > 7) {
        qrv = 0;
    }

    ovs_be16 orig_srs_qrv_qqic = htons(igh->srs_qrv << 8 | igh->qqic);
    ovs_be16 new_srs_qrv_qqic = htons(srs << 11 | qrv << 8 | qqic);

    if (orig_srs_qrv_qqic != new_srs_qrv_qqic) {
        igh->srs_qrv = (srs << 3 | qrv);
        igh->qqic = qqic;
        igh->csum = recalc_csum16(igh->csum, orig_srs_qrv_qqic,
                                  new_srs_qrv_qqic);
    }
}

void
packet_set_nd_ext(struct dp_packet *packet, const ovs_16aligned_be32 rso_flags,
                  const uint8_t opt_type)
{
    struct ovs_nd_msg *ns;
    struct ovs_nd_lla_opt *opt;
    int bytes_remain = dp_packet_l4_size(packet);
    struct ovs_16aligned_ip6_hdr * nh = dp_packet_l3(packet);
    uint32_t pseudo_hdr_csum = 0;

    if (OVS_UNLIKELY(bytes_remain < sizeof(*ns))) {
        return;
    }

    if (nh) {
        pseudo_hdr_csum = packet_csum_pseudoheader6(nh);
    }

    ns = dp_packet_l4(packet);
    opt = &ns->options[0];

    /* set RSO flags and option type */
    ns->rso_flags = rso_flags;
    opt->type = opt_type;

    /* recalculate checksum */
    ovs_be16 *csum_value = &(ns->icmph.icmp6_cksum);
    *csum_value = 0;
    *csum_value = csum_finish(csum_continue(pseudo_hdr_csum,
                              &(ns->icmph), bytes_remain));

}

void
packet_set_nd(struct dp_packet *packet, const struct in6_addr *target,
              const struct eth_addr sll, const struct eth_addr tll)
{
    struct ovs_nd_msg *ns;
    struct ovs_nd_lla_opt *opt;
    int bytes_remain = dp_packet_l4_size(packet);

    if (OVS_UNLIKELY(bytes_remain < sizeof(*ns))) {
        return;
    }

    ns = dp_packet_l4(packet);
    opt = &ns->options[0];
    bytes_remain -= sizeof(*ns);

    if (memcmp(&ns->target, target, sizeof(ovs_be32[4]))) {
        packet_set_ipv6_addr(packet, IPPROTO_ICMPV6, ns->target.be32, target,
                             true);
    }

    while (bytes_remain >= ND_LLA_OPT_LEN && opt->len != 0) {
        if (opt->type == ND_OPT_SOURCE_LINKADDR && opt->len == 1) {
            if (!eth_addr_equals(opt->mac, sll)) {
                ovs_be16 *csum = &(ns->icmph.icmp6_cksum);

                *csum = recalc_csum48(*csum, opt->mac, sll);
                opt->mac = sll;
            }

            /* A packet can only contain one SLL or TLL option */
            break;
        } else if (opt->type == ND_OPT_TARGET_LINKADDR && opt->len == 1) {
            if (!eth_addr_equals(opt->mac, tll)) {
                ovs_be16 *csum = &(ns->icmph.icmp6_cksum);

                *csum = recalc_csum48(*csum, opt->mac, tll);
                opt->mac = tll;
            }

            /* A packet can only contain one SLL or TLL option */
            break;
        }

        opt += opt->len;
        bytes_remain -= opt->len * ND_LLA_OPT_LEN;
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
 * 'broadcast' is true.  Points the L3 header to the ARP header. */
void
compose_arp(struct dp_packet *b, uint16_t arp_op,
            const struct eth_addr arp_sha, const struct eth_addr arp_tha,
            bool broadcast, ovs_be32 arp_spa, ovs_be32 arp_tpa)
{
    compose_arp__(b);

    struct eth_header *eth = dp_packet_eth(b);
    eth->eth_dst = broadcast ? eth_addr_broadcast : arp_tha;
    eth->eth_src = arp_sha;

    struct arp_eth_header *arp = dp_packet_l3(b);
    arp->ar_op = htons(arp_op);
    arp->ar_sha = arp_sha;
    arp->ar_tha = arp_tha;
    put_16aligned_be32(&arp->ar_spa, arp_spa);
    put_16aligned_be32(&arp->ar_tpa, arp_tpa);
}

/* Clears 'b' and replaces its contents by an ARP frame.  Sets the fields in
 * the Ethernet and ARP headers that are fixed for ARP frames to those fixed
 * values, and zeroes the other fields.  Points the L3 header to the ARP
 * header. */
void
compose_arp__(struct dp_packet *b)
{
    dp_packet_clear(b);
    dp_packet_prealloc_tailroom(b, ARP_PACKET_SIZE);
    dp_packet_reserve(b, 2 + VLAN_HEADER_LEN);

    struct eth_header *eth = dp_packet_put_zeros(b, sizeof *eth);
    eth->eth_type = htons(ETH_TYPE_ARP);

    struct arp_eth_header *arp = dp_packet_put_zeros(b, sizeof *arp);
    arp->ar_hrd = htons(ARP_HRD_ETHERNET);
    arp->ar_pro = htons(ARP_PRO_IP);
    arp->ar_hln = sizeof arp->ar_sha;
    arp->ar_pln = sizeof arp->ar_spa;

    dp_packet_reset_offsets(b);
    dp_packet_set_l3(b, arp);

    b->packet_type = htonl(PT_ETH);
}

/* This function expects packet with ethernet header with correct
 * l3 pointer set. */
static void *
compose_ipv6(struct dp_packet *packet, uint8_t proto,
             const struct in6_addr *src, const struct in6_addr *dst,
             uint8_t key_tc, ovs_be32 key_fl, uint8_t key_hl, int size)
{
    struct ip6_hdr *nh;
    void *data;

    nh = dp_packet_l3(packet);
    nh->ip6_vfc = 0x60;
    nh->ip6_nxt = proto;
    nh->ip6_plen = htons(size);
    data = dp_packet_put_zeros(packet, size);
    dp_packet_set_l4(packet, data);
    packet_set_ipv6(packet, src, dst, key_tc, key_fl, key_hl);
    return data;
}

/* Compose an IPv6 Neighbor Discovery Neighbor Solicitation message. */
void
compose_nd_ns(struct dp_packet *b, const struct eth_addr eth_src,
              const struct in6_addr *ipv6_src, const struct in6_addr *ipv6_dst)
{
    struct in6_addr sn_addr;
    struct eth_addr eth_dst;
    struct ovs_nd_msg *ns;
    struct ovs_nd_lla_opt *lla_opt;
    uint32_t icmp_csum;

    in6_addr_solicited_node(&sn_addr, ipv6_dst);
    ipv6_multicast_to_ethernet(&eth_dst, &sn_addr);

    eth_compose(b, eth_dst, eth_src, ETH_TYPE_IPV6, IPV6_HEADER_LEN);
    ns = compose_ipv6(b, IPPROTO_ICMPV6, ipv6_src, &sn_addr,
                      0, 0, 255, ND_MSG_LEN + ND_LLA_OPT_LEN);

    ns->icmph.icmp6_type = ND_NEIGHBOR_SOLICIT;
    ns->icmph.icmp6_code = 0;
    put_16aligned_be32(&ns->rso_flags, htonl(0));

    lla_opt = &ns->options[0];
    lla_opt->type = ND_OPT_SOURCE_LINKADDR;
    lla_opt->len = 1;

    packet_set_nd(b, ipv6_dst, eth_src, eth_addr_zero);

    ns->icmph.icmp6_cksum = 0;
    icmp_csum = packet_csum_pseudoheader6(dp_packet_l3(b));
    ns->icmph.icmp6_cksum = csum_finish(
        csum_continue(icmp_csum, ns, ND_MSG_LEN + ND_LLA_OPT_LEN));
}

/* Compose an IPv6 Neighbor Discovery Neighbor Advertisement message. */
void
compose_nd_na(struct dp_packet *b,
              const struct eth_addr eth_src, const struct eth_addr eth_dst,
              const struct in6_addr *ipv6_src, const struct in6_addr *ipv6_dst,
              ovs_be32 rso_flags)
{
    struct ovs_nd_msg *na;
    struct ovs_nd_lla_opt *lla_opt;
    uint32_t icmp_csum;

    eth_compose(b, eth_dst, eth_src, ETH_TYPE_IPV6, IPV6_HEADER_LEN);
    na = compose_ipv6(b, IPPROTO_ICMPV6, ipv6_src, ipv6_dst,
                      0, 0, 255, ND_MSG_LEN + ND_LLA_OPT_LEN);

    na->icmph.icmp6_type = ND_NEIGHBOR_ADVERT;
    na->icmph.icmp6_code = 0;
    put_16aligned_be32(&na->rso_flags, rso_flags);

    lla_opt = &na->options[0];
    lla_opt->type = ND_OPT_TARGET_LINKADDR;
    lla_opt->len = 1;

    packet_set_nd(b, ipv6_src, eth_addr_zero, eth_src);

    na->icmph.icmp6_cksum = 0;
    icmp_csum = packet_csum_pseudoheader6(dp_packet_l3(b));
    na->icmph.icmp6_cksum = csum_finish(csum_continue(
        icmp_csum, na, ND_MSG_LEN + ND_LLA_OPT_LEN));
}

/* Compose an IPv6 Neighbor Discovery Router Advertisement message with
 * Source Link-layer Address Option and MTU Option.
 * Caller can call packet_put_ra_prefix_opt to append Prefix Information
 * Options to composed messags in 'b'. */
void
compose_nd_ra(struct dp_packet *b,
              const struct eth_addr eth_src, const struct eth_addr eth_dst,
              const struct in6_addr *ipv6_src, const struct in6_addr *ipv6_dst,
              uint8_t cur_hop_limit, uint8_t mo_flags,
              ovs_be16 router_lt, ovs_be32 reachable_time,
              ovs_be32 retrans_timer, uint32_t mtu)
{
    /* Don't compose Router Advertisement packet with MTU Option if mtu
     * value is 0. */
    bool with_mtu = mtu != 0;
    size_t mtu_opt_len = with_mtu ? ND_MTU_OPT_LEN : 0;

    eth_compose(b, eth_dst, eth_src, ETH_TYPE_IPV6, IPV6_HEADER_LEN);

    struct ovs_ra_msg *ra = compose_ipv6(
        b, IPPROTO_ICMPV6, ipv6_src, ipv6_dst, 0, 0, 255,
        RA_MSG_LEN + ND_LLA_OPT_LEN + mtu_opt_len);
    ra->icmph.icmp6_type = ND_ROUTER_ADVERT;
    ra->icmph.icmp6_code = 0;
    ra->cur_hop_limit = cur_hop_limit;
    ra->mo_flags = mo_flags;
    ra->router_lifetime = router_lt;
    ra->reachable_time = reachable_time;
    ra->retrans_timer = retrans_timer;

    struct ovs_nd_lla_opt *lla_opt = ra->options;
    lla_opt->type = ND_OPT_SOURCE_LINKADDR;
    lla_opt->len = 1;
    lla_opt->mac = eth_src;

    if (with_mtu) {
        /* ovs_nd_mtu_opt has the same size with ovs_nd_lla_opt. */
        struct ovs_nd_mtu_opt *mtu_opt
            = (struct ovs_nd_mtu_opt *)(lla_opt + 1);
        mtu_opt->type = ND_OPT_MTU;
        mtu_opt->len = 1;
        mtu_opt->reserved = 0;
        put_16aligned_be32(&mtu_opt->mtu, htonl(mtu));
    }

    ra->icmph.icmp6_cksum = 0;
    uint32_t icmp_csum = packet_csum_pseudoheader6(dp_packet_l3(b));
    ra->icmph.icmp6_cksum = csum_finish(csum_continue(
        icmp_csum, ra, RA_MSG_LEN + ND_LLA_OPT_LEN + mtu_opt_len));
}

/* Append an IPv6 Neighbor Discovery Prefix Information option to a
 * Router Advertisement message. */
void
packet_put_ra_prefix_opt(struct dp_packet *b,
                         uint8_t plen, uint8_t la_flags,
                         ovs_be32 valid_lifetime, ovs_be32 preferred_lifetime,
                         const ovs_be128 prefix)
{
    size_t prev_l4_size = dp_packet_l4_size(b);
    struct ip6_hdr *nh = dp_packet_l3(b);
    nh->ip6_plen = htons(prev_l4_size + ND_PREFIX_OPT_LEN);

    struct ovs_nd_prefix_opt *prefix_opt =
        dp_packet_put_uninit(b, sizeof *prefix_opt);
    prefix_opt->type = ND_OPT_PREFIX_INFORMATION;
    prefix_opt->len = 4;
    prefix_opt->prefix_len = plen;
    prefix_opt->la_flags = la_flags;
    put_16aligned_be32(&prefix_opt->valid_lifetime, valid_lifetime);
    put_16aligned_be32(&prefix_opt->preferred_lifetime, preferred_lifetime);
    put_16aligned_be32(&prefix_opt->reserved, 0);
    memcpy(prefix_opt->prefix.be32, prefix.be32, sizeof(ovs_be32[4]));

    struct ovs_ra_msg *ra = dp_packet_l4(b);
    ra->icmph.icmp6_cksum = 0;
    uint32_t icmp_csum = packet_csum_pseudoheader6(dp_packet_l3(b));
    ra->icmph.icmp6_cksum = csum_finish(csum_continue(
        icmp_csum, ra, prev_l4_size + ND_PREFIX_OPT_LEN));
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

    partial = csum_continue(partial, &ip6->ip6_src, sizeof ip6->ip6_src);
    partial = csum_continue(partial, &ip6->ip6_dst, sizeof ip6->ip6_dst);
    partial = csum_add16(partial, htons(ip6->ip6_nxt));
    partial = csum_add16(partial, ip6->ip6_plen);

    return partial;
}

/* Calculate the IPv6 upper layer checksum according to RFC2460. We pass the
   ip6_nxt and ip6_plen values, so it will also work if extension headers
   are present. */
ovs_be16
packet_csum_upperlayer6(const struct ovs_16aligned_ip6_hdr *ip6,
                        const void *data, uint8_t l4_protocol,
                        uint16_t l4_size)
{
    uint32_t partial = 0;

    partial = csum_continue(partial, &ip6->ip6_src, sizeof ip6->ip6_src);
    partial = csum_continue(partial, &ip6->ip6_dst, sizeof ip6->ip6_dst);
    partial = csum_add16(partial, htons(l4_protocol));
    partial = csum_add16(partial, htons(l4_size));

    partial = csum_continue(partial, data, l4_size);

    return csum_finish(partial);
}
#endif

void
IP_ECN_set_ce(struct dp_packet *pkt, bool is_ipv6)
{
    if (is_ipv6) {
        ovs_16aligned_be32 *ip6 = dp_packet_l3(pkt);

        put_16aligned_be32(ip6, get_16aligned_be32(ip6) |
                                htonl(IP_ECN_CE << 20));
    } else {
        struct ip_header *nh = dp_packet_l3(pkt);
        uint8_t tos = nh->ip_tos;

        tos |= IP_ECN_CE;
        if (nh->ip_tos != tos) {
            nh->ip_csum = recalc_csum16(nh->ip_csum, htons(nh->ip_tos),
                                        htons((uint16_t) tos));
            nh->ip_tos = tos;
        }
    }
}
