/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "byte-order.h"
#include "dynamic-string.h"
#include "ofpbuf.h"

const struct in6_addr in6addr_exact = IN6ADDR_EXACT_INIT;

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

bool
eth_addr_from_string(const char *s, uint8_t ea[ETH_ADDR_LEN])
{
    if (sscanf(s, ETH_ADDR_SCAN_FMT, ETH_ADDR_SCAN_ARGS(ea))
        == ETH_ADDR_SCAN_COUNT) {
        return true;
    } else {
        memset(ea, 0, ETH_ADDR_LEN);
        return false;
    }
}

/* Fills 'b' with an 802.2 SNAP packet with Ethernet source address 'eth_src',
 * the Nicira OUI as SNAP organization and 'snap_type' as SNAP type.  The text
 * string in 'tag' is enclosed as the packet payload.
 *
 * This function is used by Open vSwitch to compose packets in cases where
 * context is important but content doesn't (or shouldn't) matter.  For this
 * purpose, 'snap_type' should be a random number and 'tag' should be an
 * English phrase that explains the purpose of the packet.  (The English phrase
 * gives hapless admins running Wireshark the opportunity to figure out what's
 * going on.) */
void
compose_benign_packet(struct ofpbuf *b, const char *tag, uint16_t snap_type,
                      const uint8_t eth_src[ETH_ADDR_LEN])
{
    size_t tag_size = strlen(tag) + 1;
    char *payload;

    payload = snap_compose(b, eth_addr_broadcast, eth_src, 0x002320, snap_type,
                           tag_size + ETH_ADDR_LEN);
    memcpy(payload, tag, tag_size);
    memcpy(payload + tag_size, eth_src, ETH_ADDR_LEN);
}

/* Modify the TCI field of 'packet', whose data must begin with an Ethernet
 * header.  If a VLAN tag is present, its TCI field is replaced by 'tci'.  If a
 * VLAN tag is not present, one is added with the TCI field set to 'tci'.
 *
 * Also sets 'packet->l2' to point to the new Ethernet header. */
void
eth_set_vlan_tci(struct ofpbuf *packet, ovs_be16 tci)
{
    struct eth_header *eh = packet->data;
    struct vlan_eth_header *veh;

    if (packet->size >= sizeof(struct vlan_eth_header)
        && eh->eth_type == htons(ETH_TYPE_VLAN)) {
        veh = packet->data;
        veh->veth_tci = tci;
    } else {
        /* Insert new 802.1Q header. */
        struct vlan_eth_header tmp;
        memcpy(tmp.veth_dst, eh->eth_dst, ETH_ADDR_LEN);
        memcpy(tmp.veth_src, eh->eth_src, ETH_ADDR_LEN);
        tmp.veth_type = htons(ETH_TYPE_VLAN);
        tmp.veth_tci = tci;
        tmp.veth_next_type = eh->eth_type;

        veh = ofpbuf_push_uninit(packet, VLAN_HEADER_LEN);
        memcpy(veh, &tmp, sizeof tmp);
    }
    packet->l2 = packet->data;
}

/* Stores the string representation of the IPv6 address 'addr' into the
 * character array 'addr_str', which must be at least INET6_ADDRSTRLEN
 * bytes long. */
void
format_ipv6_addr(char *addr_str, const struct in6_addr *addr)
{
    inet_ntop(AF_INET6, addr, addr_str, INET6_ADDRSTRLEN);
}

void
print_ipv6_addr(struct ds *string, const struct in6_addr *addr)
{
    char addr_str[INET6_ADDRSTRLEN];

    format_ipv6_addr(addr_str, addr);
    ds_put_format(string, "%s", addr_str);
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

/* Given the IPv6 netmask 'netmask', returns the number of bits of the
 * IPv6 address that it wildcards.  'netmask' must be a CIDR netmask (see
 * ipv6_is_cidr()). */
int
ipv6_count_cidr_bits(const struct in6_addr *netmask)
{
    int i;
    int count = 0;
    const uint8_t *netmaskp = &netmask->s6_addr[0];

    assert(ipv6_is_cidr(netmask));

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
 * information by the caller.
 *
 * The returned packet has enough headroom to insert an 802.1Q VLAN header if
 * desired. */
void *
eth_compose(struct ofpbuf *b, const uint8_t eth_dst[ETH_ADDR_LEN],
            const uint8_t eth_src[ETH_ADDR_LEN], uint16_t eth_type,
            size_t size)
{
    void *data;
    struct eth_header *eth;

    ofpbuf_clear(b);

    ofpbuf_prealloc_tailroom(b, ETH_HEADER_LEN + VLAN_HEADER_LEN + size);
    ofpbuf_reserve(b, VLAN_HEADER_LEN);
    eth = ofpbuf_put_uninit(b, ETH_HEADER_LEN);
    data = ofpbuf_put_uninit(b, size);

    memcpy(eth->eth_dst, eth_dst, ETH_ADDR_LEN);
    memcpy(eth->eth_src, eth_src, ETH_ADDR_LEN);
    eth->eth_type = htons(eth_type);

    return data;
}

/* Populates 'b' with an Ethernet LLC+SNAP packet headed with the given
 * 'eth_dst', 'eth_src', 'snap_org', and 'snap_type'.  A payload of 'size'
 * bytes is allocated in 'b' and returned.  This payload may be populated with
 * appropriate information by the caller.
 *
 * The returned packet has enough headroom to insert an 802.1Q VLAN header if
 * desired. */
void *
snap_compose(struct ofpbuf *b, const uint8_t eth_dst[ETH_ADDR_LEN],
             const uint8_t eth_src[ETH_ADDR_LEN],
             unsigned int oui, uint16_t snap_type, size_t size)
{
    struct eth_header *eth;
    struct llc_snap_header *llc_snap;
    void *payload;

    /* Compose basic packet structure.  (We need the payload size to stick into
     * the 802.2 header.) */
    ofpbuf_clear(b);
    ofpbuf_prealloc_tailroom(b, ETH_HEADER_LEN + VLAN_HEADER_LEN
                             + LLC_SNAP_HEADER_LEN + size);
    ofpbuf_reserve(b, VLAN_HEADER_LEN);
    eth = ofpbuf_put_zeros(b, ETH_HEADER_LEN);
    llc_snap = ofpbuf_put_zeros(b, LLC_SNAP_HEADER_LEN);
    payload = ofpbuf_put_uninit(b, size);

    /* Compose 802.2 header. */
    memcpy(eth->eth_dst, eth_dst, ETH_ADDR_LEN);
    memcpy(eth->eth_src, eth_src, ETH_ADDR_LEN);
    eth->eth_type = htons(b->size - ETH_HEADER_LEN);

    /* Compose LLC, SNAP headers. */
    llc_snap->llc.llc_dsap = LLC_DSAP_SNAP;
    llc_snap->llc.llc_ssap = LLC_SSAP_SNAP;
    llc_snap->llc.llc_cntl = LLC_CNTL_SNAP;
    llc_snap->snap.snap_org[0] = oui >> 16;
    llc_snap->snap.snap_org[1] = oui >> 8;
    llc_snap->snap.snap_org[2] = oui;
    llc_snap->snap.snap_type = htons(snap_type);

    return payload;
}
