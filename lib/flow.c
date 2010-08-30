/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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
#include <sys/types.h>
#include "flow.h"
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include "coverage.h"
#include "dynamic-string.h"
#include "hash.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
#include "packets.h"
#include "unaligned.h"
#include "vlog.h"
#include "xtoxll.h"

VLOG_DEFINE_THIS_MODULE(flow)

static struct arp_eth_header *
pull_arp(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, ARP_ETH_HEADER_LEN);
}

static struct ip_header *
pull_ip(struct ofpbuf *packet)
{
    if (packet->size >= IP_HEADER_LEN) {
        struct ip_header *ip = packet->data;
        int ip_len = IP_IHL(ip->ip_ihl_ver) * 4;
        if (ip_len >= IP_HEADER_LEN && packet->size >= ip_len) {
            return ofpbuf_pull(packet, ip_len);
        }
    }
    return NULL;
}

static struct tcp_header *
pull_tcp(struct ofpbuf *packet)
{
    if (packet->size >= TCP_HEADER_LEN) {
        struct tcp_header *tcp = packet->data;
        int tcp_len = TCP_OFFSET(tcp->tcp_ctl) * 4;
        if (tcp_len >= TCP_HEADER_LEN && packet->size >= tcp_len) {
            return ofpbuf_pull(packet, tcp_len);
        }
    }
    return NULL;
}

static struct udp_header *
pull_udp(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, UDP_HEADER_LEN);
}

static struct icmp_header *
pull_icmp(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, ICMP_HEADER_LEN);
}

static void
parse_vlan(struct ofpbuf *b, flow_t *flow)
{
    struct qtag_prefix {
        uint16_t eth_type;      /* ETH_TYPE_VLAN */
        uint16_t tci;
    };

    if (b->size >= sizeof(struct qtag_prefix) + sizeof(uint16_t)) {
        struct qtag_prefix *qp = ofpbuf_pull(b, sizeof *qp);
        flow->dl_vlan = qp->tci & htons(VLAN_VID_MASK);
        flow->dl_vlan_pcp = (ntohs(qp->tci) & VLAN_PCP_MASK) >> VLAN_PCP_SHIFT;
    }
}

static uint16_t
parse_ethertype(struct ofpbuf *b)
{
    struct llc_snap_header *llc;
    uint16_t proto;

    proto = *(uint16_t *) ofpbuf_pull(b, sizeof proto);
    if (ntohs(proto) >= ODP_DL_TYPE_ETH2_CUTOFF) {
        return proto;
    }

    if (b->size < sizeof *llc) {
        return htons(ODP_DL_TYPE_NOT_ETH_TYPE);
    }

    llc = b->data;
    if (llc->llc.llc_dsap != LLC_DSAP_SNAP
        || llc->llc.llc_ssap != LLC_SSAP_SNAP
        || llc->llc.llc_cntl != LLC_CNTL_SNAP
        || memcmp(llc->snap.snap_org, SNAP_ORG_ETHERNET,
                  sizeof llc->snap.snap_org)) {
        return htons(ODP_DL_TYPE_NOT_ETH_TYPE);
    }

    ofpbuf_pull(b, sizeof *llc);
    return llc->snap.snap_type;
}

/* 'tun_id' is in network byte order, while 'in_port' is in host byte order.
 * These byte orders are the same as they are in struct odp_flow_key.
 *
 * Initializes packet header pointers as follows:
 *
 *    - packet->l2 to the start of the Ethernet header.
 *
 *    - packet->l3 to just past the Ethernet header, or just past the
 *      vlan_header if one is present, to the first byte of the payload of the
 *      Ethernet frame.
 *
 *    - packet->l4 to just past the IPv4 header, if one is present and has a
 *      correct length, and otherwise NULL.
 *
 *    - packet->l7 to just past the TCP or UDP or ICMP header, if one is
 *      present and has a correct length, and otherwise NULL.
 */
int
flow_extract(struct ofpbuf *packet, uint32_t tun_id, uint16_t in_port,
             flow_t *flow)
{
    struct ofpbuf b = *packet;
    struct eth_header *eth;
    int retval = 0;

    COVERAGE_INC(flow_extract);

    memset(flow, 0, sizeof *flow);
    flow->tun_id = tun_id;
    flow->in_port = in_port;
    flow->dl_vlan = htons(OFP_VLAN_NONE);

    packet->l2 = b.data;
    packet->l3 = NULL;
    packet->l4 = NULL;
    packet->l7 = NULL;

    if (b.size < sizeof *eth) {
        return 0;
    }

    /* Link layer. */
    eth = b.data;
    memcpy(flow->dl_src, eth->eth_src, ETH_ADDR_LEN);
    memcpy(flow->dl_dst, eth->eth_dst, ETH_ADDR_LEN);

    /* dl_type, dl_vlan, dl_vlan_pcp. */
    ofpbuf_pull(&b, ETH_ADDR_LEN * 2);
    if (eth->eth_type == htons(ETH_TYPE_VLAN)) {
        parse_vlan(&b, flow);
    }
    flow->dl_type = parse_ethertype(&b);

    /* Network layer. */
    packet->l3 = b.data;
    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        const struct ip_header *nh = pull_ip(&b);
        if (nh) {
            flow->nw_src = get_unaligned_u32(&nh->ip_src);
            flow->nw_dst = get_unaligned_u32(&nh->ip_dst);
            flow->nw_tos = nh->ip_tos & IP_DSCP_MASK;
            flow->nw_proto = nh->ip_proto;
            packet->l4 = b.data;
            if (!IP_IS_FRAGMENT(nh->ip_frag_off)) {
                if (flow->nw_proto == IP_TYPE_TCP) {
                    const struct tcp_header *tcp = pull_tcp(&b);
                    if (tcp) {
                        flow->tp_src = tcp->tcp_src;
                        flow->tp_dst = tcp->tcp_dst;
                        packet->l7 = b.data;
                    }
                } else if (flow->nw_proto == IP_TYPE_UDP) {
                    const struct udp_header *udp = pull_udp(&b);
                    if (udp) {
                        flow->tp_src = udp->udp_src;
                        flow->tp_dst = udp->udp_dst;
                        packet->l7 = b.data;
                    }
                } else if (flow->nw_proto == IP_TYPE_ICMP) {
                    const struct icmp_header *icmp = pull_icmp(&b);
                    if (icmp) {
                        flow->icmp_type = htons(icmp->icmp_type);
                        flow->icmp_code = htons(icmp->icmp_code);
                        packet->l7 = b.data;
                    }
                }
            } else {
                retval = 1;
            }
        }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
        const struct arp_eth_header *arp = pull_arp(&b);
        if (arp && arp->ar_hrd == htons(1)
            && arp->ar_pro == htons(ETH_TYPE_IP)
            && arp->ar_hln == ETH_ADDR_LEN
            && arp->ar_pln == 4) {
            /* We only match on the lower 8 bits of the opcode. */
            if (ntohs(arp->ar_op) <= 0xff) {
                flow->nw_proto = ntohs(arp->ar_op);
            }

            if ((flow->nw_proto == ARP_OP_REQUEST)
                || (flow->nw_proto == ARP_OP_REPLY)) {
                flow->nw_src = arp->ar_spa;
                flow->nw_dst = arp->ar_tpa;
            }
        }
    }
    return retval;
}

/* Extracts the flow stats for a packet.  The 'flow' and 'packet'
 * arguments must have been initialized through a call to flow_extract().
 */
void
flow_extract_stats(const flow_t *flow, struct ofpbuf *packet,
        struct odp_flow_stats *stats)
{
    memset(stats, '\0', sizeof(*stats));

    if ((flow->dl_type == htons(ETH_TYPE_IP)) && packet->l4) {
        if ((flow->nw_proto == IP_TYPE_TCP) && packet->l7) {
            struct tcp_header *tcp = packet->l4;
            stats->tcp_flags = TCP_FLAGS(tcp->tcp_ctl);
        }
    }

    stats->n_bytes = packet->size;
    stats->n_packets = 1;
}

/* Extract 'flow' with 'wildcards' into the OpenFlow match structure
 * 'match'. */
void
flow_to_match(const flow_t *flow, uint32_t wildcards, bool tun_id_from_cookie,
              struct ofp_match *match)
{
    if (!tun_id_from_cookie) {
        wildcards &= OFPFW_ALL;
    }
    match->wildcards = htonl(wildcards);

    match->in_port = htons(flow->in_port == ODPP_LOCAL ? OFPP_LOCAL
                           : flow->in_port);
    match->dl_vlan = flow->dl_vlan;
    match->dl_vlan_pcp = flow->dl_vlan_pcp;
    memcpy(match->dl_src, flow->dl_src, ETH_ADDR_LEN);
    memcpy(match->dl_dst, flow->dl_dst, ETH_ADDR_LEN);
    match->dl_type = flow->dl_type;
    match->nw_src = flow->nw_src;
    match->nw_dst = flow->nw_dst;
    match->nw_tos = flow->nw_tos;
    match->nw_proto = flow->nw_proto;
    match->tp_src = flow->tp_src;
    match->tp_dst = flow->tp_dst;
    memset(match->pad1, '\0', sizeof match->pad1);
    memset(match->pad2, '\0', sizeof match->pad2);
}

void
flow_from_match(const struct ofp_match *match, bool tun_id_from_cookie,
                uint64_t cookie, flow_t *flow, uint32_t *flow_wildcards)
{
	uint32_t wildcards = ntohl(match->wildcards);

    flow->nw_src = match->nw_src;
    flow->nw_dst = match->nw_dst;
    if (tun_id_from_cookie && !(wildcards & NXFW_TUN_ID)) {
        flow->tun_id = htonl(ntohll(cookie) >> 32);
    } else {
        wildcards |= NXFW_TUN_ID;
        flow->tun_id = 0;
    }
    flow->in_port = (match->in_port == htons(OFPP_LOCAL) ? ODPP_LOCAL
                     : ntohs(match->in_port));
    flow->dl_vlan = match->dl_vlan;
    flow->dl_vlan_pcp = match->dl_vlan_pcp;
    flow->dl_type = match->dl_type;
    flow->tp_src = match->tp_src;
    flow->tp_dst = match->tp_dst;
    memcpy(flow->dl_src, match->dl_src, ETH_ADDR_LEN);
    memcpy(flow->dl_dst, match->dl_dst, ETH_ADDR_LEN);
    flow->nw_tos = match->nw_tos;
    flow->nw_proto = match->nw_proto;
    memset(flow->reserved, 0, sizeof flow->reserved);

    if (flow_wildcards) {
        *flow_wildcards = wildcards;
    }
}

char *
flow_to_string(const flow_t *flow)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    flow_format(&ds, flow);
    return ds_cstr(&ds);
}

void
flow_format(struct ds *ds, const flow_t *flow)
{
    ds_put_format(ds, "tunnel%08"PRIx32":in_port%04"PRIx16
                      ":vlan%"PRIu16":pcp%"PRIu8
                      " mac"ETH_ADDR_FMT"->"ETH_ADDR_FMT
                      " type%04"PRIx16
                      " proto%"PRIu8
                      " tos%"PRIu8
                      " ip"IP_FMT"->"IP_FMT
                      " port%"PRIu16"->%"PRIu16,
                  ntohl(flow->tun_id),
                  flow->in_port,
                  ntohs(flow->dl_vlan),
                  flow->dl_vlan_pcp,
                  ETH_ADDR_ARGS(flow->dl_src),
                  ETH_ADDR_ARGS(flow->dl_dst),
                  ntohs(flow->dl_type),
                  flow->nw_proto,
                  flow->nw_tos,
                  IP_ARGS(&flow->nw_src),
                  IP_ARGS(&flow->nw_dst),
                  ntohs(flow->tp_src),
                  ntohs(flow->tp_dst));
}

void
flow_print(FILE *stream, const flow_t *flow)
{
    char *s = flow_to_string(flow);
    fputs(s, stream);
    free(s);
}
