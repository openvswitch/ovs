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

#include "vlog.h"
#define THIS_MODULE VLM_flow

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

static struct eth_header *
pull_eth(struct ofpbuf *packet) 
{
    return ofpbuf_try_pull(packet, ETH_HEADER_LEN);
}

static struct vlan_header *
pull_vlan(struct ofpbuf *packet)
{
    return ofpbuf_try_pull(packet, VLAN_HEADER_LEN);
}

/* Returns 1 if 'packet' is an IP fragment, 0 otherwise. */
int
flow_extract(struct ofpbuf *packet, uint16_t in_port, flow_t *flow)
{
    struct ofpbuf b = *packet;
    struct eth_header *eth;
    int retval = 0;

    COVERAGE_INC(flow_extract);

    memset(flow, 0, sizeof *flow);
    flow->dl_vlan = htons(OFP_VLAN_NONE);
    flow->in_port = in_port;

    packet->l2 = b.data;
    packet->l3 = NULL;
    packet->l4 = NULL;
    packet->l7 = NULL;

    eth = pull_eth(&b);
    if (eth) {
        if (ntohs(eth->eth_type) >= OFP_DL_TYPE_ETH2_CUTOFF) {
            /* This is an Ethernet II frame */
            flow->dl_type = eth->eth_type;
        } else {
            /* This is an 802.2 frame */
            struct llc_header *llc = ofpbuf_at(&b, 0, sizeof *llc);
            struct snap_header *snap = ofpbuf_at(&b, sizeof *llc,
                                                 sizeof *snap);
            if (llc == NULL) {
                return 0;
            }
            if (snap
                && llc->llc_dsap == LLC_DSAP_SNAP
                && llc->llc_ssap == LLC_SSAP_SNAP
                && llc->llc_cntl == LLC_CNTL_SNAP
                && !memcmp(snap->snap_org, SNAP_ORG_ETHERNET,
                           sizeof snap->snap_org)) {
                flow->dl_type = snap->snap_type;
                ofpbuf_pull(&b, LLC_SNAP_HEADER_LEN);
            } else {
                flow->dl_type = htons(OFP_DL_TYPE_NOT_ETH_TYPE);
                ofpbuf_pull(&b, sizeof(struct llc_header));
            }
        }

        /* Check for a VLAN tag */
        if (flow->dl_type == htons(ETH_TYPE_VLAN)) {
            struct vlan_header *vh = pull_vlan(&b);
            if (vh) {
                flow->dl_type = vh->vlan_next_type;
                flow->dl_vlan = vh->vlan_tci & htons(VLAN_VID_MASK);
                flow->dl_vlan_pcp = (ntohs(vh->vlan_tci) & 0xe000) >> 13;
            }
        }
        memcpy(flow->dl_src, eth->eth_src, ETH_ADDR_LEN);
        memcpy(flow->dl_dst, eth->eth_dst, ETH_ADDR_LEN);

        packet->l3 = b.data;
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            const struct ip_header *nh = pull_ip(&b);
            if (nh) {
                flow->nw_src = nh->ip_src;
                flow->nw_dst = nh->ip_dst;
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
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
                        }
                    } else if (flow->nw_proto == IP_TYPE_UDP) {
                        const struct udp_header *udp = pull_udp(&b);
                        if (udp) {
                            flow->tp_src = udp->udp_src;
                            flow->tp_dst = udp->udp_dst;
                            packet->l7 = b.data;
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
                        }
                    } else if (flow->nw_proto == IP_TYPE_ICMP) {
                        const struct icmp_header *icmp = pull_icmp(&b);
                        if (icmp) {
                            flow->icmp_type = htons(icmp->icmp_type);
                            flow->icmp_code = htons(icmp->icmp_code);
                            packet->l7 = b.data;
                        } else {
                            /* Avoid tricking other code into thinking that
                             * this packet has an L4 header. */
                            flow->nw_proto = 0;
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
        struct ip_header *ip = packet->l3;
        stats->ip_tos = ip->ip_tos;
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
flow_to_match(const flow_t *flow, uint32_t wildcards, struct ofp_match *match)
{
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
flow_from_match(flow_t *flow, uint32_t *wildcards,
                const struct ofp_match *match)
{
    if (wildcards) {
        *wildcards = ntohl(match->wildcards);
    }
    flow->nw_src = match->nw_src;
    flow->nw_dst = match->nw_dst;
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
    ds_put_format(ds, "in_port%04x:vlan%d:pcp%d mac"ETH_ADDR_FMT
                  "->"ETH_ADDR_FMT" type%04x proto%"PRId8" tos%"PRIu8
                  " ip"IP_FMT"->"IP_FMT" port%d->%d",
                  flow->in_port, ntohs(flow->dl_vlan), flow->dl_vlan_pcp,
                  ETH_ADDR_ARGS(flow->dl_src), ETH_ADDR_ARGS(flow->dl_dst),
                  ntohs(flow->dl_type), flow->nw_proto, flow->nw_tos,
                  IP_ARGS(&flow->nw_src), IP_ARGS(&flow->nw_dst),
                  ntohs(flow->tp_src), ntohs(flow->tp_dst));
}

void
flow_print(FILE *stream, const flow_t *flow) 
{
    char *s = flow_to_string(flow);
    fputs(s, stream);
    free(s);
}
