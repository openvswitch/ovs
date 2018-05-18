/*
 * Copyright (c) 2016 Nicira, Inc.
 * Copyright (c) 2016 Red Hat, Inc.
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

#include "netdev-native-tnl.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/ioctl.h>

#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

#include "byte-order.h"
#include "csum.h"
#include "dp-packet.h"
#include "netdev.h"
#include "netdev-vport.h"
#include "netdev-vport-private.h"
#include "odp-netlink.h"
#include "packets.h"
#include "seq.h"
#include "unaligned.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(native_tnl);
static struct vlog_rate_limit err_rl = VLOG_RATE_LIMIT_INIT(60, 5);

#define VXLAN_HLEN   (sizeof(struct udp_header) +         \
                      sizeof(struct vxlanhdr))

#define GENEVE_BASE_HLEN   (sizeof(struct udp_header) +         \
                            sizeof(struct genevehdr))

uint16_t tnl_udp_port_min = 32768;
uint16_t tnl_udp_port_max = 61000;

void *
netdev_tnl_ip_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl,
                  unsigned int *hlen)
{
    void *nh;
    struct ip_header *ip;
    struct ovs_16aligned_ip6_hdr *ip6;
    void *l4;
    int l3_size;

    nh = dp_packet_l3(packet);
    ip = nh;
    ip6 = nh;
    l4 = dp_packet_l4(packet);

    if (!nh || !l4) {
        return NULL;
    }

    *hlen = sizeof(struct eth_header);

    l3_size = dp_packet_size(packet) -
              ((char *)nh - (char *)dp_packet_data(packet));

    if (IP_VER(ip->ip_ihl_ver) == 4) {

        ovs_be32 ip_src, ip_dst;

        if (OVS_UNLIKELY(!dp_packet_ip_checksum_valid(packet))) {
            if (csum(ip, IP_IHL(ip->ip_ihl_ver) * 4)) {
                VLOG_WARN_RL(&err_rl, "ip packet has invalid checksum");
                return NULL;
            }
        }

        if (ntohs(ip->ip_tot_len) > l3_size) {
            VLOG_WARN_RL(&err_rl, "ip packet is truncated (IP length %d, actual %d)",
                         ntohs(ip->ip_tot_len), l3_size);
            return NULL;
        }
        if (IP_IHL(ip->ip_ihl_ver) * 4 > sizeof(struct ip_header)) {
            VLOG_WARN_RL(&err_rl, "ip options not supported on tunnel packets "
                         "(%d bytes)", IP_IHL(ip->ip_ihl_ver) * 4);
            return NULL;
        }

        ip_src = get_16aligned_be32(&ip->ip_src);
        ip_dst = get_16aligned_be32(&ip->ip_dst);

        tnl->ip_src = ip_src;
        tnl->ip_dst = ip_dst;
        tnl->ip_tos = ip->ip_tos;
        tnl->ip_ttl = ip->ip_ttl;

        *hlen += IP_HEADER_LEN;

    } else if (IP_VER(ip->ip_ihl_ver) == 6) {
        ovs_be32 tc_flow = get_16aligned_be32(&ip6->ip6_flow);

        memcpy(tnl->ipv6_src.s6_addr, ip6->ip6_src.be16, sizeof ip6->ip6_src);
        memcpy(tnl->ipv6_dst.s6_addr, ip6->ip6_dst.be16, sizeof ip6->ip6_dst);

        tnl->ip_tos = ntohl(tc_flow) >> 20;
        tnl->ip_ttl = ip6->ip6_hlim;

        *hlen += packet->l4_ofs - packet->l3_ofs;

    } else {
        VLOG_WARN_RL(&err_rl, "ipv4 packet has invalid version (%d)",
                     IP_VER(ip->ip_ihl_ver));
        return NULL;
    }

    return l4;
}

/* Pushes the 'size' bytes of 'header' into the headroom of 'packet',
 * reallocating the packet if necessary.  'header' should contain an Ethernet
 * header, followed by an IPv4 header (without options), and an L4 header.
 *
 * This function sets the IP header's ip_tot_len field (which should be zeroed
 * as part of 'header') and puts its value into '*ip_tot_size' as well.  Also
 * updates IP header checksum, as well as the l3 and l4 offsets in 'packet'.
 *
 * Return pointer to the L4 header added to 'packet'. */
void *
netdev_tnl_push_ip_header(struct dp_packet *packet,
               const void *header, int size, int *ip_tot_size)
{
    struct eth_header *eth;
    struct ip_header *ip;
    struct ovs_16aligned_ip6_hdr *ip6;

    eth = dp_packet_push_uninit(packet, size);
    *ip_tot_size = dp_packet_size(packet) - sizeof (struct eth_header);

    memcpy(eth, header, size);
    /* The encapsulated packet has type Ethernet. Adjust dp_packet. */
    packet->packet_type = htonl(PT_ETH);
    dp_packet_reset_offsets(packet);
    packet->l3_ofs = sizeof (struct eth_header);

    if (netdev_tnl_is_header_ipv6(header)) {
        ip6 = netdev_tnl_ipv6_hdr(eth);
        *ip_tot_size -= IPV6_HEADER_LEN;
        ip6->ip6_plen = htons(*ip_tot_size);
        packet->l4_ofs = dp_packet_size(packet) - *ip_tot_size;
        return ip6 + 1;
    } else {
        ip = netdev_tnl_ip_hdr(eth);
        ip->ip_tot_len = htons(*ip_tot_size);
        ip->ip_csum = recalc_csum16(ip->ip_csum, 0, ip->ip_tot_len);
        *ip_tot_size -= IP_HEADER_LEN;
        packet->l4_ofs = dp_packet_size(packet) - *ip_tot_size;
        return ip + 1;
    }
}

static void *
udp_extract_tnl_md(struct dp_packet *packet, struct flow_tnl *tnl,
                   unsigned int *hlen)
{
    struct udp_header *udp;

    udp = netdev_tnl_ip_extract_tnl_md(packet, tnl, hlen);
    if (!udp) {
        return NULL;
    }

    if (udp->udp_csum) {
        if (OVS_UNLIKELY(!dp_packet_l4_checksum_valid(packet))) {
            uint32_t csum;
            if (netdev_tnl_is_header_ipv6(dp_packet_data(packet))) {
                csum = packet_csum_pseudoheader6(dp_packet_l3(packet));
            } else {
                csum = packet_csum_pseudoheader(dp_packet_l3(packet));
            }

            csum = csum_continue(csum, udp, dp_packet_size(packet) -
                                 ((const unsigned char *)udp -
                                  (const unsigned char *)dp_packet_eth(packet)
                                 ));
            if (csum_finish(csum)) {
                return NULL;
            }
        }
        tnl->flags |= FLOW_TNL_F_CSUM;
    }

    tnl->tp_src = udp->udp_src;
    tnl->tp_dst = udp->udp_dst;

    return udp + 1;
}


void
netdev_tnl_push_udp_header(const struct netdev *netdev OVS_UNUSED,
                           struct dp_packet *packet,
                           const struct ovs_action_push_tnl *data)
{
    struct udp_header *udp;
    int ip_tot_size;

    udp = netdev_tnl_push_ip_header(packet, data->header, data->header_len, &ip_tot_size);

    /* set udp src port */
    udp->udp_src = netdev_tnl_get_src_port(packet);
    udp->udp_len = htons(ip_tot_size);

    if (udp->udp_csum) {
        uint32_t csum;
        if (netdev_tnl_is_header_ipv6(dp_packet_data(packet))) {
            csum = packet_csum_pseudoheader6(netdev_tnl_ipv6_hdr(dp_packet_data(packet)));
        } else {
            csum = packet_csum_pseudoheader(netdev_tnl_ip_hdr(dp_packet_data(packet)));
        }

        csum = csum_continue(csum, udp, ip_tot_size);
        udp->udp_csum = csum_finish(csum);

        if (!udp->udp_csum) {
            udp->udp_csum = htons(0xffff);
        }
    }
}

static void *
eth_build_header(struct ovs_action_push_tnl *data,
                 const struct netdev_tnl_build_header_params *params)
{
    uint16_t eth_proto = params->is_ipv6 ? ETH_TYPE_IPV6 : ETH_TYPE_IP;
    struct eth_header *eth;

    memset(data->header, 0, sizeof data->header);

    eth = (struct eth_header *)data->header;
    eth->eth_dst = params->dmac;
    eth->eth_src = params->smac;
    eth->eth_type = htons(eth_proto);
    data->header_len = sizeof(struct eth_header);
    return eth + 1;
}

void *
netdev_tnl_ip_build_header(struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params,
                           uint8_t next_proto)
{
    void *l3;

    l3 = eth_build_header(data, params);
    if (!params->is_ipv6) {
        ovs_be32 ip_src = in6_addr_get_mapped_ipv4(params->s_ip);
        struct ip_header *ip;

        ip = (struct ip_header *) l3;

        ip->ip_ihl_ver = IP_IHL_VER(5, 4);
        ip->ip_tos = params->flow->tunnel.ip_tos;
        ip->ip_ttl = params->flow->tunnel.ip_ttl;
        ip->ip_proto = next_proto;
        put_16aligned_be32(&ip->ip_src, ip_src);
        put_16aligned_be32(&ip->ip_dst, params->flow->tunnel.ip_dst);

        ip->ip_frag_off = (params->flow->tunnel.flags & FLOW_TNL_F_DONT_FRAGMENT) ?
                          htons(IP_DF) : 0;

        /* Checksum has already been zeroed by eth_build_header. */
        ip->ip_csum = csum(ip, sizeof *ip);

        data->header_len += IP_HEADER_LEN;
        return ip + 1;
    } else {
        struct ovs_16aligned_ip6_hdr *ip6;

        ip6 = (struct ovs_16aligned_ip6_hdr *) l3;

        put_16aligned_be32(&ip6->ip6_flow, htonl(6 << 28) |
                           htonl(params->flow->tunnel.ip_tos << 20));
        ip6->ip6_hlim = params->flow->tunnel.ip_ttl;
        ip6->ip6_nxt = next_proto;
        memcpy(&ip6->ip6_src, params->s_ip, sizeof(ovs_be32[4]));
        memcpy(&ip6->ip6_dst, &params->flow->tunnel.ipv6_dst, sizeof(ovs_be32[4]));

        data->header_len += IPV6_HEADER_LEN;
        return ip6 + 1;
    }
}

static void *
udp_build_header(struct netdev_tunnel_config *tnl_cfg,
                 struct ovs_action_push_tnl *data,
                 const struct netdev_tnl_build_header_params *params)
{
    struct udp_header *udp;

    udp = netdev_tnl_ip_build_header(data, params, IPPROTO_UDP);
    udp->udp_dst = tnl_cfg->dst_port;

    if (params->is_ipv6 || params->flow->tunnel.flags & FLOW_TNL_F_CSUM) {
        /* Write a value in now to mark that we should compute the checksum
         * later. 0xffff is handy because it is transparent to the
         * calculation. */
        udp->udp_csum = htons(0xffff);
    }
    data->header_len += sizeof *udp;
    return udp + 1;
}

static int
gre_header_len(ovs_be16 flags)
{
    int hlen = 4;

    if (flags & htons(GRE_CSUM)) {
        hlen += 4;
    }
    if (flags & htons(GRE_KEY)) {
        hlen += 4;
    }
    if (flags & htons(GRE_SEQ)) {
        hlen += 4;
    }
    return hlen;
}

static int
parse_gre_header(struct dp_packet *packet,
                 struct flow_tnl *tnl)
{
    const struct gre_base_hdr *greh;
    ovs_16aligned_be32 *options;
    int hlen;
    unsigned int ulen;
    uint16_t greh_protocol;

    greh = netdev_tnl_ip_extract_tnl_md(packet, tnl, &ulen);
    if (!greh) {
        return -EINVAL;
    }

    if (greh->flags & ~(htons(GRE_CSUM | GRE_KEY | GRE_SEQ))) {
        return -EINVAL;
    }

    hlen = ulen + gre_header_len(greh->flags);
    if (hlen > dp_packet_size(packet)) {
        return -EINVAL;
    }

    options = (ovs_16aligned_be32 *)(greh + 1);
    if (greh->flags & htons(GRE_CSUM)) {
        ovs_be16 pkt_csum;

        pkt_csum = csum(greh, dp_packet_size(packet) -
                              ((const unsigned char *)greh -
                               (const unsigned char *)dp_packet_eth(packet)));
        if (pkt_csum) {
            return -EINVAL;
        }
        tnl->flags = FLOW_TNL_F_CSUM;
        options++;
    }

    if (greh->flags & htons(GRE_KEY)) {
        tnl->tun_id = be32_to_be64(get_16aligned_be32(options));
        tnl->flags |= FLOW_TNL_F_KEY;
        options++;
    }

    if (greh->flags & htons(GRE_SEQ)) {
        options++;
    }

    /* Set the new packet type depending on the GRE protocol field. */
    greh_protocol = ntohs(greh->protocol);
    if (greh_protocol == ETH_TYPE_TEB) {
        packet->packet_type = htonl(PT_ETH);
    } else if (greh_protocol >= ETH_TYPE_MIN) {
        /* Allow all GRE protocol values above 0x5ff as Ethertypes. */
        packet->packet_type = PACKET_TYPE_BE(OFPHTN_ETHERTYPE, greh_protocol);
    } else {
        return -EINVAL;
    }

    return hlen;
}

struct dp_packet *
netdev_gre_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    int hlen = sizeof(struct eth_header) + 4;

    hlen += netdev_tnl_is_header_ipv6(dp_packet_data(packet)) ?
            IPV6_HEADER_LEN : IP_HEADER_LEN;

    pkt_metadata_init_tnl(md);
    if (hlen > dp_packet_size(packet)) {
        goto err;
    }

    hlen = parse_gre_header(packet, tnl);
    if (hlen < 0) {
        goto err;
    }

    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

void
netdev_gre_push_header(const struct netdev *netdev,
                       struct dp_packet *packet,
                       const struct ovs_action_push_tnl *data)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct gre_base_hdr *greh;
    int ip_tot_size;

    greh = netdev_tnl_push_ip_header(packet, data->header, data->header_len, &ip_tot_size);

    if (greh->flags & htons(GRE_CSUM)) {
        ovs_be16 *csum_opt = (ovs_be16 *) (greh + 1);
        *csum_opt = csum(greh, ip_tot_size);
    }

    if (greh->flags & htons(GRE_SEQ)) {
        /* Last 4 byte is GRE seqno */
        int seq_ofs = gre_header_len(greh->flags) - 4;
        ovs_16aligned_be32 *seq_opt =
            ALIGNED_CAST(ovs_16aligned_be32 *, (char *)greh + seq_ofs);
        tnl_cfg = &dev->tnl_cfg;
        put_16aligned_be32(seq_opt, htonl(tnl_cfg->seqno++));
    }
}

int
netdev_gre_build_header(const struct netdev *netdev,
                        struct ovs_action_push_tnl *data,
                        const struct netdev_tnl_build_header_params *params)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct gre_base_hdr *greh;
    ovs_16aligned_be32 *options;
    unsigned int hlen;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    greh = netdev_tnl_ip_build_header(data, params, IPPROTO_GRE);

    if (params->flow->packet_type == htonl(PT_ETH)) {
        greh->protocol = htons(ETH_TYPE_TEB);
    } else if (pt_ns(params->flow->packet_type) == OFPHTN_ETHERTYPE) {
        greh->protocol = pt_ns_type_be(params->flow->packet_type);
    } else {
        ovs_mutex_unlock(&dev->mutex);
        return 1;
    }
    greh->flags = 0;

    options = (ovs_16aligned_be32 *) (greh + 1);
    if (params->flow->tunnel.flags & FLOW_TNL_F_CSUM) {
        greh->flags |= htons(GRE_CSUM);
        put_16aligned_be32(options, 0);
        options++;
    }

    if (tnl_cfg->out_key_present) {
        greh->flags |= htons(GRE_KEY);
        put_16aligned_be32(options, be64_to_be32(params->flow->tunnel.tun_id));
        options++;
    }

    if (tnl_cfg->set_seq) {
        greh->flags |= htons(GRE_SEQ);
        /* seqno is updated at push header */
        options++;
    }

    ovs_mutex_unlock(&dev->mutex);

    hlen = (uint8_t *) options - (uint8_t *) greh;

    data->header_len += hlen;
    if (!params->is_ipv6) {
        data->tnl_type = OVS_VPORT_TYPE_GRE;
    } else {
        data->tnl_type = OVS_VPORT_TYPE_IP6GRE;
    }
    return 0;
}

struct dp_packet *
netdev_erspan_pop_header(struct dp_packet *packet)
{
    const struct gre_base_hdr *greh;
    const struct erspan_base_hdr *ersh;
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    int hlen = sizeof(struct eth_header);
    unsigned int ulen;
    uint16_t greh_protocol;

    hlen += netdev_tnl_is_header_ipv6(dp_packet_data(packet)) ?
            IPV6_HEADER_LEN : IP_HEADER_LEN;

    pkt_metadata_init_tnl(md);
    if (hlen > dp_packet_size(packet)) {
        goto err;
    }

    greh = netdev_tnl_ip_extract_tnl_md(packet, tnl, &ulen);
    if (!greh) {
        goto err;
    }

    greh_protocol = ntohs(greh->protocol);
    if (greh_protocol != ETH_TYPE_ERSPAN1 &&
        greh_protocol != ETH_TYPE_ERSPAN2) {
        goto err;
    }

    if (greh->flags & ~htons(GRE_SEQ)) {
        goto err;
    }

    ersh = ERSPAN_HDR(greh);
    tnl->tun_id = be16_to_be64(htons(get_sid(ersh)));
    tnl->erspan_ver = ersh->ver;

    if (ersh->ver == 1) {
        ovs_16aligned_be32 *index = ALIGNED_CAST(ovs_16aligned_be32 *,
                                                 ersh + 1);
        tnl->erspan_idx = ntohl(get_16aligned_be32(index));
        tnl->flags |= FLOW_TNL_F_KEY;
        hlen = ulen + ERSPAN_GREHDR_LEN + sizeof *ersh + ERSPAN_V1_MDSIZE;
    } else if (ersh->ver == 2) {
        struct erspan_md2 *md2 = ALIGNED_CAST(struct erspan_md2 *, ersh + 1);
        tnl->erspan_dir = md2->dir;
        tnl->erspan_hwid = get_hwid(md2);
        tnl->flags |= FLOW_TNL_F_KEY;
        hlen = ulen + ERSPAN_GREHDR_LEN + sizeof *ersh + ERSPAN_V2_MDSIZE;
    } else {
        VLOG_WARN_RL(&err_rl, "ERSPAN version error %d", ersh->ver);
        goto err;
    }

    if (hlen > dp_packet_size(packet)) {
        goto err;
    }

    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

void
netdev_erspan_push_header(const struct netdev *netdev,
                          struct dp_packet *packet,
                          const struct ovs_action_push_tnl *data)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct erspan_base_hdr *ersh;
    struct gre_base_hdr *greh;
    struct erspan_md2 *md2;
    int ip_tot_size;

    greh = netdev_tnl_push_ip_header(packet, data->header,
                                     data->header_len, &ip_tot_size);

    /* update GRE seqno */
    tnl_cfg = &dev->tnl_cfg;
    ovs_16aligned_be32 *seqno = (ovs_16aligned_be32 *) (greh + 1);
    put_16aligned_be32(seqno, htonl(tnl_cfg->seqno++));

    /* update v2 timestamp */
    if (greh->protocol == htons(ETH_TYPE_ERSPAN2)) {
        ersh = ERSPAN_HDR(greh);
        md2 = ALIGNED_CAST(struct erspan_md2 *, ersh + 1);
        put_16aligned_be32(&md2->timestamp, get_erspan_ts(ERSPAN_100US));
    }
    return;
}

int
netdev_erspan_build_header(const struct netdev *netdev,
                        struct ovs_action_push_tnl *data,
                        const struct netdev_tnl_build_header_params *params)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct gre_base_hdr *greh;
    struct erspan_base_hdr *ersh;
    unsigned int hlen;
    uint32_t tun_id;
    int erspan_ver;
    uint16_t sid;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;
    greh = netdev_tnl_ip_build_header(data, params, IPPROTO_GRE);
    ersh = ERSPAN_HDR(greh);

    tun_id = ntohl(be64_to_be32(params->flow->tunnel.tun_id));
    /* ERSPAN only has 10-bit session ID */
    if (tun_id & ~ERSPAN_SID_MASK) {
        ovs_mutex_unlock(&dev->mutex);
        return 1;
    } else {
        sid = (uint16_t) tun_id;
    }

    if (tnl_cfg->erspan_ver_flow) {
        erspan_ver = params->flow->tunnel.erspan_ver;
    } else {
        erspan_ver = tnl_cfg->erspan_ver;
    }

    if (erspan_ver == 1) {
        ovs_be32 *index;

        greh->protocol = htons(ETH_TYPE_ERSPAN1);
        greh->flags = htons(GRE_SEQ);
        ersh->ver = 1;
        set_sid(ersh, sid);

        put_16aligned_be32(ALIGNED_CAST(ovs_16aligned_be32 *, ersh + 1),
                           htonl(tnl_cfg->erspan_idx));

        index = (ovs_be32 *)(ersh + 1);

        if (tnl_cfg->erspan_idx_flow) {
            *index = htonl(params->flow->tunnel.erspan_idx);
        } else {
            *index = htonl(tnl_cfg->erspan_idx);
        }

        hlen = ERSPAN_GREHDR_LEN + sizeof *ersh + ERSPAN_V1_MDSIZE;
    } else if (erspan_ver == 2) {
        struct erspan_md2 *md2 = ALIGNED_CAST(struct erspan_md2 *, ersh + 1);

        greh->protocol = htons(ETH_TYPE_ERSPAN2);
        greh->flags = htons(GRE_SEQ);
        ersh->ver = 2;
        set_sid(ersh, sid);

        md2->sgt = 0; /* security group tag */
        md2->gra = 0;
        put_16aligned_be32(&md2->timestamp, 0);

        if (tnl_cfg->erspan_hwid_flow) {
            set_hwid(md2, params->flow->tunnel.erspan_hwid);
        } else {
            set_hwid(md2, tnl_cfg->erspan_hwid);
        }

        if (tnl_cfg->erspan_dir_flow) {
            md2->dir = params->flow->tunnel.erspan_dir;
        } else {
            md2->dir = tnl_cfg->erspan_dir;
        }

        hlen = ERSPAN_GREHDR_LEN + sizeof *ersh + ERSPAN_V2_MDSIZE;
    } else {
        VLOG_WARN_RL(&err_rl, "ERSPAN version error %d", tnl_cfg->erspan_ver);
        ovs_mutex_unlock(&dev->mutex);
        return 1;
    }

    ovs_mutex_unlock(&dev->mutex);

    data->header_len += hlen;

    if (params->is_ipv6) {
        data->tnl_type = OVS_VPORT_TYPE_IP6ERSPAN;
    } else {
        data->tnl_type = OVS_VPORT_TYPE_ERSPAN;
    }
    return 0;
}

struct dp_packet *
netdev_vxlan_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct vxlanhdr *vxh;
    unsigned int hlen;
    ovs_be32 vx_flags;
    enum packet_type next_pt = PT_ETH;

    ovs_assert(packet->l3_ofs > 0);
    ovs_assert(packet->l4_ofs > 0);

    pkt_metadata_init_tnl(md);
    if (VXLAN_HLEN > dp_packet_l4_size(packet)) {
        goto err;
    }

    vxh = udp_extract_tnl_md(packet, tnl, &hlen);
    if (!vxh) {
        goto err;
    }

    vx_flags = get_16aligned_be32(&vxh->vx_flags);
    if (vx_flags & htonl(VXLAN_HF_GPE)) {
        vx_flags &= htonl(~VXLAN_GPE_USED_BITS);
        /* Drop the OAM packets */
        if (vxh->vx_gpe.flags & VXLAN_GPE_FLAGS_O) {
            goto err;
        }
        switch (vxh->vx_gpe.next_protocol) {
        case VXLAN_GPE_NP_IPV4:
            next_pt = PT_IPV4;
            break;
        case VXLAN_GPE_NP_IPV6:
            next_pt = PT_IPV6;
            break;
        case VXLAN_GPE_NP_NSH:
            next_pt = PT_NSH;
            break;
        case VXLAN_GPE_NP_ETHERNET:
            next_pt = PT_ETH;
            break;
        default:
            goto err;
        }
    }

    if (vx_flags != htonl(VXLAN_FLAGS) ||
       (get_16aligned_be32(&vxh->vx_vni) & htonl(0xff))) {
        VLOG_WARN_RL(&err_rl, "invalid vxlan flags=%#x vni=%#x\n",
                     ntohl(vx_flags),
                     ntohl(get_16aligned_be32(&vxh->vx_vni)));
        goto err;
    }
    tnl->tun_id = htonll(ntohl(get_16aligned_be32(&vxh->vx_vni)) >> 8);
    tnl->flags |= FLOW_TNL_F_KEY;

    packet->packet_type = htonl(next_pt);
    dp_packet_reset_packet(packet, hlen + VXLAN_HLEN);
    if (next_pt != PT_ETH) {
        packet->l3_ofs = 0;
    }

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

int
netdev_vxlan_build_header(const struct netdev *netdev,
                          struct ovs_action_push_tnl *data,
                          const struct netdev_tnl_build_header_params *params)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct vxlanhdr *vxh;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    vxh = udp_build_header(tnl_cfg, data, params);

    if (tnl_cfg->exts & (1 << OVS_VXLAN_EXT_GPE)) {
        put_16aligned_be32(&vxh->vx_flags, htonl(VXLAN_FLAGS | VXLAN_HF_GPE));
        put_16aligned_be32(&vxh->vx_vni,
                           htonl(ntohll(params->flow->tunnel.tun_id) << 8));
        if (params->flow->packet_type == htonl(PT_ETH)) {
            vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_ETHERNET;
        } else if (pt_ns(params->flow->packet_type) == OFPHTN_ETHERTYPE) {
            switch (pt_ns_type(params->flow->packet_type)) {
            case ETH_TYPE_IP:
                vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_IPV4;
                break;
            case ETH_TYPE_IPV6:
                vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_IPV6;
                break;
            case ETH_TYPE_NSH:
                vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_NSH;
                break;
            case ETH_TYPE_TEB:
                vxh->vx_gpe.next_protocol = VXLAN_GPE_NP_ETHERNET;
                break;
            default:
                goto drop;
            }
        } else {
            goto drop;
        }
    } else {
        put_16aligned_be32(&vxh->vx_flags, htonl(VXLAN_FLAGS));
        put_16aligned_be32(&vxh->vx_vni,
                           htonl(ntohll(params->flow->tunnel.tun_id) << 8));
    }

    ovs_mutex_unlock(&dev->mutex);
    data->header_len += sizeof *vxh;
    data->tnl_type = OVS_VPORT_TYPE_VXLAN;
    return 0;

drop:
    ovs_mutex_unlock(&dev->mutex);
    return 1;
}

struct dp_packet *
netdev_geneve_pop_header(struct dp_packet *packet)
{
    struct pkt_metadata *md = &packet->md;
    struct flow_tnl *tnl = &md->tunnel;
    struct genevehdr *gnh;
    unsigned int hlen, opts_len, ulen;

    pkt_metadata_init_tnl(md);
    if (GENEVE_BASE_HLEN > dp_packet_l4_size(packet)) {
        VLOG_WARN_RL(&err_rl, "geneve packet too small: min header=%u packet size=%"PRIuSIZE"\n",
                     (unsigned int)GENEVE_BASE_HLEN, dp_packet_l4_size(packet));
        goto err;
    }

    gnh = udp_extract_tnl_md(packet, tnl, &ulen);
    if (!gnh) {
        goto err;
    }

    opts_len = gnh->opt_len * 4;
    hlen = ulen + GENEVE_BASE_HLEN + opts_len;
    if (hlen > dp_packet_size(packet)) {
        VLOG_WARN_RL(&err_rl, "geneve packet too small: header len=%u packet size=%u\n",
                     hlen, dp_packet_size(packet));
        goto err;
    }

    if (gnh->ver != 0) {
        VLOG_WARN_RL(&err_rl, "unknown geneve version: %"PRIu8"\n", gnh->ver);
        goto err;
    }

    if (gnh->proto_type != htons(ETH_TYPE_TEB)) {
        VLOG_WARN_RL(&err_rl, "unknown geneve encapsulated protocol: %#x\n",
                     ntohs(gnh->proto_type));
        goto err;
    }

    tnl->flags |= gnh->oam ? FLOW_TNL_F_OAM : 0;
    tnl->tun_id = htonll(ntohl(get_16aligned_be32(&gnh->vni)) >> 8);
    tnl->flags |= FLOW_TNL_F_KEY;

    memcpy(tnl->metadata.opts.gnv, gnh->options, opts_len);
    tnl->metadata.present.len = opts_len;
    tnl->flags |= FLOW_TNL_F_UDPIF;

    packet->packet_type = htonl(PT_ETH);
    dp_packet_reset_packet(packet, hlen);

    return packet;
err:
    dp_packet_delete(packet);
    return NULL;
}

int
netdev_geneve_build_header(const struct netdev *netdev,
                           struct ovs_action_push_tnl *data,
                           const struct netdev_tnl_build_header_params *params)
{
    struct netdev_vport *dev = netdev_vport_cast(netdev);
    struct netdev_tunnel_config *tnl_cfg;
    struct genevehdr *gnh;
    int opt_len;
    bool crit_opt;

    /* XXX: RCUfy tnl_cfg. */
    ovs_mutex_lock(&dev->mutex);
    tnl_cfg = &dev->tnl_cfg;

    gnh = udp_build_header(tnl_cfg, data, params);

    put_16aligned_be32(&gnh->vni, htonl(ntohll(params->flow->tunnel.tun_id) << 8));

    ovs_mutex_unlock(&dev->mutex);

    opt_len = tun_metadata_to_geneve_header(&params->flow->tunnel,
                                            gnh->options, &crit_opt);

    gnh->opt_len = opt_len / 4;
    gnh->oam = !!(params->flow->tunnel.flags & FLOW_TNL_F_OAM);
    gnh->critical = crit_opt ? 1 : 0;
    gnh->proto_type = htons(ETH_TYPE_TEB);

    data->header_len += sizeof *gnh + opt_len;
    data->tnl_type = OVS_VPORT_TYPE_GENEVE;
    return 0;
}


void
netdev_tnl_egress_port_range(struct unixctl_conn *conn, int argc,
                             const char *argv[], void *aux OVS_UNUSED)
{
    int val1, val2;

    if (argc < 3) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        ds_put_format(&ds, "Tunnel UDP source port range: %"PRIu16"-%"PRIu16"\n",
                            tnl_udp_port_min, tnl_udp_port_max);

        unixctl_command_reply(conn, ds_cstr(&ds));
        ds_destroy(&ds);
        return;
    }

    if (argc != 3) {
        return;
    }

    val1 = atoi(argv[1]);
    if (val1 <= 0 || val1 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid min.");
        return;
    }
    val2 = atoi(argv[2]);
    if (val2 <= 0 || val2 > UINT16_MAX) {
        unixctl_command_reply(conn, "Invalid max.");
        return;
    }

    if (val1 > val2) {
        tnl_udp_port_min = val2;
        tnl_udp_port_max = val1;
    } else {
        tnl_udp_port_min = val1;
        tnl_udp_port_max = val2;
    }
    seq_change(tnl_conf_seq);

    unixctl_command_reply(conn, "OK");
}
