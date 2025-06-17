/*
 * Copyright (c) 2023 Red Hat, Inc.
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
#include <stdlib.h>
#include <string.h>

#include "dp-packet.h"
#include "dp-packet-gso.h"
#include "netdev-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dp_packet_gso);

/* Retuns a new packet that is a segment of packet 'p'.
 *
 * The new packet is initialized with 'hdr_len' bytes from the
 * start of packet 'p' and then appended with 'data_len' bytes
 * from the 'data' buffer.
 *
 * Note: The packet headers are not updated. */
static struct dp_packet *
dp_packet_gso_seg_new(const struct dp_packet *p, size_t hdr_len,
                      const char *data, size_t data_len)
{
    struct dp_packet *seg = dp_packet_new_with_headroom(hdr_len + data_len,
                                                        dp_packet_headroom(p));

    /* Append the original packet headers and then the payload. */
    dp_packet_put(seg, dp_packet_data(p), hdr_len);
    dp_packet_put(seg, data, data_len);

    /* The new segment should have the same offsets. */
    seg->l2_5_ofs = p->l2_5_ofs;
    seg->l3_ofs = p->l3_ofs;
    seg->l4_ofs = p->l4_ofs;
    seg->inner_l3_ofs = p->inner_l3_ofs;
    seg->inner_l4_ofs = p->inner_l4_ofs;

    /* The protocol headers remain the same, so preserve hash and mark. */
    seg->has_hash = p->has_hash;
    *dp_packet_rss_ptr(seg) = *dp_packet_rss_ptr(p);
    seg->has_mark = p->has_mark;
    *dp_packet_flow_mark_ptr(seg) = *dp_packet_flow_mark_ptr(p);

    /* The segment should inherit all the offloading flags from the
     * original packet, except for the TCP segmentation, external
     * buffer and indirect buffer flags. */
    *dp_packet_ol_flags_ptr(seg) = *dp_packet_ol_flags_ptr(p)
        & DP_PACKET_OL_SUPPORTED_MASK;
    seg->offloads = p->offloads;

    dp_packet_hwol_reset_tcp_seg(seg);

    return seg;
}

/* Returns the calculated number of TCP segments in packet 'p'. */
int
dp_packet_gso_nr_segs(struct dp_packet *p)
{
    uint16_t segsz = dp_packet_get_tso_segsz(p);
    const char *data_tail;
    const char *data_pos;

    if (dp_packet_tunnel(p)) {
        data_pos = dp_packet_get_inner_tcp_payload(p);
    } else {
        data_pos = dp_packet_get_tcp_payload(p);
    }
    data_tail = (char *) dp_packet_tail(p) - dp_packet_l2_pad_size(p);

    return DIV_ROUND_UP(data_tail - data_pos, segsz);
}

/* Perform software segmentation on packet 'p'.
 *
 * Segments packet 'p' into the array of preallocated batches in 'batches',
 * updating the 'batches' pointer as needed and returns true.
 *
 * Returns false if the packet cannot be segmented. */
bool
dp_packet_gso(struct dp_packet *p, struct dp_packet_batch **batches)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    struct dp_packet_batch *curr_batch = *batches;
    struct tcp_header *tcp_hdr;
    struct ip_header *ip_hdr;
    uint16_t inner_ip_id = 0;
    uint16_t outer_ip_id = 0;
    struct dp_packet *seg;
    uint16_t tcp_offset;
    uint16_t tso_segsz;
    uint32_t tcp_seq;
    bool outer_ipv4;
    int hdr_len;
    int seg_len;
    bool udp_tnl = dp_packet_tunnel_vxlan(p)
                   || dp_packet_tunnel_geneve(p);
    bool gre_tnl = dp_packet_tunnel_gre(p);

    tso_segsz = dp_packet_get_tso_segsz(p);
    if (!tso_segsz) {
        VLOG_WARN_RL(&rl, "GSO packet with len %d with no segment size.",
                     dp_packet_size(p));
        return false;
    }

    if (udp_tnl || gre_tnl) {
        ip_hdr = dp_packet_inner_l3(p);
        if (IP_VER(ip_hdr->ip_ihl_ver) == 4) {
            inner_ip_id = ntohs(ip_hdr->ip_id);
        }

        tcp_hdr = dp_packet_inner_l4(p);
    } else {
        tcp_hdr = dp_packet_l4(p);
    }

    ip_hdr = dp_packet_l3(p);
    outer_ipv4 = IP_VER(ip_hdr->ip_ihl_ver) == 4;
    if (outer_ipv4) {
        outer_ip_id = ntohs(ip_hdr->ip_id);
    }

    tcp_offset = TCP_OFFSET(tcp_hdr->tcp_ctl);
    tcp_seq = ntohl(get_16aligned_be32(&tcp_hdr->tcp_seq));
    hdr_len = ((char *) tcp_hdr - (char *) dp_packet_eth(p))
              + tcp_offset * 4;
    const char *data_tail = (char *) dp_packet_tail(p)
                            - dp_packet_l2_pad_size(p);
    const char *data_pos = (char *) tcp_hdr + tcp_offset * 4;
    int n_segs = dp_packet_gso_nr_segs(p);

    for (int i = 0; i < n_segs; i++) {
        seg_len = data_tail - data_pos;
        if (seg_len > tso_segsz) {
            seg_len = tso_segsz;
        }

        seg = dp_packet_gso_seg_new(p, hdr_len, data_pos, seg_len);
        data_pos += seg_len;

        if (udp_tnl) {
            /* Update tunnel UDP header length. */
            struct udp_header *tnl_hdr;

            tnl_hdr = dp_packet_l4(seg);
            tnl_hdr->udp_len = htons(dp_packet_l4_size(seg));
            dp_packet_l4_checksum_set_partial(seg);
        }

        if (udp_tnl || gre_tnl) {
            /* Update tunnel inner L3 header. */
            ip_hdr = dp_packet_inner_l3(seg);
            if (IP_VER(ip_hdr->ip_ihl_ver) == 4) {
                ip_hdr->ip_tot_len = htons(dp_packet_inner_l3_size(seg));
                ip_hdr->ip_id = htons(inner_ip_id);
                ip_hdr->ip_csum = 0;
                dp_packet_inner_ip_checksum_set_partial(seg);
                inner_ip_id++;
            } else {
                struct ovs_16aligned_ip6_hdr *ip6_hdr;

                ip6_hdr = dp_packet_inner_l3(seg);
                ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen
                    = htons(dp_packet_inner_l3_size(seg) - sizeof *ip6_hdr);
            }
        }

        /* Update L3 header. */
        if (outer_ipv4) {
            ip_hdr = dp_packet_l3(seg);
            ip_hdr->ip_tot_len = htons(dp_packet_l3_size(seg));
            ip_hdr->ip_id = htons(outer_ip_id);
            ip_hdr->ip_csum = 0;
            dp_packet_ip_checksum_set_partial(seg);
            outer_ip_id++;
        } else {
            struct ovs_16aligned_ip6_hdr *ip6_hdr = dp_packet_l3(seg);

            ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen
                = htons(dp_packet_l3_size(seg) - sizeof *ip6_hdr);
        }

        /* Update L4 header. */
        if (udp_tnl || gre_tnl) {
            tcp_hdr = dp_packet_inner_l4(seg);
            dp_packet_inner_l4_checksum_set_partial(seg);
        } else {
            tcp_hdr = dp_packet_l4(seg);
            dp_packet_l4_checksum_set_partial(seg);
        }
        put_16aligned_be32(&tcp_hdr->tcp_seq, htonl(tcp_seq));
        tcp_seq += seg_len;
        if (OVS_LIKELY(i < (n_segs - 1))) {
            /* Reset flags PUSH and FIN unless it is the last segment. */
            uint16_t tcp_flags = TCP_FLAGS(tcp_hdr->tcp_ctl)
                                 & ~(TCP_PSH | TCP_FIN);
            tcp_hdr->tcp_ctl = TCP_CTL(tcp_flags, tcp_offset);
        }

        if (gre_tnl) {
            struct gre_base_hdr *ghdr;

            ghdr = dp_packet_l4(seg);

            if (ghdr->flags & htons(GRE_CSUM)) {
                ovs_be16 *csum_opt = (ovs_be16 *) (ghdr + 1);
                *csum_opt = 0;
                *csum_opt = csum(ghdr, dp_packet_l4_size(seg));
            }
        }

        if (dp_packet_batch_is_full(curr_batch)) {
            curr_batch++;
        }

        dp_packet_batch_add(curr_batch, seg);
    }

    *batches = curr_batch;
    return true;
}
