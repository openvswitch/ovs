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
 * from the packet 'p' at offset 'data_off'.
 *
 * Note: The packet headers are not updated. */
static struct dp_packet *
dp_packet_gso_seg_new(const struct dp_packet *p, size_t hdr_len,
                      size_t data_off, size_t data_len)
{
    struct dp_packet *seg = dp_packet_new_with_headroom(hdr_len + data_len,
                                                        dp_packet_headroom(p));

    /* Append the original packet headers and then the payload. */
    dp_packet_put(seg, dp_packet_data(p), hdr_len);
    dp_packet_put(seg, (char *) dp_packet_data(p) + data_off, data_len);

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

    seg->offloads = p->offloads;

    return seg;
}

/* Returns the calculated number of TCP segments in packet 'p'. */
unsigned int
dp_packet_gso_nr_segs(struct dp_packet *p)
{
    uint16_t segsz = dp_packet_get_tso_segsz(p);
    uint32_t data_length;

    if (dp_packet_tunnel(p)) {
        data_length = dp_packet_get_inner_tcp_payload_length(p);
    } else {
        data_length = dp_packet_get_tcp_payload_length(p);
    }

    return DIV_ROUND_UP(data_length, segsz);
}

/* For partial segmentation, we try to pack as much data as we can in a first
 * packet (up to the final number of segments on the wire).
 * If there is still some data left, we need an extra "little" packet
 * (shorter than tso_segsz). */
unsigned int
dp_packet_gso_partial_nr_segs(struct dp_packet *p)
{
    if ((dp_packet_tunnel_geneve(p) || dp_packet_tunnel_vxlan(p))
        && dp_packet_l4_checksum_partial(p)
        && dp_packet_get_inner_tcp_payload_length(p)
           != dp_packet_gso_nr_segs(p) * dp_packet_get_tso_segsz(p)) {
        return 2;
    }

    return 1;
}

static void
dp_packet_gso_update_segment(struct dp_packet *seg, unsigned int seg_no,
                             unsigned int n_segs, uint16_t tso_segsz,
                             bool udp_tnl, bool gre_tnl)
{
    struct tcp_header *tcp_hdr;
    struct ip_header *ip_hdr;
    uint32_t tcp_seq;

    if (udp_tnl) {
        /* Update tunnel UDP header length. */
        struct udp_header *tnl_hdr;

        tnl_hdr = dp_packet_l4(seg);
        tnl_hdr->udp_len = htons(dp_packet_l4_size(seg));
    }

    if (udp_tnl || gre_tnl) {
        /* Update tunnel inner L3 header. */
        ip_hdr = dp_packet_inner_l3(seg);
        if (IP_VER(ip_hdr->ip_ihl_ver) == 4) {
            ip_hdr->ip_tot_len = htons(dp_packet_inner_l3_size(seg));
            ip_hdr->ip_id = htons(ntohs(ip_hdr->ip_id) + seg_no);
            ip_hdr->ip_csum = 0;
            dp_packet_inner_ip_checksum_set_partial(seg);
        } else {
            struct ovs_16aligned_ip6_hdr *ip6_hdr;

            ip6_hdr = dp_packet_inner_l3(seg);
            ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen
                = htons(dp_packet_inner_l3_size(seg) - sizeof *ip6_hdr);
        }
    }

    /* Update L3 header. */
    ip_hdr = dp_packet_l3(seg);
    if (IP_VER(ip_hdr->ip_ihl_ver) == 4) {
        ip_hdr->ip_tot_len = htons(dp_packet_l3_size(seg));
        ip_hdr->ip_id = htons(ntohs(ip_hdr->ip_id) + seg_no);
        ip_hdr->ip_csum = 0;
        dp_packet_ip_checksum_set_partial(seg);
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
    tcp_seq = ntohl(get_16aligned_be32(&tcp_hdr->tcp_seq));
    tcp_seq += seg_no * tso_segsz;
    put_16aligned_be32(&tcp_hdr->tcp_seq, htonl(tcp_seq));

    if (seg_no < (n_segs - 1) && !dp_packet_get_tso_segsz(seg)) {
        uint16_t tcp_offset = TCP_OFFSET(tcp_hdr->tcp_ctl);
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
}

static void
dp_packet_gso__(struct dp_packet *p, struct dp_packet_batch **batches,
                bool partial_seg)
{
    struct dp_packet_batch *curr_batch = *batches;
    struct dp_packet *seg;
    unsigned int n_segs;
    uint16_t tso_segsz;
    size_t data_len;
    size_t hdr_len;
    bool udp_tnl;
    bool gre_tnl;

    tso_segsz = dp_packet_get_tso_segsz(p);
    ovs_assert(tso_segsz);
    n_segs = dp_packet_gso_nr_segs(p);
    udp_tnl = dp_packet_tunnel_vxlan(p) || dp_packet_tunnel_geneve(p);
    gre_tnl = dp_packet_tunnel_gre(p);

    /* Put back the first segment in the batch, it will be trimmed after
     * all segments have been copied. */
    if (dp_packet_batch_is_full(curr_batch)) {
        curr_batch++;
    }
    dp_packet_batch_add(curr_batch, p);

    if (n_segs <= 1) {
        goto out;
    }

    if (dp_packet_tunnel(p)) {
        hdr_len = (char *) dp_packet_get_inner_tcp_payload(p)
                  - (char *) dp_packet_eth(p);
        data_len = dp_packet_get_inner_tcp_payload_length(p);
    } else {
        hdr_len = (char *) dp_packet_get_tcp_payload(p)
                  - (char *) dp_packet_eth(p);
        data_len = dp_packet_get_tcp_payload_length(p);
    }

    if (partial_seg) {
        if (dp_packet_gso_partial_nr_segs(p) != 1) {
            goto last_seg;
        }
        goto first_seg;
    }

    for (unsigned int i = 1; i < n_segs - 1; i++) {
        seg = dp_packet_gso_seg_new(p, hdr_len, hdr_len + i * tso_segsz,
                                    tso_segsz);
        dp_packet_gso_update_segment(seg, i, n_segs, tso_segsz, udp_tnl,
                                     gre_tnl);

        if (dp_packet_batch_is_full(curr_batch)) {
            curr_batch++;
        }
        dp_packet_batch_add(curr_batch, seg);
    }

last_seg:
    /* Create the last segment. */
    seg = dp_packet_gso_seg_new(p, hdr_len, hdr_len + (n_segs - 1) * tso_segsz,
                                data_len - (n_segs - 1) * tso_segsz);
    dp_packet_gso_update_segment(seg, n_segs - 1, n_segs, tso_segsz, udp_tnl,
                                 gre_tnl);

    if (dp_packet_batch_is_full(curr_batch)) {
        curr_batch++;
    }
    dp_packet_batch_add(curr_batch, seg);

first_seg:
    if (partial_seg) {
        if (dp_packet_gso_partial_nr_segs(p) != 1) {
            dp_packet_set_size(p, hdr_len + (n_segs - 1) * tso_segsz);
            if (n_segs == 2) {
                /* No need to ask HW segmentation, we already did the job. */
                dp_packet_set_tso_segsz(p, 0);
            }
        }
    } else {
        /* Trim the first segment and reset TSO. */
        dp_packet_set_size(p, hdr_len + tso_segsz);
        dp_packet_set_tso_segsz(p, 0);
    }
    dp_packet_gso_update_segment(p, 0, n_segs, tso_segsz, udp_tnl, gre_tnl);

out:
    *batches = curr_batch;
}

/* Perform software segmentation on packet 'p'.
 *
 * Segments packet 'p' into the array of preallocated batches in 'batches',
 * updating the 'batches' pointer as needed. */
void
dp_packet_gso(struct dp_packet *p, struct dp_packet_batch **batches)
{
    dp_packet_gso__(p, batches, false);
}

/* Perform partial software segmentation on packet 'p'.
 *
 * For UDP tunnels, if the packet payload length is not aligned on the
 * segmentation size, segments the last segment of packet 'p' into the array
 * of preallocated batches in 'batches', updating the 'batches' pointer
 * as needed. */
void
dp_packet_gso_partial(struct dp_packet *p, struct dp_packet_batch **batches)
{
    dp_packet_gso__(p, batches, true);
}
