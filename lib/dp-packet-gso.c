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

    /* The protocol headers remain the same, so preserve hash and mark. */
    *dp_packet_rss_ptr(seg) = *dp_packet_rss_ptr(p);
    *dp_packet_flow_mark_ptr(seg) = *dp_packet_flow_mark_ptr(p);

    /* The segment should inherit all the offloading flags from the
     * original packet, except for the TCP segmentation, external
     * buffer and indirect buffer flags. */
    *dp_packet_ol_flags_ptr(seg) = *dp_packet_ol_flags_ptr(p)
        & DP_PACKET_OL_SUPPORTED_MASK;

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

    data_pos = dp_packet_get_tcp_payload(p);
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
    struct dp_packet *seg;
    uint16_t tcp_offset;
    uint16_t tso_segsz;
    uint32_t tcp_seq;
    uint16_t ip_id;
    int hdr_len;
    int seg_len;

    tso_segsz = dp_packet_get_tso_segsz(p);
    if (!tso_segsz) {
        VLOG_WARN_RL(&rl, "GSO packet with len %d with no segment size.",
                     dp_packet_size(p));
        return false;
    }

    tcp_hdr = dp_packet_l4(p);
    tcp_offset = TCP_OFFSET(tcp_hdr->tcp_ctl);
    tcp_seq = ntohl(get_16aligned_be32(&tcp_hdr->tcp_seq));
    hdr_len = ((char *) dp_packet_l4(p) - (char *) dp_packet_eth(p))
              + tcp_offset * 4;
    ip_id = 0;
    if (dp_packet_hwol_is_ipv4(p)) {
        ip_hdr = dp_packet_l3(p);
        ip_id = ntohs(ip_hdr->ip_id);
    }

    const char *data_tail = (char *) dp_packet_tail(p)
                            - dp_packet_l2_pad_size(p);
    const char *data_pos = dp_packet_get_tcp_payload(p);
    int n_segs = dp_packet_gso_nr_segs(p);

    for (int i = 0; i < n_segs; i++) {
        seg_len = data_tail - data_pos;
        if (seg_len > tso_segsz) {
            seg_len = tso_segsz;
        }

        seg = dp_packet_gso_seg_new(p, hdr_len, data_pos, seg_len);
        data_pos += seg_len;

        /* Update L3 header. */
        if (dp_packet_hwol_is_ipv4(seg)) {
            ip_hdr = dp_packet_l3(seg);
            ip_hdr->ip_tot_len = htons(sizeof *ip_hdr +
                                       dp_packet_l4_size(seg));
            ip_hdr->ip_id = htons(ip_id);
            ip_hdr->ip_csum = 0;
            ip_id++;
        } else {
            struct ovs_16aligned_ip6_hdr *ip6_hdr = dp_packet_l3(seg);

            ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen
                = htons(dp_packet_l3_size(seg) - sizeof *ip6_hdr);
        }

        /* Update L4 header. */
        tcp_hdr = dp_packet_l4(seg);
        put_16aligned_be32(&tcp_hdr->tcp_seq, htonl(tcp_seq));
        tcp_seq += seg_len;
        if (OVS_LIKELY(i < (n_segs - 1))) {
            /* Reset flags PUSH and FIN unless it is the last segment. */
            uint16_t tcp_flags = TCP_FLAGS(tcp_hdr->tcp_ctl)
                                 & ~(TCP_PSH | TCP_FIN);
            tcp_hdr->tcp_ctl = TCP_CTL(tcp_flags, tcp_offset);
        }

        if (dp_packet_batch_is_full(curr_batch)) {
            curr_batch++;
        }

        dp_packet_batch_add(curr_batch, seg);
    }

    *batches = curr_batch;
    return true;
}
