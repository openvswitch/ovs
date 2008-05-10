/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */
#include <sys/types.h>
#include "flow.h"
#include <inttypes.h>
#include <netinet/in.h>
#include <string.h>
#include "buffer.h"
#include "hash.h"
#include "openflow.h"
#include "packets.h"

#include "vlog.h"
#define THIS_MODULE VLM_flow

void
flow_extract(struct buffer *packet, uint16_t in_port, struct flow *flow)
{
    struct buffer b = *packet;
    struct eth_header *eth;

    if (b.size < ETH_TOTAL_MIN) {
        VLOG_WARN("packet length %zu less than minimum size %d",
                  b.size, ETH_TOTAL_MIN);
    }

    memset(flow, 0, sizeof *flow);
    flow->in_port = htons(in_port);

    packet->l2 = b.data;
    packet->l3 = NULL;
    packet->l4 = NULL;

    eth = buffer_at(&b, 0, sizeof *eth);
    if (eth) {
        buffer_pull(&b, ETH_HEADER_LEN);
        if (ntohs(eth->eth_type) >= OFP_DL_TYPE_ETH2_CUTOFF) {
            /* This is an Ethernet II frame */
            flow->dl_type = eth->eth_type;
        } else {
            /* This is an 802.2 frame */
            struct llc_snap_header *h = buffer_at(&b, 0, sizeof *h);
            if (h == NULL) {
                return;
            }
            if (h->llc.llc_dsap == LLC_DSAP_SNAP
                && h->llc.llc_ssap == LLC_SSAP_SNAP
                && h->llc.llc_cntl == LLC_CNTL_SNAP
                && !memcmp(h->snap.snap_org, SNAP_ORG_ETHERNET,
                           sizeof h->snap.snap_org)) {
                flow->dl_type = h->snap.snap_type;
                buffer_pull(&b, sizeof *h);
            } else {
                flow->dl_type = OFP_DL_TYPE_NOT_ETH_TYPE;
                buffer_pull(&b, sizeof(struct llc_header));
            }
        }

        /* Check for a VLAN tag */
        if (flow->dl_type != htons(ETH_TYPE_VLAN)) {
            flow->dl_vlan = htons(OFP_VLAN_NONE);
        } else {
            struct vlan_header *vh = buffer_at(&b, 0, sizeof *vh);
            flow->dl_type = vh->vlan_next_type;
            flow->dl_vlan = vh->vlan_tci & htons(VLAN_VID);
            buffer_pull(&b, sizeof *vh);
        }
        memcpy(flow->dl_src, eth->eth_src, ETH_ADDR_LEN);
        memcpy(flow->dl_dst, eth->eth_dst, ETH_ADDR_LEN);

        packet->l3 = b.data;
        if (flow->dl_type == htons(ETH_TYPE_IP)) {
            const struct ip_header *nh = buffer_at(&b, 0, sizeof *nh);
            if (nh) {
                int ip_len = IP_IHL(nh->ip_ihl_ver) * 4;
                if (ip_len < IP_HEADER_LEN) {
                    return;
                }

                flow->nw_src = nh->ip_src;
                flow->nw_dst = nh->ip_dst;
                flow->nw_proto = nh->ip_proto;
                if (flow->nw_proto == IP_TYPE_TCP
                    || flow->nw_proto == IP_TYPE_UDP) {
                    const struct udp_header *th;
                    th = packet->l4 = buffer_at(&b, ip_len, sizeof *th);
                    if (th) {
                        flow->tp_src = th->udp_src;
                        flow->tp_dst = th->udp_dst;
                    } else {
                        /* Avoid tricking other code into thinking that this
                         * packet has an L4 header. */
                        flow->nw_proto = 0;
                    }
                }
            }
        }
    }
}

void
flow_print(FILE *stream, const struct flow *flow) 
{
    fprintf(stream,
            "port%04x:vlan%04x mac"ETH_ADDR_FMT"->"ETH_ADDR_FMT" "
            "proto%04x ip"IP_FMT"->"IP_FMT" port%d->%d",
            ntohs(flow->in_port), ntohs(flow->dl_vlan),
            ETH_ADDR_ARGS(flow->dl_src), ETH_ADDR_ARGS(flow->dl_dst),
            ntohs(flow->dl_type),
            IP_ARGS(&flow->nw_src), IP_ARGS(&flow->nw_dst),
            ntohs(flow->tp_src), ntohs(flow->tp_dst));
}

int
flow_compare(const struct flow *a, const struct flow *b)
{
    return memcmp(a, b, sizeof *a);
}

unsigned long int
flow_hash(const struct flow *flow, uint32_t basis) 
{
    return hash_fnv(flow, sizeof *flow, basis);
}
