/* Copyright (c) 2015, 2016, 2017 Red Hat, Inc.
 * Copyright (c) 2017 Nicira, Inc.
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

#include "pinctrl.h"

#include "coverage.h"
#include "csum.h"
#include "dirs.h"
#include "dp-packet.h"
#include "flow.h"
#include "gchassis.h"
#include "lport.h"
#include "nx-match.h"
#include "ovn-controller.h"
#include "lib/packets.h"
#include "lib/sset.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-packet.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-switch.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/vlog.h"

#include "lib/dhcp.h"
#include "ovn-controller.h"
#include "ovn/actions.h"
#include "ovn/lex.h"
#include "ovn/lib/acl-log.h"
#include "ovn/lib/logical-fields.h"
#include "ovn/lib/ovn-l7.h"
#include "ovn/lib/ovn-util.h"
#include "openvswitch/poll-loop.h"
#include "openvswitch/rconn.h"
#include "socket-util.h"
#include "timeval.h"
#include "vswitch-idl.h"
#include "lflow.h"

VLOG_DEFINE_THIS_MODULE(pinctrl);

/* OpenFlow connection to the switch. */
static struct rconn *swconn;

/* Last seen sequence number for 'swconn'.  When this differs from
 * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
static unsigned int conn_seq_no;

static void pinctrl_handle_put_mac_binding(const struct flow *md,
                                           const struct flow *headers,
                                           bool is_arp);
static void init_put_mac_bindings(void);
static void destroy_put_mac_bindings(void);
static void run_put_mac_bindings(struct controller_ctx *);
static void wait_put_mac_bindings(struct controller_ctx *);
static void flush_put_mac_bindings(void);

static void init_send_garps(void);
static void destroy_send_garps(void);
static void send_garp_wait(void);
static void send_garp_run(struct controller_ctx *ctx,
                          const struct ovsrec_bridge *,
                          const struct sbrec_chassis *,
                          const struct chassis_index *chassis_index,
                          struct hmap *local_datapaths,
                          struct sset *active_tunnels);
static void pinctrl_handle_nd_na(const struct flow *ip_flow,
                                 const struct match *md,
                                 struct ofpbuf *userdata);
static void reload_metadata(struct ofpbuf *ofpacts,
                            const struct match *md);
static void pinctrl_handle_put_nd_ra_opts(
    const struct flow *ip_flow, struct dp_packet *pkt_in,
    struct ofputil_packet_in *pin, struct ofpbuf *userdata,
    struct ofpbuf *continuation);
static void pinctrl_handle_nd_ns(const struct flow *ip_flow,
                                 const struct match *md,
                                 struct ofpbuf *userdata);
static void init_ipv6_ras(void);
static void destroy_ipv6_ras(void);
static void ipv6_ra_wait(void);
static void send_ipv6_ras(const struct controller_ctx *,
                          struct hmap *local_datapaths);

COVERAGE_DEFINE(pinctrl_drop_put_mac_binding);

void
pinctrl_init(void)
{
    swconn = rconn_create(5, 0, DSCP_DEFAULT, 1 << OFP13_VERSION);
    conn_seq_no = 0;
    init_put_mac_bindings();
    init_send_garps();
    init_ipv6_ras();
}

static ovs_be32
queue_msg(struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid = oh->xid;

    rconn_send(swconn, msg, NULL);
    return xid;
}

/* Sets up global 'swconn', a newly (re)connected connection to a switch. */
static void
pinctrl_setup(void)
{
    /* Fetch the switch configuration.  The response later will allow us to
     * change the miss_send_len to UINT16_MAX, so that we can enable
     * asynchronous messages. */
    queue_msg(ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST,
                           rconn_get_version(swconn), 0));

    /* Set a packet-in format that supports userdata.  */
    queue_msg(ofputil_encode_set_packet_in_format(rconn_get_version(swconn),
                                                  OFPUTIL_PACKET_IN_NXT2));
}

static void
set_switch_config(struct rconn *swconn_,
                  const struct ofputil_switch_config *config)
{
    enum ofp_version version = rconn_get_version(swconn_);
    struct ofpbuf *request = ofputil_encode_set_config(config, version);
    queue_msg(request);
}

static void
set_actions_and_enqueue_msg(const struct dp_packet *packet,
                           const struct match *md,
                           struct ofpbuf *userdata)
{
    /* Copy metadata from 'md' into the packet-out via "set_field"
     * actions, then add actions from 'userdata'.
     */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);

    reload_metadata(&ofpacts, md);
    enum ofperr error = ofpacts_pull_openflow_actions(userdata, userdata->size,
                                                      version, NULL, NULL,
                                                      &ofpacts);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "failed to parse actions from userdata (%s)",
                     ofperr_to_string(error));
        ofpbuf_uninit(&ofpacts);
        return;
    }

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(packet),
        .packet_len = dp_packet_size(packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(ofputil_encode_packet_out(&po, proto));
    ofpbuf_uninit(&ofpacts);
}

static void
pinctrl_handle_arp(const struct flow *ip_flow, const struct match *md,
                   struct ofpbuf *userdata)
{
    /* This action only works for IP packets, and the switch should only send
     * us IP packets this way, but check here just to be sure. */
    if (ip_flow->dl_type != htons(ETH_TYPE_IP)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "ARP action on non-IP packet (Ethertype %"PRIx16")",
                     ntohs(ip_flow->dl_type));
        return;
    }

    /* Compose an ARP packet. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_arp__(&packet);

    struct eth_header *eth = dp_packet_eth(&packet);
    eth->eth_dst = ip_flow->dl_dst;
    eth->eth_src = ip_flow->dl_src;

    struct arp_eth_header *arp = dp_packet_l3(&packet);
    arp->ar_op = htons(ARP_OP_REQUEST);
    arp->ar_sha = ip_flow->dl_src;
    put_16aligned_be32(&arp->ar_spa, ip_flow->nw_src);
    arp->ar_tha = eth_addr_zero;
    put_16aligned_be32(&arp->ar_tpa, ip_flow->nw_dst);

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    set_actions_and_enqueue_msg(&packet, md, userdata);
    dp_packet_uninit(&packet);
}

static void
pinctrl_handle_icmp(const struct flow *ip_flow, struct dp_packet *pkt_in,
                    const struct match *md, struct ofpbuf *userdata)
{
    /* This action only works for IP packets, and the switch should only send
     * us IP packets this way, but check here just to be sure. */
    if (ip_flow->dl_type != htons(ETH_TYPE_IP) &&
        ip_flow->dl_type != htons(ETH_TYPE_IPV6)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl,
                     "ICMP action on non-IP packet (eth_type 0x%"PRIx16")",
                     ntohs(ip_flow->dl_type));
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    dp_packet_clear(&packet);
    packet.packet_type = htonl(PT_ETH);

    struct eth_header *eh = dp_packet_put_zeros(&packet, sizeof *eh);
    eh->eth_dst = ip_flow->dl_dst;
    eh->eth_src = ip_flow->dl_src;

    if (get_dl_type(ip_flow) == htons(ETH_TYPE_IP)) {
        struct ip_header *nh = dp_packet_put_zeros(&packet, sizeof *nh);

        eh->eth_type = htons(ETH_TYPE_IP);
        dp_packet_set_l3(&packet, nh);
        nh->ip_ihl_ver = IP_IHL_VER(5, 4);
        nh->ip_tot_len = htons(sizeof(struct ip_header) +
                               sizeof(struct icmp_header));
        nh->ip_proto = IPPROTO_ICMP;
        nh->ip_frag_off = htons(IP_DF);
        packet_set_ipv4(&packet, ip_flow->nw_src, ip_flow->nw_dst,
                        ip_flow->nw_tos, 255);

        struct icmp_header *ih = dp_packet_put_zeros(&packet, sizeof *ih);
        dp_packet_set_l4(&packet, ih);
        packet_set_icmp(&packet, ICMP4_DST_UNREACH, 1);
    } else {
        struct ip6_hdr *nh = dp_packet_put_zeros(&packet, sizeof *nh);
        struct icmp6_error_header *ih;
        uint32_t icmpv6_csum;

        eh->eth_type = htons(ETH_TYPE_IPV6);
        dp_packet_set_l3(&packet, nh);
        nh->ip6_vfc = 0x60;
        nh->ip6_nxt = IPPROTO_ICMPV6;
        nh->ip6_plen = htons(sizeof(*nh) + ICMP6_ERROR_HEADER_LEN);
        packet_set_ipv6(&packet, &ip_flow->ipv6_src, &ip_flow->ipv6_dst,
                        ip_flow->nw_tos, ip_flow->ipv6_label, 255);

        ih = dp_packet_put_zeros(&packet, sizeof *ih);
        dp_packet_set_l4(&packet, ih);
        ih->icmp6_base.icmp6_type = ICMP6_DST_UNREACH;
        ih->icmp6_base.icmp6_code = 1;
        ih->icmp6_base.icmp6_cksum = 0;

        uint8_t *data = dp_packet_put_zeros(&packet, sizeof *nh);
        memcpy(data, dp_packet_l3(pkt_in), sizeof(*nh));

        icmpv6_csum = packet_csum_pseudoheader6(dp_packet_l3(&packet));
        ih->icmp6_base.icmp6_cksum = csum_finish(
            csum_continue(icmpv6_csum, ih,
                          sizeof(*nh) + ICMP6_ERROR_HEADER_LEN));
    }

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    set_actions_and_enqueue_msg(&packet, md, userdata);
    dp_packet_uninit(&packet);
}

static void
pinctrl_handle_tcp_reset(const struct flow *ip_flow, struct dp_packet *pkt_in,
                         const struct match *md, struct ofpbuf *userdata)
{
    /* This action only works for TCP segments, and the switch should only send
     * us TCP segments this way, but check here just to be sure. */
    if (ip_flow->nw_proto != IPPROTO_TCP) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "TCP_RESET action on non-TCP packet");
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;

    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    dp_packet_clear(&packet);
    packet.packet_type = htonl(PT_ETH);

    struct eth_header *eh = dp_packet_put_zeros(&packet, sizeof *eh);
    eh->eth_dst = ip_flow->dl_dst;
    eh->eth_src = ip_flow->dl_src;

    if (get_dl_type(ip_flow) == htons(ETH_TYPE_IPV6)) {
        struct ip6_hdr *nh = dp_packet_put_zeros(&packet, sizeof *nh);

        eh->eth_type = htons(ETH_TYPE_IPV6);
        dp_packet_set_l3(&packet, nh);
        nh->ip6_vfc = 0x60;
        nh->ip6_nxt = IPPROTO_TCP;
        nh->ip6_plen = htons(TCP_HEADER_LEN);
        packet_set_ipv6(&packet, &ip_flow->ipv6_src, &ip_flow->ipv6_dst,
                        ip_flow->nw_tos, ip_flow->ipv6_label, 255);
    } else {
        struct ip_header *nh = dp_packet_put_zeros(&packet, sizeof *nh);

        eh->eth_type = htons(ETH_TYPE_IP);
        dp_packet_set_l3(&packet, nh);
        nh->ip_ihl_ver = IP_IHL_VER(5, 4);
        nh->ip_tot_len = htons(IP_HEADER_LEN + TCP_HEADER_LEN);
        nh->ip_proto = IPPROTO_TCP;
        nh->ip_frag_off = htons(IP_DF);
        packet_set_ipv4(&packet, ip_flow->nw_src, ip_flow->nw_dst,
                        ip_flow->nw_tos, 255);
    }

    struct tcp_header *th = dp_packet_put_zeros(&packet, sizeof *th);
    struct tcp_header *tcp_in = dp_packet_l4(pkt_in);
    dp_packet_set_l4(&packet, th);
    th->tcp_ctl = TCP_CTL(TCP_RST, 5);
    if (ip_flow->tcp_flags & htons(TCP_ACK)) {
        th->tcp_seq = tcp_in->tcp_ack;
    } else {
        uint32_t tcp_seq, ack_seq, tcp_len;

        tcp_seq = ntohl(get_16aligned_be32(&tcp_in->tcp_seq));
        tcp_len = TCP_OFFSET(tcp_in->tcp_ctl) * 4;
        ack_seq = tcp_seq + dp_packet_l4_size(pkt_in) - tcp_len;
        put_16aligned_be32(&th->tcp_ack, htonl(ack_seq));
        put_16aligned_be32(&th->tcp_seq, 0);
    }
    packet_set_tcp_port(&packet, ip_flow->tp_dst, ip_flow->tp_src);

    if (ip_flow->vlans[0].tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q),
                      ip_flow->vlans[0].tci);
    }

    set_actions_and_enqueue_msg(&packet, md, userdata);
    dp_packet_uninit(&packet);
}

static void
pinctrl_handle_put_dhcp_opts(
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct ofpbuf *userdata, struct ofpbuf *continuation)
{
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    /* Parse result offset and offer IP. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    ovs_be32 *offer_ip = ofpbuf_try_pull(userdata, sizeof *offer_ip);
    if (!ofsp || !offer_ip) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "offset or offer_ip not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "DHCP options not present in the userdata");
        goto exit;
    }

    /* Validate the DHCP request packet.
     * Format of the DHCP packet is
     * ------------------------------------------------------------------------
     *| UDP HEADER  | DHCP HEADER  | 4 Byte DHCP Cookie | DHCP OPTIONS(var len)|
     * ------------------------------------------------------------------------
     */
    if (dp_packet_l4_size(pkt_in) < (UDP_HEADER_LEN +
        sizeof (struct dhcp_header) + sizeof(uint32_t) + 3)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid or incomplete DHCP packet recieved");
        goto exit;
    }

    struct dhcp_header const *in_dhcp_data = dp_packet_get_udp_payload(pkt_in);
    if (in_dhcp_data->op != DHCP_OP_REQUEST) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid opcode in the DHCP packet : %d",
                     in_dhcp_data->op);
        goto exit;
    }

    /* DHCP options follow the DHCP header. The first 4 bytes of the DHCP
     * options is the DHCP magic cookie followed by the actual DHCP options.
     */
    const uint8_t *in_dhcp_opt =
        (const uint8_t *)dp_packet_get_udp_payload(pkt_in) +
        sizeof (struct dhcp_header);

    ovs_be32 magic_cookie = htonl(DHCP_MAGIC_COOKIE);
    if (memcmp(in_dhcp_opt, &magic_cookie, sizeof(ovs_be32))) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "DHCP magic cookie not present in the DHCP packet");
        goto exit;
    }

    in_dhcp_opt += 4;
    /* Check that the DHCP Message Type (opt 53) is present or not with
     * valid values - DHCP_MSG_DISCOVER or DHCP_MSG_REQUEST as the first
     * DHCP option.
     */
    if (!(in_dhcp_opt[0] == DHCP_OPT_MSG_TYPE && in_dhcp_opt[1] == 1 && (
            in_dhcp_opt[2] == DHCP_MSG_DISCOVER ||
            in_dhcp_opt[2] == DHCP_MSG_REQUEST))) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "Invalid DHCP message type : opt code = %d,"
                     " opt value = %d", in_dhcp_opt[0], in_dhcp_opt[2]);
        goto exit;
    }

    uint8_t msg_type;
    if (in_dhcp_opt[2] == DHCP_MSG_DISCOVER) {
        msg_type = DHCP_MSG_OFFER;
    } else {
        msg_type = DHCP_MSG_ACK;
    }

    /* Frame the DHCP reply packet
     * Total DHCP options length will be options stored in the userdata +
     * 16 bytes.
     *
     * --------------------------------------------------------------
     *| 4 Bytes (dhcp cookie) | 3 Bytes (option type) | DHCP options |
     * --------------------------------------------------------------
     *| 4 Bytes padding | 1 Byte (option end 0xFF ) | 4 Bytes padding|
     * --------------------------------------------------------------
     */
    uint16_t new_l4_size = UDP_HEADER_LEN + DHCP_HEADER_LEN + \
                           userdata->size + 16;
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;

    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy the L2 and L3 headers from the pkt_in as they would remain same*/
    dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs), pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    struct udp_header *udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);

    struct dhcp_header *dhcp_data = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, DHCP_HEADER_LEN), DHCP_HEADER_LEN);
    dhcp_data->op = DHCP_OP_REPLY;
    dhcp_data->yiaddr = *offer_ip;
    dp_packet_put(&pkt_out, &magic_cookie, sizeof(ovs_be32));

    uint8_t *out_dhcp_opts = dp_packet_put_zeros(&pkt_out,
                                                 userdata->size + 12);
    /* DHCP option - type */
    out_dhcp_opts[0] = DHCP_OPT_MSG_TYPE;
    out_dhcp_opts[1] = 1;
    out_dhcp_opts[2] = msg_type;
    out_dhcp_opts += 3;

    memcpy(out_dhcp_opts, userdata->data, userdata->size);
    out_dhcp_opts += userdata->size;
    /* Padding */
    out_dhcp_opts += 4;
    /* End */
    out_dhcp_opts[0] = DHCP_OPT_END;

    udp->udp_len = htons(new_l4_size);

    struct ip_header *out_ip = dp_packet_l3(&pkt_out);
    out_ip->ip_tot_len = htons(pkt_out.l4_ofs - pkt_out.l3_ofs + new_l4_size);
    udp->udp_csum = 0;
    /* Checksum needs to be initialized to zero. */
    out_ip->ip_csum = 0;
    out_ip->ip_csum = csum(out_ip, sizeof *out_ip);

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);

    /* Log the response. */
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(20, 40);
    const struct eth_header *l2 = dp_packet_eth(&pkt_out);
    VLOG_INFO_RL(&rl, "DHCP%s "ETH_ADDR_FMT" "IP_FMT"",
                 msg_type == DHCP_MSG_OFFER ? "OFFER" : "ACK",
                 ETH_ADDR_ARGS(l2->eth_src), IP_ARGS(*offer_ip));

    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(ofputil_encode_resume(pin, continuation, proto));
    if (pkt_out_ptr) {
        dp_packet_uninit(pkt_out_ptr);
    }
}

static bool
compose_out_dhcpv6_opts(struct ofpbuf *userdata,
                        struct ofpbuf *out_dhcpv6_opts, ovs_be32 iaid)
{
    while (userdata->size) {
        struct dhcp_opt6_header *userdata_opt = ofpbuf_try_pull(
            userdata, sizeof *userdata_opt);
        if (!userdata_opt) {
            return false;
        }

        size_t size = ntohs(userdata_opt->size);
        uint8_t *userdata_opt_data = ofpbuf_try_pull(userdata, size);
        if (!userdata_opt_data) {
            return false;
        }

        switch (ntohs(userdata_opt->opt_code)) {
        case DHCPV6_OPT_SERVER_ID_CODE:
        {
            /* The Server Identifier option carries a DUID
             * identifying a server between a client and a server.
             * See RFC 3315 Sec 9 and Sec 22.3.
             *
             * We use DUID Based on Link-layer Address [DUID-LL].
             */

            struct dhcpv6_opt_server_id *opt_server_id = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_server_id);

            opt_server_id->opt.code = htons(DHCPV6_OPT_SERVER_ID_CODE);
            opt_server_id->opt.len = htons(size + 4);
            opt_server_id->duid_type = htons(DHCPV6_DUID_LL);
            opt_server_id->hw_type = htons(DHCPV6_HW_TYPE_ETH);
            memcpy(&opt_server_id->mac, userdata_opt_data,
                    sizeof(struct eth_addr));
            break;
        }

        case DHCPV6_OPT_IA_ADDR_CODE:
        {
            if (size != sizeof(struct in6_addr)) {
                return false;
            }

            /* IA Address option is used to specify IPv6 addresses associated
             * with an IA_NA or IA_TA. The IA Address option must be
             * encapsulated in the Options field of an IA_NA or IA_TA option.
             *
             * We will encapsulate the IA Address within the IA_NA option.
             * Please see RFC 3315 section 22.5 and 22.6
             */
            struct dhcpv6_opt_ia_na *opt_ia_na = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_ia_na);
            opt_ia_na->opt.code = htons(DHCPV6_OPT_IA_NA_CODE);
            /* IA_NA length (in bytes)-
             *  IAID - 4
             *  T1   - 4
             *  T2   - 4
             *  IA Address - sizeof(struct dhcpv6_opt_ia_addr)
             */
            opt_ia_na->opt.len = htons(12 + sizeof(struct dhcpv6_opt_ia_addr));
            opt_ia_na->iaid = iaid;
            /* Set the lifetime of the address(es) to infinity */
            opt_ia_na->t1 = OVS_BE32_MAX;
            opt_ia_na->t2 = OVS_BE32_MAX;

            struct dhcpv6_opt_ia_addr *opt_ia_addr = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_ia_addr);
            opt_ia_addr->opt.code = htons(DHCPV6_OPT_IA_ADDR_CODE);
            opt_ia_addr->opt.len = htons(size + 8);
            memcpy(opt_ia_addr->ipv6.s6_addr, userdata_opt_data, size);
            opt_ia_addr->t1 = OVS_BE32_MAX;
            opt_ia_addr->t2 = OVS_BE32_MAX;
            break;
        }

        case DHCPV6_OPT_DNS_SERVER_CODE:
        {
            struct dhcpv6_opt_header *opt_dns = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_dns);
            opt_dns->code = htons(DHCPV6_OPT_DNS_SERVER_CODE);
            opt_dns->len = htons(size);
            ofpbuf_put(out_dhcpv6_opts, userdata_opt_data, size);
            break;
        }

        case DHCPV6_OPT_DOMAIN_SEARCH_CODE:
        {
            struct dhcpv6_opt_header *opt_dsl = ofpbuf_put_zeros(
                out_dhcpv6_opts, sizeof *opt_dsl);
            opt_dsl->code = htons(DHCPV6_OPT_DOMAIN_SEARCH_CODE);
            opt_dsl->len = htons(size + 2);
            uint8_t *data = ofpbuf_put_zeros(out_dhcpv6_opts, size + 2);
            *data = size;
            memcpy(data + 1, userdata_opt_data, size);
            break;
        }

        default:
            return false;
        }
    }
    return true;
}

static void
pinctrl_handle_put_dhcpv6_opts(
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct ofpbuf *userdata, struct ofpbuf *continuation OVS_UNUSED)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        VLOG_WARN_RL(&rl, "DHCPv6 options not present in the userdata");
        goto exit;
    }

    struct udp_header *in_udp = dp_packet_l4(pkt_in);
    const uint8_t *in_dhcpv6_data = dp_packet_get_udp_payload(pkt_in);
    if (!in_udp || !in_dhcpv6_data) {
        VLOG_WARN_RL(&rl, "truncated dhcpv6 packet");
        goto exit;
    }

    uint8_t out_dhcpv6_msg_type;
    switch(*in_dhcpv6_data) {
    case DHCPV6_MSG_TYPE_SOLICIT:
        out_dhcpv6_msg_type = DHCPV6_MSG_TYPE_ADVT;
        break;

    case DHCPV6_MSG_TYPE_REQUEST:
    case DHCPV6_MSG_TYPE_CONFIRM:
    case DHCPV6_MSG_TYPE_DECLINE:
        out_dhcpv6_msg_type = DHCPV6_MSG_TYPE_REPLY;
        break;

    default:
        /* Invalid or unsupported DHCPv6 message type */
        goto exit;
    }

    /* Skip 4 bytes (message type (1 byte) + transaction ID (3 bytes). */
    in_dhcpv6_data += 4;
    /* We need to extract IAID from the IA-NA option of the client's DHCPv6
     * solicit/request/confirm packet and copy the same IAID in the Server's
     * response. */
    ovs_be32 iaid = 0;
    struct dhcpv6_opt_header const *in_opt_client_id = NULL;
    size_t udp_len = ntohs(in_udp->udp_len);
    size_t l4_len = dp_packet_l4_size(pkt_in);
    uint8_t *end = (uint8_t *)in_udp + MIN(udp_len, l4_len);
    while (in_dhcpv6_data < end) {
        struct dhcpv6_opt_header const *in_opt =
             (struct dhcpv6_opt_header *)in_dhcpv6_data;
        switch(ntohs(in_opt->code)) {
        case DHCPV6_OPT_IA_NA_CODE:
        {
            struct dhcpv6_opt_ia_na *opt_ia_na = (
                struct dhcpv6_opt_ia_na *)in_opt;
            iaid = opt_ia_na->iaid;
            break;
        }

        case DHCPV6_OPT_CLIENT_ID_CODE:
            in_opt_client_id = in_opt;
            break;

        default:
            break;
        }
        in_dhcpv6_data += sizeof *in_opt + ntohs(in_opt->len);
    }

    if (!in_opt_client_id) {
        VLOG_WARN_RL(&rl, "DHCPv6 option - Client id not present in the "
                     " DHCPv6 packet");
        goto exit;
    }

    if (!iaid) {
        VLOG_WARN_RL(&rl, "DHCPv6 option - IA NA not present in the "
                     " DHCPv6 packet");
        goto exit;
    }

    uint64_t out_ofpacts_dhcpv6_opts_stub[256 / 8];
    struct ofpbuf out_dhcpv6_opts =
        OFPBUF_STUB_INITIALIZER(out_ofpacts_dhcpv6_opts_stub);

    if (!compose_out_dhcpv6_opts(userdata, &out_dhcpv6_opts, iaid)) {
        VLOG_WARN_RL(&rl, "Invalid userdata");
        goto exit;
    }

    uint16_t new_l4_size
        = (UDP_HEADER_LEN + 4 + sizeof *in_opt_client_id +
           ntohs(in_opt_client_id->len) + out_dhcpv6_opts.size);
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;

    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy L2 and L3 headers from pkt_in. */
    dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs),
                  pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    /* Pull the DHCPv6 message type and transaction id from the pkt_in.
     * Need to preserve the transaction id in the DHCPv6 reply packet. */
    struct udp_header *out_udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);
    uint8_t *out_dhcpv6 = dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, 4), 4);

    /* Set the proper DHCPv6 message type. */
    *out_dhcpv6 = out_dhcpv6_msg_type;

    /* Copy the Client Identifier. */
    dp_packet_put(&pkt_out, in_opt_client_id,
                  sizeof *in_opt_client_id + ntohs(in_opt_client_id->len));

    /* Copy the DHCPv6 Options. */
    dp_packet_put(&pkt_out, out_dhcpv6_opts.data, out_dhcpv6_opts.size);
    out_udp->udp_len = htons(new_l4_size);
    out_udp->udp_csum = 0;

    struct ovs_16aligned_ip6_hdr *out_ip6 = dp_packet_l3(&pkt_out);
    out_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = out_udp->udp_len;

    uint32_t csum;
    csum = packet_csum_pseudoheader6(dp_packet_l3(&pkt_out));
    csum = csum_continue(csum, out_udp, dp_packet_size(&pkt_out) -
                         ((const unsigned char *)out_udp -
                         (const unsigned char *)dp_packet_eth(&pkt_out)));
    out_udp->udp_csum = csum_finish(csum);
    if (!out_udp->udp_csum) {
        out_udp->udp_csum = htons(0xffff);
    }

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);
    ofpbuf_uninit(&out_dhcpv6_opts);
    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}

static void
put_be16(struct ofpbuf *buf, ovs_be16 x)
{
    ofpbuf_put(buf, &x, sizeof x);
}

static void
put_be32(struct ofpbuf *buf, ovs_be32 x)
{
    ofpbuf_put(buf, &x, sizeof x);
}

static void
pinctrl_handle_dns_lookup(
    struct dp_packet *pkt_in, struct ofputil_packet_in *pin,
    struct ofpbuf *userdata, struct ofpbuf *continuation,
    struct controller_ctx *ctx)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    /* Extract the DNS header */
    struct dns_header const *in_dns_header = dp_packet_get_udp_payload(pkt_in);
    if (!in_dns_header) {
        VLOG_WARN_RL(&rl, "truncated dns packet");
        goto exit;
    }

    /* Check if it is DNS request or not */
    if (in_dns_header->lo_flag & 0x80) {
        /* It's a DNS response packet which we are not interested in */
        goto exit;
    }

    /* Check if at least one query request is present */
    if (!in_dns_header->qdcount) {
        goto exit;
    }

    struct udp_header *in_udp = dp_packet_l4(pkt_in);
    size_t udp_len = ntohs(in_udp->udp_len);
    size_t l4_len = dp_packet_l4_size(pkt_in);
    uint8_t *end = (uint8_t *)in_udp + MIN(udp_len, l4_len);
    uint8_t *in_dns_data = (uint8_t *)(in_dns_header + 1);
    uint8_t *in_queryname = in_dns_data;
    uint8_t idx = 0;
    struct ds query_name;
    ds_init(&query_name);
    /* Extract the query_name. If the query name is - 'www.ovn.org' it would be
     * encoded as (in hex) - 03 77 77 77 03 6f 76 63 03 6f 72 67 00.
     */
    while ((in_dns_data + idx) < end && in_dns_data[idx]) {
        uint8_t label_len = in_dns_data[idx++];
        if (in_dns_data + idx + label_len > end) {
            ds_destroy(&query_name);
            goto exit;
        }
        ds_put_buffer(&query_name, (const char *) in_dns_data + idx, label_len);
        idx += label_len;
        ds_put_char(&query_name, '.');
    }

    idx++;
    ds_chomp(&query_name, '.');
    in_dns_data += idx;

    /* Query should have TYPE and CLASS fields */
    if (in_dns_data + (2 * sizeof(ovs_be16)) > end) {
        ds_destroy(&query_name);
        goto exit;
    }

    uint16_t query_type = ntohs(*ALIGNED_CAST(const ovs_be16 *, in_dns_data));
    /* Supported query types - A, AAAA and ANY */
    if (!(query_type == DNS_QUERY_TYPE_A || query_type == DNS_QUERY_TYPE_AAAA
          || query_type == DNS_QUERY_TYPE_ANY)) {
        ds_destroy(&query_name);
        goto exit;
    }

    uint64_t dp_key = ntohll(pin->flow_metadata.flow.metadata);
    const struct sbrec_dns *sbrec_dns;
    const char *answer_ips = NULL;
    SBREC_DNS_FOR_EACH(sbrec_dns, ctx->ovnsb_idl) {
        for (size_t i = 0; i < sbrec_dns->n_datapaths; i++) {
            if (sbrec_dns->datapaths[i]->tunnel_key == dp_key) {
                answer_ips = smap_get(&sbrec_dns->records,
                                      ds_cstr(&query_name));
                if (answer_ips) {
                    break;
                }
            }
        }

        if (answer_ips) {
            break;
        }
    }

    ds_destroy(&query_name);
    if (!answer_ips) {
        goto exit;
    }

    struct lport_addresses ip_addrs;
    if (!extract_ip_addresses(answer_ips, &ip_addrs)) {
        goto exit;
    }

    uint16_t ancount = 0;
    uint64_t dns_ans_stub[128 / 8];
    struct ofpbuf dns_answer = OFPBUF_STUB_INITIALIZER(dns_ans_stub);

    if (query_type == DNS_QUERY_TYPE_A || query_type == DNS_QUERY_TYPE_ANY) {
        for (size_t i = 0; i < ip_addrs.n_ipv4_addrs; i++) {
            /* Copy the answer section */
            /* Format of the answer section is
             *  - NAME     -> The domain name
             *  - TYPE     -> 2 octets containing one of the RR type codes
             *  - CLASS    -> 2 octets which specify the class of the data
             *                in the RDATA field.
             *  - TTL      -> 32 bit unsigned int specifying the time
             *                interval (in secs) that the resource record
             *                 may be cached before it should be discarded.
             *  - RDLENGTH -> 16 bit integer specifying the length of the
             *                RDATA field.
             *  - RDATA    -> a variable length string of octets that
             *                describes the resource. In our case it will
             *                be IP address of the domain name.
             */
            ofpbuf_put(&dns_answer, in_queryname, idx);
            put_be16(&dns_answer, htons(DNS_QUERY_TYPE_A));
            put_be16(&dns_answer, htons(DNS_CLASS_IN));
            put_be32(&dns_answer, htonl(DNS_DEFAULT_RR_TTL));
            put_be16(&dns_answer, htons(sizeof(ovs_be32)));
            put_be32(&dns_answer, ip_addrs.ipv4_addrs[i].addr);
            ancount++;
        }
    }

    if (query_type == DNS_QUERY_TYPE_AAAA ||
        query_type == DNS_QUERY_TYPE_ANY) {
        for (size_t i = 0; i < ip_addrs.n_ipv6_addrs; i++) {
            ofpbuf_put(&dns_answer, in_queryname, idx);
            put_be16(&dns_answer, htons(DNS_QUERY_TYPE_AAAA));
            put_be16(&dns_answer, htons(DNS_CLASS_IN));
            put_be32(&dns_answer, htonl(DNS_DEFAULT_RR_TTL));
            const struct in6_addr *ip6 = &ip_addrs.ipv6_addrs[i].addr;
            put_be16(&dns_answer, htons(sizeof *ip6));
            ofpbuf_put(&dns_answer, ip6, sizeof *ip6);
            ancount++;
        }
    }

    destroy_lport_addresses(&ip_addrs);

    if (!ancount) {
        ofpbuf_uninit(&dns_answer);
        goto exit;
    }

    uint16_t new_l4_size = ntohs(in_udp->udp_len) +  dns_answer.size;
    size_t new_packet_size = pkt_in->l4_ofs + new_l4_size;
    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy the L2 and L3 headers from the pkt_in as they would remain same.*/
    dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs), pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    struct udp_header *out_udp = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, UDP_HEADER_LEN), UDP_HEADER_LEN);

    /* Copy the DNS header. */
    struct dns_header *out_dns_header = dp_packet_put(
        &pkt_out, dp_packet_pull(pkt_in, sizeof *out_dns_header),
        sizeof *out_dns_header);

    /* Set the response bit to 1 in the flags. */
    out_dns_header->lo_flag |= 0x80;

    /* Set the answer RR. */
    out_dns_header->ancount = htons(ancount);

    /* Copy the Query section. */
    dp_packet_put(&pkt_out, dp_packet_data(pkt_in), dp_packet_size(pkt_in));

    /* Copy the answer sections. */
    dp_packet_put(&pkt_out, dns_answer.data, dns_answer.size);
    ofpbuf_uninit(&dns_answer);

    out_udp->udp_len = htons(new_l4_size);
    out_udp->udp_csum = 0;

    struct eth_header *eth = dp_packet_data(&pkt_out);
    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        struct ip_header *out_ip = dp_packet_l3(&pkt_out);
        out_ip->ip_tot_len = htons(pkt_out.l4_ofs - pkt_out.l3_ofs
                                   + new_l4_size);
        /* Checksum needs to be initialized to zero. */
        out_ip->ip_csum = 0;
        out_ip->ip_csum = csum(out_ip, sizeof *out_ip);
    } else {
        struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(&pkt_out);
        nh->ip6_plen = htons(new_l4_size);

        /* IPv6 needs UDP checksum calculated */
        uint32_t csum;
        csum = packet_csum_pseudoheader6(nh);
        csum = csum_continue(csum, out_udp, dp_packet_size(&pkt_out) -
                             ((const unsigned char *)out_udp -
                             (const unsigned char *)eth));
        out_udp->udp_csum = csum_finish(csum);
        if (!out_udp->udp_csum) {
            out_udp->udp_csum = htons(0xffff);
        }
    }

    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);

    success = 1;
exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}

static void
process_packet_in(const struct ofp_header *msg, struct controller_ctx *ctx)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    struct ofputil_packet_in pin;
    struct ofpbuf continuation;
    enum ofperr error = ofputil_decode_packet_in(msg, true, NULL, NULL, &pin,
                                                 NULL, NULL, &continuation);

    if (error) {
        VLOG_WARN_RL(&rl, "error decoding packet-in: %s",
                     ofperr_to_string(error));
        return;
    }
    if (pin.reason != OFPR_ACTION) {
        return;
    }

    struct ofpbuf userdata = ofpbuf_const_initializer(pin.userdata,
                                                      pin.userdata_len);
    const struct action_header *ah = ofpbuf_pull(&userdata, sizeof *ah);
    if (!ah) {
        VLOG_WARN_RL(&rl, "packet-in userdata lacks action header");
        return;
    }

    struct dp_packet packet;
    dp_packet_use_const(&packet, pin.packet, pin.packet_len);
    struct flow headers;
    flow_extract(&packet, &headers);

    switch (ntohl(ah->opcode)) {
    case ACTION_OPCODE_ARP:
        pinctrl_handle_arp(&headers, &pin.flow_metadata, &userdata);
        break;

    case ACTION_OPCODE_PUT_ARP:
        pinctrl_handle_put_mac_binding(&pin.flow_metadata.flow, &headers,
                                       true);
        break;

    case ACTION_OPCODE_PUT_DHCP_OPTS:
        pinctrl_handle_put_dhcp_opts(&packet, &pin, &userdata, &continuation);
        break;

    case ACTION_OPCODE_ND_NA:
        pinctrl_handle_nd_na(&headers, &pin.flow_metadata, &userdata);
        break;

    case ACTION_OPCODE_PUT_ND:
        pinctrl_handle_put_mac_binding(&pin.flow_metadata.flow, &headers,
                                       false);
        break;

    case ACTION_OPCODE_PUT_DHCPV6_OPTS:
        pinctrl_handle_put_dhcpv6_opts(&packet, &pin, &userdata,
                                       &continuation);
        break;

    case ACTION_OPCODE_DNS_LOOKUP:
        pinctrl_handle_dns_lookup(&packet, &pin, &userdata, &continuation, ctx);
        break;

    case ACTION_OPCODE_LOG:
        handle_acl_log(&headers, &userdata);
        break;

    case ACTION_OPCODE_PUT_ND_RA_OPTS:
        pinctrl_handle_put_nd_ra_opts(&headers, &packet, &pin, &userdata,
                                      &continuation);
        break;

    case ACTION_OPCODE_ND_NS:
        pinctrl_handle_nd_ns(&headers, &pin.flow_metadata, &userdata);
        break;

    case ACTION_OPCODE_ICMP:
        pinctrl_handle_icmp(&headers, &packet, &pin.flow_metadata,
                            &userdata);
        break;

    case ACTION_OPCODE_TCP_RESET:
        pinctrl_handle_tcp_reset(&headers, &packet, &pin.flow_metadata,
                                 &userdata);
        break;

    default:
        VLOG_WARN_RL(&rl, "unrecognized packet-in opcode %"PRIu32,
                     ntohl(ah->opcode));
        break;
    }
}

static void
pinctrl_recv(const struct ofp_header *oh, enum ofptype type,
             struct controller_ctx *ctx)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(ofputil_encode_echo_reply(oh));
    } else if (type == OFPTYPE_GET_CONFIG_REPLY) {
        /* Enable asynchronous messages */
        struct ofputil_switch_config config;

        ofputil_decode_get_config_reply(oh, &config);
        config.miss_send_len = UINT16_MAX;
        set_switch_config(swconn, &config);
    } else if (type == OFPTYPE_PACKET_IN) {
        process_packet_in(oh, ctx);
    } else {
        if (VLOG_IS_DBG_ENABLED()) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

            char *s = ofp_to_string(oh, ntohs(oh->length), NULL, NULL, 2);

            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
            free(s);
        }
    }
}

void
pinctrl_run(struct controller_ctx *ctx,
            const struct ovsrec_bridge *br_int,
            const struct sbrec_chassis *chassis,
            const struct chassis_index *chassis_index,
            struct hmap *local_datapaths,
            struct sset *active_tunnels)
{
    char *target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_int->name);
    if (strcmp(target, rconn_get_target(swconn))) {
        VLOG_INFO("%s: connecting to switch", target);
        rconn_connect(swconn, target, target);
    }
    free(target);

    rconn_run(swconn);

    if (!rconn_is_connected(swconn)) {
        return;
    }

    if (conn_seq_no != rconn_get_connection_seqno(swconn)) {
        pinctrl_setup();
        conn_seq_no = rconn_get_connection_seqno(swconn);
        flush_put_mac_bindings();
    }

    /* Process a limited number of messages per call. */
    for (int i = 0; i < 50; i++) {
        struct ofpbuf *msg = rconn_recv(swconn);
        if (!msg) {
            break;
        }

        const struct ofp_header *oh = msg->data;
        enum ofptype type;

        ofptype_decode(&type, oh);
        pinctrl_recv(oh, type, ctx);
        ofpbuf_delete(msg);
    }

    run_put_mac_bindings(ctx);
    send_garp_run(ctx, br_int, chassis, chassis_index, local_datapaths,
                  active_tunnels);
    send_ipv6_ras(ctx, local_datapaths);
}

/* Table of ipv6_ra_state structures, keyed on logical port name */
static struct shash ipv6_ras;

/* Next IPV6 RA in seconds. */
static long long int send_ipv6_ra_time;

struct ipv6_ra_config {
    time_t min_interval;
    time_t max_interval;
    struct eth_addr eth_src;
    struct eth_addr eth_dst;
    struct in6_addr ipv6_src;
    struct in6_addr ipv6_dst;
    int32_t mtu;
    uint8_t mo_flags; /* Managed/Other flags for RAs */
    uint8_t la_flags; /* On-link/autonomous flags for address prefixes */
    struct lport_addresses prefixes;
};

struct ipv6_ra_state {
    long long int next_announce;
    struct ipv6_ra_config *config;
    int64_t port_key;
    int64_t metadata;
    bool delete_me;
};

static void
init_ipv6_ras(void)
{
    shash_init(&ipv6_ras);
    send_ipv6_ra_time = LLONG_MAX;
}

static void
ipv6_ra_config_delete(struct ipv6_ra_config *config)
{
    if (config) {
        destroy_lport_addresses(&config->prefixes);
        free(config);
    }
}

static void
ipv6_ra_delete(struct ipv6_ra_state *ra)
{
    if (ra) {
        ipv6_ra_config_delete(ra->config);
        free(ra);
    }
}

static void
destroy_ipv6_ras(void)
{
    struct shash_node *iter, *next;
    SHASH_FOR_EACH_SAFE (iter, next, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        ipv6_ra_delete(ra);
        shash_delete(&ipv6_ras, iter);
    }
    shash_destroy(&ipv6_ras);
}

static struct ipv6_ra_config *
ipv6_ra_update_config(const struct sbrec_port_binding *pb)
{
    struct ipv6_ra_config *config;

    config = xzalloc(sizeof *config);

    config->max_interval = smap_get_int(&pb->options, "ipv6_ra_max_interval",
            ND_RA_MAX_INTERVAL_DEFAULT);
    config->min_interval = smap_get_int(&pb->options, "ipv6_ra_min_interval",
            nd_ra_min_interval_default(config->max_interval));
    config->mtu = smap_get_int(&pb->options, "ipv6_ra_mtu", ND_MTU_DEFAULT);
    config->la_flags = ND_PREFIX_ON_LINK;

    const char *address_mode = smap_get(&pb->options, "ipv6_ra_address_mode");
    if (!address_mode) {
        VLOG_WARN("No address mode specified");
        goto fail;
    }
    if (!strcmp(address_mode, "dhcpv6_stateless")) {
        config->mo_flags = IPV6_ND_RA_FLAG_OTHER_ADDR_CONFIG;
    } else if (!strcmp(address_mode, "dhcpv6_stateful")) {
        config->mo_flags = IPV6_ND_RA_FLAG_MANAGED_ADDR_CONFIG;
    } else if (!strcmp(address_mode, "slaac")) {
        config->la_flags |= ND_PREFIX_AUTONOMOUS_ADDRESS;
    } else {
        VLOG_WARN("Invalid address mode %s", address_mode);
        goto fail;
    }

    const char *prefixes = smap_get(&pb->options, "ipv6_ra_prefixes");
    if (prefixes && !extract_ip_addresses(prefixes, &config->prefixes)) {
        VLOG_WARN("Invalid IPv6 prefixes: %s", prefixes);
        goto fail;
    }

    /* All nodes multicast addresses */
    config->eth_dst = (struct eth_addr) ETH_ADDR_C(33,33,00,00,00,01);
    ipv6_parse("ff02::1", &config->ipv6_dst);

    const char *eth_addr = smap_get(&pb->options, "ipv6_ra_src_eth");
    if (!eth_addr || !eth_addr_from_string(eth_addr, &config->eth_src)) {
        VLOG_WARN("Invalid ethernet source %s", eth_addr);
        goto fail;
    }
    const char *ip_addr = smap_get(&pb->options, "ipv6_ra_src_addr");
    if (!ip_addr || !ipv6_parse(ip_addr, &config->ipv6_src)) {
        VLOG_WARN("Invalid IP source %s", ip_addr);
        goto fail;
    }

    return config;

fail:
    ipv6_ra_config_delete(config);
    return NULL;
}

static long long int
ipv6_ra_calc_next_announce(time_t min_interval, time_t max_interval)
{
    long long int min_interval_ms = min_interval * 1000LL;
    long long int max_interval_ms = max_interval * 1000LL;

    return time_msec() + min_interval_ms +
        random_range(max_interval_ms - min_interval_ms);
}

static void
put_load(uint64_t value, enum mf_field_id dst, int ofs, int n_bits,
         struct ofpbuf *ofpacts)
{
    struct ofpact_set_field *sf = ofpact_put_set_field(ofpacts,
                                                       mf_from_id(dst), NULL,
                                                       NULL);
    ovs_be64 n_value = htonll(value);
    bitwise_copy(&n_value, 8, 0, sf->value, sf->field->n_bytes, ofs, n_bits);
    bitwise_one(ofpact_set_field_mask(sf), sf->field->n_bytes, ofs, n_bits);
}

static long long int
ipv6_ra_send(struct ipv6_ra_state *ra)
{
    if (time_msec() < ra->next_announce) {
        return ra->next_announce;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_nd_ra(&packet, ra->config->eth_src, ra->config->eth_dst,
            &ra->config->ipv6_src, &ra->config->ipv6_dst,
            255, ra->config->mo_flags, 0, 0, 0, ra->config->mtu);

    for (int i = 0; i < ra->config->prefixes.n_ipv6_addrs; i++) {
        ovs_be128 addr;
        memcpy(&addr, &ra->config->prefixes.ipv6_addrs[i].addr, sizeof addr);
        packet_put_ra_prefix_opt(&packet,
            ra->config->prefixes.ipv6_addrs[i].plen,
            ra->config->la_flags, htonl(IPV6_ND_RA_OPT_PREFIX_VALID_LIFETIME),
            htonl(IPV6_ND_RA_OPT_PREFIX_PREFERRED_LIFETIME), addr);
    }

    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);

    /* Set MFF_LOG_DATAPATH and MFF_LOG_INPORT. */
    uint32_t dp_key = ra->metadata;
    uint32_t port_key = ra->port_key;
    put_load(dp_key, MFF_LOG_DATAPATH, 0, 64, &ofpacts);
    put_load(port_key, MFF_LOG_INPORT, 0, 32, &ofpacts);
    put_load(1, MFF_LOG_FLAGS, MLF_LOCAL_ONLY_BIT, 1, &ofpacts);
    struct ofpact_resubmit *resubmit = ofpact_put_RESUBMIT(&ofpacts);
    resubmit->in_port = OFPP_CONTROLLER;
    resubmit->table_id = OFTABLE_LOG_INGRESS_PIPELINE;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };

    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

    ra->next_announce = ipv6_ra_calc_next_announce(ra->config->min_interval,
            ra->config->max_interval);

    return ra->next_announce;
}

static void
ipv6_ra_wait(void)
{
    poll_timer_wait_until(send_ipv6_ra_time);
}

static void
send_ipv6_ras(const struct controller_ctx *ctx, struct hmap *local_datapaths)
{
    struct shash_node *iter, *iter_next;

    send_ipv6_ra_time = LLONG_MAX;

    SHASH_FOR_EACH (iter, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        ra->delete_me = true;
    }

    const struct local_datapath *ld;
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        struct sbrec_port_binding *lpval;
        const struct sbrec_port_binding *pb;
        struct ovsdb_idl_index_cursor cursor;

        lpval = sbrec_port_binding_index_init_row(ctx->ovnsb_idl,
                                                  &sbrec_table_port_binding);
        sbrec_port_binding_index_set_datapath(lpval, ld->datapath);
        ovsdb_idl_initialize_cursor(ctx->ovnsb_idl, &sbrec_table_port_binding,
                                    "lport-by-datapath", &cursor);
        SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, &cursor, lpval) {
            if (!smap_get_bool(&pb->options, "ipv6_ra_send_periodic", false)) {
                continue;
            }

            const char *peer_s = smap_get(&pb->options, "peer");
            if (!peer_s) {
                continue;
            }

            const struct sbrec_port_binding *peer
                = lport_lookup_by_name(ctx->ovnsb_idl, peer_s);
            if (!peer) {
                continue;
            }

            struct ipv6_ra_config *config = ipv6_ra_update_config(pb);
            if (!config) {
                continue;
            }

            struct ipv6_ra_state *ra
                = shash_find_data(&ipv6_ras, pb->logical_port);
            if (!ra) {
                ra = xzalloc(sizeof *ra);
                ra->config = config;
                ra->next_announce = ipv6_ra_calc_next_announce(
                    ra->config->min_interval,
                    ra->config->max_interval);
                shash_add(&ipv6_ras, pb->logical_port, ra);
            } else {
                ipv6_ra_config_delete(ra->config);
                ra->config = config;
            }

            /* Peer is the logical switch port that the logical
             * router port is connected to. The RA is injected
             * into that logical switch port.
             */
            ra->port_key = peer->tunnel_key;
            ra->metadata = peer->datapath->tunnel_key;
            ra->delete_me = false;

            long long int next_ra = ipv6_ra_send(ra);
            if (send_ipv6_ra_time > next_ra) {
                send_ipv6_ra_time = next_ra;
            }
        }
        sbrec_port_binding_index_destroy_row(lpval);
    }

    /* Remove those that are no longer in the SB database */
    SHASH_FOR_EACH_SAFE (iter, iter_next, &ipv6_ras) {
        struct ipv6_ra_state *ra = iter->data;
        if (ra->delete_me) {
            shash_delete(&ipv6_ras, iter);
            ipv6_ra_delete(ra);
        }
    }
}

void
pinctrl_wait(struct controller_ctx *ctx)
{
    wait_put_mac_bindings(ctx);
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);
    send_garp_wait();
    ipv6_ra_wait();
}

void
pinctrl_destroy(void)
{
    rconn_destroy(swconn);
    destroy_put_mac_bindings();
    destroy_send_garps();
    destroy_ipv6_ras();
}

/* Implementation of the "put_arp" and "put_nd" OVN actions.  These
 * actions send a packet to ovn-controller, using the flow as an API
 * (see actions.h for details).  This code implements the actions by
 * updating the MAC_Binding table in the southbound database.
 *
 * This code could be a lot simpler if the database could always be updated,
 * but in fact we can only update it when ctx->ovnsb_idl_txn is nonnull.  Thus,
 * we buffer up a few put_mac_bindings (but we don't keep them longer
 * than 1 second) and apply them whenever a database transaction is
 * available. */

/* Buffered "put_mac_binding" operation. */
struct put_mac_binding {
    struct hmap_node hmap_node; /* In 'put_mac_bindings'. */

    long long int timestamp;    /* In milliseconds. */

    /* Key. */
    uint32_t dp_key;
    uint32_t port_key;
    char ip_s[INET6_ADDRSTRLEN + 1];

    /* Value. */
    struct eth_addr mac;
};

/* Contains "struct put_mac_binding"s. */
static struct hmap put_mac_bindings;

static void
init_put_mac_bindings(void)
{
    hmap_init(&put_mac_bindings);
}

static void
destroy_put_mac_bindings(void)
{
    flush_put_mac_bindings();
    hmap_destroy(&put_mac_bindings);
}

static struct put_mac_binding *
pinctrl_find_put_mac_binding(uint32_t dp_key, uint32_t port_key,
                             const char *ip_s, uint32_t hash)
{
    struct put_mac_binding *pa;
    HMAP_FOR_EACH_WITH_HASH (pa, hmap_node, hash, &put_mac_bindings) {
        if (pa->dp_key == dp_key
            && pa->port_key == port_key
            && !strcmp(pa->ip_s, ip_s)) {
            return pa;
        }
    }
    return NULL;
}

static void
pinctrl_handle_put_mac_binding(const struct flow *md,
                               const struct flow *headers, bool is_arp)
{
    uint32_t dp_key = ntohll(md->metadata);
    uint32_t port_key = md->regs[MFF_LOG_INPORT - MFF_REG0];
    char ip_s[INET6_ADDRSTRLEN];

    if (is_arp) {
        ovs_be32 ip = htonl(md->regs[0]);
        inet_ntop(AF_INET, &ip, ip_s, sizeof(ip_s));
    } else {
        ovs_be128 ip6 = hton128(flow_get_xxreg(md, 0));
        inet_ntop(AF_INET6, &ip6, ip_s, sizeof(ip_s));
    }
    uint32_t hash = hash_string(ip_s, hash_2words(dp_key, port_key));
    struct put_mac_binding *pmb
        = pinctrl_find_put_mac_binding(dp_key, port_key, ip_s, hash);
    if (!pmb) {
        if (hmap_count(&put_mac_bindings) >= 1000) {
            COVERAGE_INC(pinctrl_drop_put_mac_binding);
            return;
        }

        pmb = xmalloc(sizeof *pmb);
        hmap_insert(&put_mac_bindings, &pmb->hmap_node, hash);
        pmb->dp_key = dp_key;
        pmb->port_key = port_key;
        ovs_strlcpy_arrays(pmb->ip_s, ip_s);
    }
    pmb->timestamp = time_msec();
    pmb->mac = headers->dl_src;
}

static void
run_put_mac_binding(struct controller_ctx *ctx,
                    const struct put_mac_binding *pmb)
{
    if (time_msec() > pmb->timestamp + 1000) {
        return;
    }

    /* Convert logical datapath and logical port key into lport. */
    const struct sbrec_port_binding *pb
        = lport_lookup_by_key(ctx->ovnsb_idl, pmb->dp_key, pmb->port_key);
    if (!pb) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_WARN_RL(&rl, "unknown logical port with datapath %"PRIu32" "
                     "and port %"PRIu32, pmb->dp_key, pmb->port_key);
        return;
    }

    /* Convert ethernet argument to string form for database. */
    char mac_string[ETH_ADDR_STRLEN + 1];
    snprintf(mac_string, sizeof mac_string,
             ETH_ADDR_FMT, ETH_ADDR_ARGS(pmb->mac));

    /* Check for an update an existing IP-MAC binding for this logical
     * port.
     *
     * XXX This is not very efficient. */
    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_FOR_EACH (b, ctx->ovnsb_idl) {
        if (!strcmp(b->logical_port, pb->logical_port)
            && !strcmp(b->ip, pmb->ip_s)) {
            if (strcmp(b->mac, mac_string)) {
                sbrec_mac_binding_set_mac(b, mac_string);
            }
            return;
        }
    }

    /* Add new IP-MAC binding for this logical port. */
    b = sbrec_mac_binding_insert(ctx->ovnsb_idl_txn);
    sbrec_mac_binding_set_logical_port(b, pb->logical_port);
    sbrec_mac_binding_set_ip(b, pmb->ip_s);
    sbrec_mac_binding_set_mac(b, mac_string);
    sbrec_mac_binding_set_datapath(b, pb->datapath);
}

static void
run_put_mac_bindings(struct controller_ctx *ctx)
{
    if (!ctx->ovnsb_idl_txn) {
        return;
    }

    const struct put_mac_binding *pmb;
    HMAP_FOR_EACH (pmb, hmap_node, &put_mac_bindings) {
        run_put_mac_binding(ctx, pmb);
    }
    flush_put_mac_bindings();
}

static void
wait_put_mac_bindings(struct controller_ctx *ctx)
{
    if (ctx->ovnsb_idl_txn && !hmap_is_empty(&put_mac_bindings)) {
        poll_immediate_wake();
    }
}

static void
flush_put_mac_bindings(void)
{
    struct put_mac_binding *pmb;
    HMAP_FOR_EACH_POP (pmb, hmap_node, &put_mac_bindings) {
        free(pmb);
    }
}

/*
 * Send gratuitous ARP for vif on localnet.
 *
 * When a new vif on localnet is added, gratuitous ARPs are sent announcing
 * the port's mac,ip mapping.  On localnet, such announcements are needed for
 * switches and routers on the broadcast segment to update their port-mac
 * and ARP tables.
 */
struct garp_data {
    struct eth_addr ea;          /* Ethernet address of port. */
    ovs_be32 ipv4;               /* Ipv4 address of port. */
    long long int announce_time; /* Next announcement in ms. */
    int backoff;                 /* Backoff for the next announcement. */
    ofp_port_t ofport;           /* ofport used to output this GARP. */
    int tag;                     /* VLAN tag of this GARP packet, or -1. */
};

/* Contains GARPs to be sent. */
static struct shash send_garp_data;

/* Next GARP announcement in ms. */
static long long int send_garp_time;

static void
init_send_garps(void)
{
    shash_init(&send_garp_data);
    send_garp_time = LLONG_MAX;
}

static void
destroy_send_garps(void)
{
    shash_destroy_free_data(&send_garp_data);
}

static void
add_garp(const char *name, ofp_port_t ofport, int tag,
         const struct eth_addr ea, ovs_be32 ip)
{
    struct garp_data *garp = xmalloc(sizeof *garp);
    garp->ea = ea;
    garp->ipv4 = ip;
    garp->announce_time = time_msec() + 1000;
    garp->backoff = 1;
    garp->ofport = ofport;
    garp->tag = tag;
    shash_add(&send_garp_data, name, garp);
}

/* Add or update a vif for which GARPs need to be announced. */
static void
send_garp_update(const struct sbrec_port_binding *binding_rec,
                 struct simap *localnet_ofports, struct hmap *local_datapaths,
                 struct shash *nat_addresses)
{
    /* Find the localnet ofport to send this GARP. */
    struct local_datapath *ld
        = get_local_datapath(local_datapaths,
                             binding_rec->datapath->tunnel_key);
    if (!ld || !ld->localnet_port) {
        return;
    }
    ofp_port_t ofport = u16_to_ofp(simap_get(localnet_ofports,
                                             ld->localnet_port->logical_port));
    int tag = ld->localnet_port->n_tag ? *ld->localnet_port->tag : -1;

    volatile struct garp_data *garp = NULL;
    /* Update GARP for NAT IP if it exists.  Consider port bindings with type
     * "l3gateway" for logical switch ports attached to gateway routers, and
     * port bindings with type "patch" for logical switch ports attached to
     * distributed gateway ports. */
    if (!strcmp(binding_rec->type, "l3gateway")
        || !strcmp(binding_rec->type, "patch")) {
        struct lport_addresses *laddrs = NULL;
        while ((laddrs = shash_find_and_delete(nat_addresses,
                                               binding_rec->logical_port))) {
            int i;
            for (i = 0; i < laddrs->n_ipv4_addrs; i++) {
                char *name = xasprintf("%s-%s", binding_rec->logical_port,
                                                laddrs->ipv4_addrs[i].addr_s);
                garp = shash_find_data(&send_garp_data, name);
                if (garp) {
                    garp->ofport = ofport;
                    garp->tag = tag;
                } else {
                    add_garp(name, ofport, tag, laddrs->ea,
                             laddrs->ipv4_addrs[i].addr);
                }
                free(name);
            }
            destroy_lport_addresses(laddrs);
            free(laddrs);
        }
        return;
    }

    /* Update GARP for vif if it exists. */
    garp = shash_find_data(&send_garp_data, binding_rec->logical_port);
    if (garp) {
        garp->ofport = ofport;
        return;
    }

    /* Add GARP for new vif. */
    int i;
    for (i = 0; i < binding_rec->n_mac; i++) {
        struct lport_addresses laddrs;
        if (!extract_lsp_addresses(binding_rec->mac[i], &laddrs)
            || !laddrs.n_ipv4_addrs) {
            continue;
        }

        add_garp(binding_rec->logical_port, ofport, tag,
                 laddrs.ea, laddrs.ipv4_addrs[0].addr);

        destroy_lport_addresses(&laddrs);
        break;
    }
}

/* Remove a vif from GARP announcements. */
static void
send_garp_delete(const char *lport)
{
    struct garp_data *garp = shash_find_and_delete(&send_garp_data, lport);
    free(garp);
}

static long long int
send_garp(struct garp_data *garp, long long int current_time)
{
    if (current_time < garp->announce_time) {
        return garp->announce_time;
    }

    /* Compose a GARP request packet. */
    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);
    compose_arp(&packet, ARP_OP_REQUEST, garp->ea, eth_addr_zero,
                true, garp->ipv4, garp->ipv4);

    /* Compose a GARP request packet's vlan if exist. */
    if (garp->tag >= 0) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN), htons(garp->tag));
    }

    /* Compose actions.  The garp request is output on localnet ofport. */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);
    ofpact_put_OUTPUT(&ofpacts)->port = garp->ofport;

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    match_set_in_port(&po.flow_metadata, OFPP_CONTROLLER);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(ofputil_encode_packet_out(&po, proto));
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);

    /* Set the next announcement.  At most 5 announcements are sent for a
     * vif. */
    if (garp->backoff < 16) {
        garp->backoff *= 2;
        garp->announce_time = current_time + garp->backoff * 1000;
    } else {
        garp->announce_time = LLONG_MAX;
    }
    return garp->announce_time;
}

/* Get localnet vifs, local l3gw ports and ofport for localnet patch ports. */
static void
get_localnet_vifs_l3gwports(struct controller_ctx *ctx,
                  const struct ovsrec_bridge *br_int,
                  const struct sbrec_chassis *chassis,
                  struct hmap *local_datapaths,
                  struct sset *localnet_vifs,
                  struct simap *localnet_ofports,
                  struct sset *local_l3gw_ports)
{
    for (int i = 0; i < br_int->n_ports; i++) {
        const struct ovsrec_port *port_rec = br_int->ports[i];
        if (!strcmp(port_rec->name, br_int->name)) {
            continue;
        }
        const char *chassis_id = smap_get(&port_rec->external_ids,
                                          "ovn-chassis-id");
        if (chassis_id && !strcmp(chassis_id, chassis->name)) {
            continue;
        }
        const char *localnet = smap_get(&port_rec->external_ids,
                                        "ovn-localnet-port");
        for (int j = 0; j < port_rec->n_interfaces; j++) {
            const struct ovsrec_interface *iface_rec = port_rec->interfaces[j];
            if (!iface_rec->n_ofport) {
                continue;
            }
            /* Get localnet port with its ofport. */
            if (localnet) {
                int64_t ofport = iface_rec->ofport[0];
                if (ofport < 1 || ofport > ofp_to_u16(OFPP_MAX)) {
                    continue;
                }
                simap_put(localnet_ofports, localnet, ofport);
                continue;
            }
            /* Get localnet vif. */
            const char *iface_id = smap_get(&iface_rec->external_ids,
                                            "iface-id");
            if (!iface_id) {
                continue;
            }
            const struct sbrec_port_binding *pb
                = lport_lookup_by_name(ctx->ovnsb_idl, iface_id);
            if (!pb) {
                continue;
            }
            struct local_datapath *ld
                = get_local_datapath(local_datapaths,
                                     pb->datapath->tunnel_key);
            if (ld && ld->localnet_port) {
                sset_add(localnet_vifs, iface_id);
            }
        }
    }

    const struct local_datapath *ld;
    struct ovsdb_idl_index_cursor cursor;
    struct sbrec_port_binding *lpval;
    lpval = sbrec_port_binding_index_init_row(ctx->ovnsb_idl,
                                              &sbrec_table_port_binding);
    ovsdb_idl_initialize_cursor(ctx->ovnsb_idl, &sbrec_table_port_binding,
                                "lport-by-datapath", &cursor);
    HMAP_FOR_EACH (ld, hmap_node, local_datapaths) {
        const struct sbrec_port_binding *pb;

        if (!ld->localnet_port) {
            continue;
        }

        /* Get l3gw ports.  Consider port bindings with type "l3gateway"
         * that connect to gateway routers (if local), and consider port
         * bindings of type "patch" since they might connect to
         * distributed gateway ports with NAT addresses. */

        sbrec_port_binding_index_set_datapath(lpval, ld->datapath);

        SBREC_PORT_BINDING_FOR_EACH_EQUAL (pb, &cursor, lpval) {
            if ((ld->has_local_l3gateway && !strcmp(pb->type, "l3gateway"))
                || !strcmp(pb->type, "patch")) {
                sset_add(local_l3gw_ports, pb->logical_port);
            }
        }
    }
    sbrec_port_binding_index_destroy_row(lpval);
}

static bool
pinctrl_is_chassis_resident(struct controller_ctx *ctx,
                            const struct sbrec_chassis *chassis,
                            const struct chassis_index *chassis_index,
                            struct sset *active_tunnels,
                            const char *port_name)
{
    const struct sbrec_port_binding *pb
        = lport_lookup_by_name(ctx->ovnsb_idl, port_name);
    if (!pb || !pb->chassis) {
        return false;
    }
    if (strcmp(pb->type, "chassisredirect")) {
        return pb->chassis == chassis;
    } else {
        struct ovs_list *gateway_chassis =
            gateway_chassis_get_ordered(pb, chassis_index);
        bool active = gateway_chassis_is_active(gateway_chassis,
                                                chassis,
                                                active_tunnels);
        gateway_chassis_destroy(gateway_chassis);
        return active;
    }
}

/* Extracts the mac, IPv4 and IPv6 addresses, and logical port from
 * 'addresses' which should be of the format 'MAC [IP1 IP2 ..]
 * [is_chassis_resident("LPORT_NAME")]', where IPn should be a valid IPv4
 * or IPv6 address, and stores them in the 'ipv4_addrs' and 'ipv6_addrs'
 * fields of 'laddrs'.  The logical port name is stored in 'lport'.
 *
 * Returns true if at least 'MAC' is found in 'address', false otherwise.
 *
 * The caller must call destroy_lport_addresses() and free(*lport). */
static bool
extract_addresses_with_port(const char *addresses,
                            struct lport_addresses *laddrs,
                            char **lport)
{
    int ofs;
    if (!extract_addresses(addresses, laddrs, &ofs)) {
        return false;
    } else if (ofs >= strlen(addresses)) {
        return true;
    }

    struct lexer lexer;
    lexer_init(&lexer, addresses + ofs);
    lexer_get(&lexer);

    if (lexer.error || lexer.token.type != LEX_T_ID
        || !lexer_match_id(&lexer, "is_chassis_resident")) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "invalid syntax '%s' in address", addresses);
        lexer_destroy(&lexer);
        return true;
    }

    if (!lexer_match(&lexer, LEX_T_LPAREN)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "Syntax error: expecting '(' after "
                          "'is_chassis_resident' in address '%s'", addresses);
        lexer_destroy(&lexer);
        return false;
    }

    if (lexer.token.type != LEX_T_STRING) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl,
                    "Syntax error: expecting quoted string after"
                    " 'is_chassis_resident' in address '%s'", addresses);
        lexer_destroy(&lexer);
        return false;
    }

    *lport = xstrdup(lexer.token.s);

    lexer_get(&lexer);
    if (!lexer_match(&lexer, LEX_T_RPAREN)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);
        VLOG_INFO_RL(&rl, "Syntax error: expecting ')' after quoted string in "
                          "'is_chassis_resident()' in address '%s'",
                          addresses);
        lexer_destroy(&lexer);
        return false;
    }

    lexer_destroy(&lexer);
    return true;
}

static void
consider_nat_address(struct controller_ctx *ctx,
                     const char *nat_address,
                     const struct sbrec_port_binding *pb,
                     struct sset *nat_address_keys,
                     const struct sbrec_chassis *chassis,
                     const struct chassis_index *chassis_index,
                     struct sset *active_tunnels,
                     struct shash *nat_addresses)
{
    struct lport_addresses *laddrs = xmalloc(sizeof *laddrs);
    char *lport = NULL;
    if (!extract_addresses_with_port(nat_address, laddrs, &lport)
        || (!lport && !strcmp(pb->type, "patch"))
        || (lport && !pinctrl_is_chassis_resident(
            ctx, chassis, chassis_index, active_tunnels, lport))) {
        destroy_lport_addresses(laddrs);
        free(laddrs);
        free(lport);
        return;
    }
    free(lport);

    int i;
    for (i = 0; i < laddrs->n_ipv4_addrs; i++) {
        char *name = xasprintf("%s-%s", pb->logical_port,
                                        laddrs->ipv4_addrs[i].addr_s);
        sset_add(nat_address_keys, name);
        free(name);
    }
    shash_add(nat_addresses, pb->logical_port, laddrs);
}

static void
get_nat_addresses_and_keys(struct controller_ctx *ctx,
                           struct sset *nat_address_keys,
                           struct sset *local_l3gw_ports,
                           const struct sbrec_chassis *chassis,
                           const struct chassis_index *chassis_index,
                           struct sset *active_tunnels,
                           struct shash *nat_addresses)
{
    const char *gw_port;
    SSET_FOR_EACH(gw_port, local_l3gw_ports) {
        const struct sbrec_port_binding *pb;

        pb = lport_lookup_by_name(ctx->ovnsb_idl, gw_port);
        if (!pb) {
            continue;
        }

        if (pb->n_nat_addresses) {
            for (int i = 0; i < pb->n_nat_addresses; i++) {
                consider_nat_address(ctx, pb->nat_addresses[i], pb,
                                     nat_address_keys, chassis,
                                     chassis_index, active_tunnels,
                                     nat_addresses);
            }
        } else {
            /* Continue to support options:nat-addresses for version
             * upgrade. */
            const char *nat_addresses_options = smap_get(&pb->options,
                                                         "nat-addresses");
            if (nat_addresses_options) {
                consider_nat_address(ctx, nat_addresses_options, pb,
                                     nat_address_keys, chassis,
                                     chassis_index, active_tunnels,
                                     nat_addresses);
            }
        }
    }
}

static void
send_garp_wait(void)
{
    poll_timer_wait_until(send_garp_time);
}

static void
send_garp_run(struct controller_ctx *ctx,
              const struct ovsrec_bridge *br_int,
              const struct sbrec_chassis *chassis,
              const struct chassis_index *chassis_index,
              struct hmap *local_datapaths,
              struct sset *active_tunnels)
{
    struct sset localnet_vifs = SSET_INITIALIZER(&localnet_vifs);
    struct sset local_l3gw_ports = SSET_INITIALIZER(&local_l3gw_ports);
    struct sset nat_ip_keys = SSET_INITIALIZER(&nat_ip_keys);
    struct simap localnet_ofports = SIMAP_INITIALIZER(&localnet_ofports);
    struct shash nat_addresses;

    shash_init(&nat_addresses);

    get_localnet_vifs_l3gwports(ctx, br_int, chassis, local_datapaths,
                      &localnet_vifs, &localnet_ofports, &local_l3gw_ports);

    get_nat_addresses_and_keys(ctx, &nat_ip_keys, &local_l3gw_ports,
                               chassis, chassis_index, active_tunnels,
                               &nat_addresses);
    /* For deleted ports and deleted nat ips, remove from send_garp_data. */
    struct shash_node *iter, *next;
    SHASH_FOR_EACH_SAFE (iter, next, &send_garp_data) {
        if (!sset_contains(&localnet_vifs, iter->name) &&
            !sset_contains(&nat_ip_keys, iter->name)) {
            send_garp_delete(iter->name);
        }
    }

    /* Update send_garp_data. */
    const char *iface_id;
    SSET_FOR_EACH (iface_id, &localnet_vifs) {
        const struct sbrec_port_binding *pb;

        pb = lport_lookup_by_name(ctx->ovnsb_idl, iface_id);
        if (pb) {
            send_garp_update(pb, &localnet_ofports, local_datapaths,
                             &nat_addresses);
        }
    }

    /* Update send_garp_data for nat-addresses. */
    const char *gw_port;
    SSET_FOR_EACH (gw_port, &local_l3gw_ports) {
        const struct sbrec_port_binding *pb;

        pb = lport_lookup_by_name(ctx->ovnsb_idl, gw_port);
        if (pb) {
            send_garp_update(pb, &localnet_ofports, local_datapaths,
                             &nat_addresses);
        }
    }

    /* Send GARPs, and update the next announcement. */
    long long int current_time = time_msec();
    send_garp_time = LLONG_MAX;
    SHASH_FOR_EACH (iter, &send_garp_data) {
        long long int next_announce = send_garp(iter->data, current_time);
        if (send_garp_time > next_announce) {
            send_garp_time = next_announce;
        }
    }
    sset_destroy(&localnet_vifs);
    sset_destroy(&local_l3gw_ports);
    simap_destroy(&localnet_ofports);

    SHASH_FOR_EACH_SAFE (iter, next, &nat_addresses) {
        struct lport_addresses *laddrs = iter->data;
        destroy_lport_addresses(laddrs);
        shash_delete(&nat_addresses, iter);
        free(laddrs);
    }
    shash_destroy(&nat_addresses);

    sset_destroy(&nat_ip_keys);
}

static void
reload_metadata(struct ofpbuf *ofpacts, const struct match *md)
{
    enum mf_field_id md_fields[] = {
#if FLOW_N_REGS == 16
        MFF_REG0,
        MFF_REG1,
        MFF_REG2,
        MFF_REG3,
        MFF_REG4,
        MFF_REG5,
        MFF_REG6,
        MFF_REG7,
        MFF_REG8,
        MFF_REG9,
        MFF_REG10,
        MFF_REG11,
        MFF_REG12,
        MFF_REG13,
        MFF_REG14,
        MFF_REG15,
#else
#error
#endif
        MFF_METADATA,
    };
    for (size_t i = 0; i < ARRAY_SIZE(md_fields); i++) {
        const struct mf_field *field = mf_from_id(md_fields[i]);
        if (!mf_is_all_wild(field, &md->wc)) {
            union mf_value value;
            mf_get_value(field, &md->flow, &value);
            ofpact_put_set_field(ofpacts, field, &value, NULL);
        }
    }
}

static void
pinctrl_handle_nd_na(const struct flow *ip_flow, const struct match *md,
                     struct ofpbuf *userdata)
{
    /* This action only works for IPv6 ND packets, and the switch should only
     * send us ND packets this way, but check here just to be sure. */
    if (!is_nd(ip_flow, NULL)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "NA action on non-ND packet");
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    /* xxx These flags are not exactly correct.  Look at section 7.2.4
     * xxx of RFC 4861.  For example, we need to set ND_RSO_ROUTER for
     * xxx router's interfaces and ND_RSO_SOLICITED only if it was
     * xxx requested. */
    compose_nd_na(&packet, ip_flow->dl_dst, ip_flow->dl_src,
                  &ip_flow->nd_target, &ip_flow->ipv6_src,
                  htonl(ND_RSO_SOLICITED | ND_RSO_OVERRIDE));

    /* Reload previous packet metadata and set actions from userdata. */
    set_actions_and_enqueue_msg(&packet, md, userdata);
    dp_packet_uninit(&packet);
}

static void
pinctrl_handle_nd_ns(const struct flow *ip_flow, const struct match *md,
                     struct ofpbuf *userdata)
{
    /* This action only works for IPv6 packets. */
    if (get_dl_type(ip_flow) != htons(ETH_TYPE_IPV6)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "NS action on non-IPv6 packet");
        return;
    }

    uint64_t packet_stub[128 / 8];
    struct dp_packet packet;
    dp_packet_use_stub(&packet, packet_stub, sizeof packet_stub);

    compose_nd_ns(&packet, ip_flow->dl_src, &ip_flow->ipv6_src,
                  &ip_flow->ipv6_dst);

    /* Reload previous packet metadata and set actions from userdata. */
    set_actions_and_enqueue_msg(&packet, md, userdata);
    dp_packet_uninit(&packet);
}

static void
pinctrl_handle_put_nd_ra_opts(
    const struct flow *in_flow, struct dp_packet *pkt_in,
    struct ofputil_packet_in *pin, struct ofpbuf *userdata,
    struct ofpbuf *continuation)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    enum ofp_version version = rconn_get_version(swconn);
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    struct dp_packet *pkt_out_ptr = NULL;
    uint32_t success = 0;

    /* Parse result field. */
    const struct mf_field *f;
    enum ofperr ofperr = nx_pull_header(userdata, NULL, &f, NULL);
    if (ofperr) {
       VLOG_WARN_RL(&rl, "bad result OXM (%s)", ofperr_to_string(ofperr));
       goto exit;
    }

    /* Parse result offset. */
    ovs_be32 *ofsp = ofpbuf_try_pull(userdata, sizeof *ofsp);
    if (!ofsp) {
        VLOG_WARN_RL(&rl, "offset not present in the userdata");
        goto exit;
    }

    /* Check that the result is valid and writable. */
    struct mf_subfield dst = { .field = f, .ofs = ntohl(*ofsp), .n_bits = 1 };
    ofperr = mf_check_dst(&dst, NULL);
    if (ofperr) {
        VLOG_WARN_RL(&rl, "bad result bit (%s)", ofperr_to_string(ofperr));
        goto exit;
    }

    if (!userdata->size) {
        VLOG_WARN_RL(&rl, "IPv6 ND RA options not present in the userdata");
        goto exit;
    }

    if (!is_icmpv6(in_flow, NULL) || in_flow->tp_dst != htons(0) ||
        in_flow->tp_src != htons(ND_ROUTER_SOLICIT)) {
        VLOG_WARN_RL(&rl, "put_nd_ra action on invalid or unsupported packet");
        goto exit;
    }

    size_t new_packet_size = pkt_in->l4_ofs + userdata->size;
    struct dp_packet pkt_out;
    dp_packet_init(&pkt_out, new_packet_size);
    dp_packet_clear(&pkt_out);
    dp_packet_prealloc_tailroom(&pkt_out, new_packet_size);
    pkt_out_ptr = &pkt_out;

    /* Copy L2 and L3 headers from pkt_in. */
    dp_packet_put(&pkt_out, dp_packet_pull(pkt_in, pkt_in->l4_ofs),
                  pkt_in->l4_ofs);

    pkt_out.l2_5_ofs = pkt_in->l2_5_ofs;
    pkt_out.l2_pad_size = pkt_in->l2_pad_size;
    pkt_out.l3_ofs = pkt_in->l3_ofs;
    pkt_out.l4_ofs = pkt_in->l4_ofs;

    /* Copy the ICMPv6 Router Advertisement data from 'userdata' field. */
    dp_packet_put(&pkt_out, userdata->data, userdata->size);

    /* Set the IPv6 payload length and calculate the ICMPv6 checksum. */
    struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(&pkt_out);
    nh->ip6_plen = htons(userdata->size);
    struct ovs_ra_msg *ra = dp_packet_l4(&pkt_out);
    ra->icmph.icmp6_cksum = 0;
    uint32_t icmp_csum = packet_csum_pseudoheader6(nh);
    ra->icmph.icmp6_cksum = csum_finish(csum_continue(
        icmp_csum, ra, userdata->size));
    pin->packet = dp_packet_data(&pkt_out);
    pin->packet_len = dp_packet_size(&pkt_out);
    success = 1;

exit:
    if (!ofperr) {
        union mf_subvalue sv;
        sv.u8_val = success;
        mf_write_subfield(&dst, &sv, &pin->flow_metadata);
    }
    queue_msg(ofputil_encode_resume(pin, continuation, proto));
    dp_packet_uninit(pkt_out_ptr);
}
