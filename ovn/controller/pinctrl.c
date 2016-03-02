/* Copyright (c) 2015, 2016 Red Hat, Inc.
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

#include "dirs.h"
#include "dp-packet.h"
#include "ofp-actions.h"
#include "ofp-msgs.h"
#include "ofp-print.h"
#include "ofp-util.h"
#include "ovn/lib/actions.h"
#include "rconn.h"
#include "openvswitch/vlog.h"
#include "socket-util.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(pinctrl);

/* OpenFlow connection to the switch. */
static struct rconn *swconn;

/* Last seen sequence number for 'swconn'.  When this differs from
 * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
static unsigned int conn_seq_no;

void
pinctrl_init(void)
{
    swconn = rconn_create(5, 0, DSCP_DEFAULT, 1 << OFP13_VERSION);
    conn_seq_no = 0;
}

static ovs_be32
queue_msg(struct ofpbuf *msg)
{
    const struct ofp_header *oh = msg->data;
    ovs_be32 xid = oh->xid;

    rconn_send(swconn, msg, NULL);
    return xid;
}

/* Sets up 'swconn', a newly (re)connected connection to a switch. */
static void
pinctrl_setup(struct rconn *swconn)
{
    /* Fetch the switch configuration.  The response later will allow us to
     * change the miss_send_len to UINT16_MAX, so that we can enable
     * asynchronous messages. */
    queue_msg(ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST,
                           rconn_get_version(swconn), 0));

    /* Set a packet-in format that supports userdata.  */
    queue_msg(ofputil_make_set_packet_in_format(rconn_get_version(swconn),
                                                NXPIF_NXT_PACKET_IN2));
}

static void
set_switch_config(struct rconn *swconn,
                  const struct ofputil_switch_config *config)
{
    enum ofp_version version = rconn_get_version(swconn);
    struct ofpbuf *request = ofputil_encode_set_config(config, version);
    queue_msg(request);
}

static void
pinctrl_handle_arp(const struct flow *ip_flow, struct ofpbuf *userdata)
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

    struct eth_header *eth = dp_packet_l2(&packet);
    eth->eth_dst = ip_flow->dl_dst;
    eth->eth_src = ip_flow->dl_src;

    struct arp_eth_header *arp = dp_packet_l3(&packet);
    arp->ar_op = htons(ARP_OP_REQUEST);
    arp->ar_sha = ip_flow->dl_src;
    put_16aligned_be32(&arp->ar_spa, ip_flow->nw_src);
    arp->ar_tha = eth_addr_zero;
    put_16aligned_be32(&arp->ar_tpa, ip_flow->nw_dst);

    if (ip_flow->vlan_tci & htons(VLAN_CFI)) {
        eth_push_vlan(&packet, htons(ETH_TYPE_VLAN_8021Q), ip_flow->vlan_tci);
    }

    /* Compose actions.
     *
     * First, add actions to restore the metadata, then add actions from
     * 'userdata'.
     */
    uint64_t ofpacts_stub[1024 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);

    for (int id = 0; id < MFF_N_IDS; id++) {
        const struct mf_field *field = mf_from_id(id);

        if (field->prereqs == MFP_NONE
            && field->writable
            && id != MFF_IN_PORT && id != MFF_IN_PORT_OXM
            && mf_is_set(field, ip_flow))
        {
            struct ofpact_set_field *sf = ofpact_put_SET_FIELD(&ofpacts);
            sf->field = field;
            sf->flow_has_vlan = false;
            mf_get_value(field, ip_flow, &sf->value);
            bitwise_one(&sf->mask, sizeof sf->mask, 0, field->n_bits);
        }
    }
    enum ofperr error = ofpacts_pull_openflow_actions(userdata, userdata->size,
                                                      version, &ofpacts);
    if (error) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
        VLOG_WARN_RL(&rl, "failed to parse arp actions (%s)",
                     ofperr_to_string(error));
        goto exit;
    }

    struct ofputil_packet_out po = {
        .packet = dp_packet_data(&packet),
        .packet_len = dp_packet_size(&packet),
        .buffer_id = UINT32_MAX,
        .in_port = OFPP_CONTROLLER,
        .ofpacts = ofpacts.data,
        .ofpacts_len = ofpacts.size,
    };
    enum ofputil_protocol proto = ofputil_protocol_from_ofp_version(version);
    queue_msg(ofputil_encode_packet_out(&po, proto));

exit:
    dp_packet_uninit(&packet);
    ofpbuf_uninit(&ofpacts);
}

static void
process_packet_in(const struct ofp_header *msg)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

    struct ofputil_packet_in pin;
    enum ofperr error = ofputil_decode_packet_in(msg, true, &pin,
                                                 NULL, NULL, NULL);
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

    const struct flow *md = &pin.flow_metadata.flow;
    switch (ntohl(ah->opcode)) {
    case ACTION_OPCODE_ARP:
        pinctrl_handle_arp(&headers, &userdata);
        break;

    default:
        VLOG_WARN_RL(&rl, "unrecognized packet-in command %#"PRIx32,
                     md->regs[0]);
        break;
    }
}

static void
pinctrl_recv(const struct ofp_header *oh, enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(make_echo_reply(oh));
    } else if (type == OFPTYPE_GET_CONFIG_REPLY) {
        /* Enable asynchronous messages (see "Asynchronous Messages" in
         * DESIGN.md for more information). */
        struct ofputil_switch_config config;

        ofputil_decode_get_config_reply(oh, &config);
        config.miss_send_len = UINT16_MAX;
        set_switch_config(swconn, &config);
    } else if (type == OFPTYPE_PACKET_IN) {
        process_packet_in(oh);
    } else if (type != OFPTYPE_ECHO_REPLY && type != OFPTYPE_BARRIER_REPLY) {
        if (VLOG_IS_DBG_ENABLED()) {
            static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 300);

            char *s = ofp_to_string(oh, ntohs(oh->length), 2);

            VLOG_DBG_RL(&rl, "OpenFlow packet ignored: %s", s);
            free(s);
        }
    }
}

void
pinctrl_run(const struct ovsrec_bridge *br_int)
{
    if (br_int) {
        char *target;

        target = xasprintf("unix:%s/%s.mgmt", ovs_rundir(), br_int->name);
        if (strcmp(target, rconn_get_target(swconn))) {
            VLOG_INFO("%s: connecting to switch", target);
            rconn_connect(swconn, target, target);
        }
        free(target);
    } else {
        rconn_disconnect(swconn);
    }

    rconn_run(swconn);

    if (rconn_is_connected(swconn)) {
        if (conn_seq_no != rconn_get_connection_seqno(swconn)) {
            pinctrl_setup(swconn);
            conn_seq_no = rconn_get_connection_seqno(swconn);
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
            pinctrl_recv(oh, type);
            ofpbuf_delete(msg);
        }
    }
}

void
pinctrl_wait(void)
{
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);
}

void
pinctrl_destroy(void)
{
    rconn_destroy(swconn);
}
