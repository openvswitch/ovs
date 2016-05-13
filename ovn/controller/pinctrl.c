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

#include "coverage.h"
#include "dirs.h"
#include "dp-packet.h"
#include "flow.h"
#include "lport.h"
#include "openvswitch/ofp-actions.h"
#include "openvswitch/ofp-msgs.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofp-util.h"
#include "openvswitch/vlog.h"
#include "ovn-controller.h"
#include "ovn/lib/actions.h"
#include "ovn/lib/logical-fields.h"
#include "poll-loop.h"
#include "rconn.h"
#include "socket-util.h"
#include "timeval.h"
#include "vswitch-idl.h"

VLOG_DEFINE_THIS_MODULE(pinctrl);

/* OpenFlow connection to the switch. */
static struct rconn *swconn;

/* Last seen sequence number for 'swconn'.  When this differs from
 * rconn_get_connection_seqno(rconn), 'swconn' has reconnected. */
static unsigned int conn_seq_no;

static void pinctrl_handle_put_arp(const struct flow *md,
                                   const struct flow *headers);
static void init_put_arps(void);
static void destroy_put_arps(void);
static void run_put_arps(struct controller_ctx *,
                         const struct lport_index *lports);
static void wait_put_arps(struct controller_ctx *);
static void flush_put_arps(void);

COVERAGE_DEFINE(pinctrl_drop_put_arp);

void
pinctrl_init(void)
{
    swconn = rconn_create(5, 0, DSCP_DEFAULT, 1 << OFP13_VERSION);
    conn_seq_no = 0;
    init_put_arps();
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
     * First, copy metadata from 'md' into the packet-out via "set_field"
     * actions, then add actions from 'userdata'.
     */
    uint64_t ofpacts_stub[4096 / 8];
    struct ofpbuf ofpacts = OFPBUF_STUB_INITIALIZER(ofpacts_stub);
    enum ofp_version version = rconn_get_version(swconn);

    enum mf_field_id md_fields[] = {
#if FLOW_N_REGS == 8
        MFF_REG0,
        MFF_REG1,
        MFF_REG2,
        MFF_REG3,
        MFF_REG4,
        MFF_REG5,
        MFF_REG6,
        MFF_REG7,
#else
#error
#endif
        MFF_METADATA,
    };
    for (size_t i = 0; i < ARRAY_SIZE(md_fields); i++) {
        const struct mf_field *field = mf_from_id(md_fields[i]);
        if (!mf_is_all_wild(field, &md->wc)) {
            struct ofpact_set_field *sf = ofpact_put_SET_FIELD(&ofpacts);
            sf->field = field;
            sf->flow_has_vlan = false;
            mf_get_value(field, &md->flow, &sf->value);
            memset(&sf->mask, 0xff, field->n_bytes);
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

    switch (ntohl(ah->opcode)) {
    case ACTION_OPCODE_ARP:
        pinctrl_handle_arp(&headers, &pin.flow_metadata, &userdata);
        break;

    case ACTION_OPCODE_PUT_ARP:
        pinctrl_handle_put_arp(&pin.flow_metadata.flow, &headers);
        break;

    default:
        VLOG_WARN_RL(&rl, "unrecognized packet-in opcode %"PRIu32,
                     ntohl(ah->opcode));
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
pinctrl_run(struct controller_ctx *ctx, const struct lport_index *lports,
            const struct ovsrec_bridge *br_int)
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
            flush_put_arps();
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

    run_put_arps(ctx, lports);
}

void
pinctrl_wait(struct controller_ctx *ctx)
{
    wait_put_arps(ctx);
    rconn_run_wait(swconn);
    rconn_recv_wait(swconn);
}

void
pinctrl_destroy(void)
{
    rconn_destroy(swconn);
    destroy_put_arps();
}

/* Implementation of the "put_arp" OVN action.  This action sends a packet to
 * ovn-controller, using the flow as an API (see actions.h for details).  This
 * code implements the action by updating the MAC_Binding table in the
 * southbound database.
 *
 * This code could be a lot simpler if the database could always be updated,
 * but in fact we can only update it when ctx->ovnsb_idl_txn is nonnull.  Thus,
 * we buffer up a few put_arps (but we don't keep them longer than 1 second)
 * and apply them whenever a database transaction is available. */

/* Buffered "put_arp" operation. */
struct put_arp {
    struct hmap_node hmap_node; /* In 'put_arps'. */

    long long int timestamp;    /* In milliseconds. */

    /* Key. */
    uint32_t dp_key;
    uint32_t port_key;
    ovs_be32 ip;

    /* Value. */
    struct eth_addr mac;
};

/* Contains "struct put_arp"s. */
static struct hmap put_arps;

static void
init_put_arps(void)
{
    hmap_init(&put_arps);
}

static void
destroy_put_arps(void)
{
    flush_put_arps();
    hmap_destroy(&put_arps);
}

static struct put_arp *
pinctrl_find_put_arp(uint32_t dp_key, uint32_t port_key, ovs_be32 ip,
                     uint32_t hash)
{
    struct put_arp *pa;
    HMAP_FOR_EACH_WITH_HASH (pa, hmap_node, hash, &put_arps) {
        if (pa->dp_key == dp_key
            && pa->port_key == port_key
            && pa->ip == ip) {
            return pa;
        }
    }
    return NULL;
}

static void
pinctrl_handle_put_arp(const struct flow *md, const struct flow *headers)
{
    uint32_t dp_key = ntohll(md->metadata);
    uint32_t port_key = md->regs[MFF_LOG_INPORT - MFF_REG0];
    ovs_be32 ip = htonl(md->regs[0]);
    uint32_t hash = hash_3words(dp_key, port_key, (OVS_FORCE uint32_t) ip);
    struct put_arp *pa = pinctrl_find_put_arp(dp_key, port_key, ip, hash);
    if (!pa) {
        if (hmap_count(&put_arps) >= 1000) {
            COVERAGE_INC(pinctrl_drop_put_arp);
            return;
        }

        pa = xmalloc(sizeof *pa);
        hmap_insert(&put_arps, &pa->hmap_node, hash);
        pa->dp_key = dp_key;
        pa->port_key = port_key;
        pa->ip = ip;
    }
    pa->timestamp = time_msec();
    pa->mac = headers->dl_src;
}

static void
run_put_arp(struct controller_ctx *ctx, const struct lport_index *lports,
            const struct put_arp *pa)
{
    if (time_msec() > pa->timestamp + 1000) {
        return;
    }

    /* Convert logical datapath and logical port key into lport. */
    const struct sbrec_port_binding *pb
        = lport_lookup_by_key(lports, pa->dp_key, pa->port_key);
    if (!pb) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);

        VLOG_WARN_RL(&rl, "unknown logical port with datapath %"PRIu32" "
                     "and port %"PRIu32, pa->dp_key, pa->port_key);
        return;
    }

    /* Convert arguments to string form for database. */
    char ip_string[INET_ADDRSTRLEN + 1];
    snprintf(ip_string, sizeof ip_string, IP_FMT, IP_ARGS(pa->ip));

    char mac_string[ETH_ADDR_STRLEN + 1];
    snprintf(mac_string, sizeof mac_string,
             ETH_ADDR_FMT, ETH_ADDR_ARGS(pa->mac));

    /* Check for and update an existing IP-MAC binding for this logical
     * port.
     *
     * XXX This is not very efficient. */
    const struct sbrec_mac_binding *b;
    SBREC_MAC_BINDING_FOR_EACH (b, ctx->ovnsb_idl) {
        if (!strcmp(b->logical_port, pb->logical_port)
            && !strcmp(b->ip, ip_string)) {
            if (strcmp(b->mac, mac_string)) {
                sbrec_mac_binding_set_mac(b, mac_string);
            }
            return;
        }
    }

    /* Add new IP-MAC binding for this logical port. */
    b = sbrec_mac_binding_insert(ctx->ovnsb_idl_txn);
    sbrec_mac_binding_set_logical_port(b, pb->logical_port);
    sbrec_mac_binding_set_ip(b, ip_string);
    sbrec_mac_binding_set_mac(b, mac_string);
}

static void
run_put_arps(struct controller_ctx *ctx, const struct lport_index *lports)
{
    if (!ctx->ovnsb_idl_txn) {
        return;
    }

    const struct put_arp *pa;
    HMAP_FOR_EACH (pa, hmap_node, &put_arps) {
        run_put_arp(ctx, lports, pa);
    }
    flush_put_arps();
}

static void
wait_put_arps(struct controller_ctx *ctx)
{
    if (ctx->ovnsb_idl_txn && !hmap_is_empty(&put_arps)) {
        poll_immediate_wake();
    }
}

static void
flush_put_arps(void)
{
    struct put_arp *pa;
    HMAP_FOR_EACH_POP (pa, hmap_node, &put_arps) {
        free(pa);
    }
}
