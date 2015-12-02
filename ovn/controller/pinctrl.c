
/* Copyright (c) 2015 Red Hat, Inc.
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
#include "dirs.h"
#include "pinctrl.h"
#include "ofp-msgs.h"
#include "ofp-print.h"
#include "ofp-util.h"
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

static void
get_switch_config(struct rconn *swconn)
{
    struct ofpbuf *request;

    request = ofpraw_alloc(OFPRAW_OFPT_GET_CONFIG_REQUEST,
                           rconn_get_version(swconn), 0);
    queue_msg(request);
}

static void
set_switch_config(struct rconn *swconn, const struct ofp_switch_config *config)
{
    struct ofpbuf *request;

    request =
        ofpraw_alloc(OFPRAW_OFPT_SET_CONFIG, rconn_get_version(swconn), 0);
    ofpbuf_put(request, config, sizeof *config);

    queue_msg(request);
}

static void
process_packet_in(struct controller_ctx *ctx OVS_UNUSED,
                  const struct ofp_header *msg)
{
    struct ofputil_packet_in pin;

    if (ofputil_decode_packet_in(&pin, msg) != 0) {
        return;
    }
    if (pin.reason != OFPR_ACTION) {
        return;
    }

    /* XXX : process the received packet */
}

static void
pinctrl_recv(struct controller_ctx *ctx, const struct ofp_header *oh,
             enum ofptype type)
{
    if (type == OFPTYPE_ECHO_REQUEST) {
        queue_msg(make_echo_reply(oh));
    } else if (type == OFPTYPE_GET_CONFIG_REPLY) {
        struct ofpbuf rq_buf;
        struct ofp_switch_config *config_, config;

        ofpbuf_use_const(&rq_buf, oh, ntohs(oh->length));
        config_ = ofpbuf_pull(&rq_buf, sizeof *config_);
        config = *config_;
        config.miss_send_len = htons(UINT16_MAX);
        set_switch_config(swconn, &config);
    } else if (type == OFPTYPE_PACKET_IN) {
        process_packet_in(ctx, oh);
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
pinctrl_run(struct controller_ctx *ctx, const struct ovsrec_bridge *br_int)
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

    if (!rconn_is_connected(swconn)) {
        return;
    }

    if (conn_seq_no != rconn_get_connection_seqno(swconn)) {
        get_switch_config(swconn);
        conn_seq_no = rconn_get_connection_seqno(swconn);
    }

    struct ofpbuf *msg = rconn_recv(swconn);

    if (!msg) {
        return;
    }

    const struct ofp_header *oh = msg->data;
    enum ofptype type;

    ofptype_decode(&type, oh);
    pinctrl_recv(ctx, oh, type);
    ofpbuf_delete(msg);
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
