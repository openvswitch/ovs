/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "in-band.h"
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include "flow.h"
#include "mac-learning.h"
#include "netdev.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofproto.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "rconn.h"
#include "status.h"
#include "timeval.h"
#include "vconn.h"

#define THIS_MODULE VLM_in_band
#include "vlog.h"

#define IB_BASE_PRIORITY 18181800

enum {
    IBR_FROM_LOCAL_PORT,        /* Sent by the local port. */
    IBR_OFP_TO_LOCAL,           /* Sent to secure channel on local port. */
    IBR_ARP_FROM_LOCAL,         /* ARP from the local port. */
    IBR_ARP_FROM_CTL,           /* ARP from the controller. */
    IBR_TO_CTL_OFP_SRC,         /* To controller, OpenFlow source port. */
    IBR_TO_CTL_OFP_DST,         /* To controller, OpenFlow dest port. */
    IBR_FROM_CTL_OFP_SRC,       /* From controller, OpenFlow source port. */
    IBR_FROM_CTL_OFP_DST,       /* From controller, OpenFlow dest port. */
#if OFP_TCP_PORT != OFP_SSL_PORT
#error Need to support separate TCP and SSL flows.
#endif
    N_IB_RULES
};

struct ib_rule {
    bool installed;
    flow_t flow;
    uint32_t wildcards;
    unsigned int priority;
};

struct in_band {
    struct ofproto *ofproto;
    struct rconn *controller;
    struct status_category *ss_cat;

    /* Keeping track of controller's MAC address. */
    uint32_t ip;                /* Current IP, 0 if unknown. */
    uint32_t last_ip;           /* Last known IP, 0 if never known. */
    uint8_t mac[ETH_ADDR_LEN];  /* Current MAC, 0 if unknown. */
    uint8_t last_mac[ETH_ADDR_LEN]; /* Last known MAC, 0 if never known */
    char *dev_name;
    time_t next_refresh;        /* Next time to refresh MAC address. */

    /* Keeping track of the local port's MAC address. */
    uint8_t local_mac[ETH_ADDR_LEN]; /* Current MAC. */
    time_t next_local_refresh;  /* Next time to refresh MAC address. */

    /* Rules that we set up. */
    struct ib_rule rules[N_IB_RULES];
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static const uint8_t *
get_controller_mac(struct in_band *ib)
{
    time_t now = time_now();
    uint32_t controller_ip;

    controller_ip = rconn_get_remote_ip(ib->controller);
    if (controller_ip != ib->ip || now >= ib->next_refresh) {
        bool have_mac;

        ib->ip = controller_ip;

        /* Look up MAC address. */
        memset(ib->mac, 0, sizeof ib->mac);
        if (ib->ip) {
            uint32_t local_ip = rconn_get_local_ip(ib->controller);
            struct in_addr in4;
            int retval;

            in4.s_addr = local_ip;
            if (netdev_find_dev_by_in4(&in4, &ib->dev_name)) {
                retval = netdev_nodev_arp_lookup(ib->dev_name, ib->ip,
                        ib->mac);
                if (retval) {
                    VLOG_DBG_RL(&rl, "cannot look up controller MAC address "
                                "("IP_FMT"): %s",
                                IP_ARGS(&ib->ip), strerror(retval));
                }
            } else {
                VLOG_DBG_RL(&rl, "cannot find device with IP address "IP_FMT,
                    IP_ARGS(&local_ip));
            }
        }
        have_mac = !eth_addr_is_zero(ib->mac);

        /* Log changes in IP, MAC addresses. */
        if (ib->ip && ib->ip != ib->last_ip) {
            VLOG_DBG("controller IP address changed from "IP_FMT
                     " to "IP_FMT, IP_ARGS(&ib->last_ip), IP_ARGS(&ib->ip));
            ib->last_ip = ib->ip;
        }
        if (have_mac && memcmp(ib->last_mac, ib->mac, ETH_ADDR_LEN)) {
            VLOG_DBG("controller MAC address changed from "ETH_ADDR_FMT" to "
                     ETH_ADDR_FMT,
                     ETH_ADDR_ARGS(ib->last_mac), ETH_ADDR_ARGS(ib->mac));
            memcpy(ib->last_mac, ib->mac, ETH_ADDR_LEN);
        }

        /* Schedule next refresh.
         *
         * If we have an IP address but not a MAC address, then refresh
         * quickly, since we probably will get a MAC address soon (via ARP).
         * Otherwise, we can afford to wait a little while. */
        ib->next_refresh = now + (!ib->ip || have_mac ? 10 : 1);
    }
    return !eth_addr_is_zero(ib->mac) ? ib->mac : NULL;
}

static const uint8_t *
get_local_mac(struct in_band *ib)
{
    time_t now = time_now();
    if (now >= ib->next_local_refresh) {
        uint8_t ea[ETH_ADDR_LEN];
        if (ib->dev_name && (!netdev_nodev_get_etheraddr(ib->dev_name, ea))) {
            memcpy(ib->local_mac, ea, ETH_ADDR_LEN);
        }
        ib->next_local_refresh = now + 1;
    }
    return !eth_addr_is_zero(ib->local_mac) ? ib->local_mac : NULL;
}

static void
in_band_status_cb(struct status_reply *sr, void *in_band_)
{
    struct in_band *in_band = in_band_;
    const uint8_t *local_mac;
    const uint8_t *controller_mac;

    local_mac = get_local_mac(in_band);
    if (local_mac) {
        status_reply_put(sr, "local-mac="ETH_ADDR_FMT,
                         ETH_ADDR_ARGS(local_mac));
    }

    controller_mac = get_controller_mac(in_band);
    if (controller_mac) {
        status_reply_put(sr, "controller-mac="ETH_ADDR_FMT,
                         ETH_ADDR_ARGS(controller_mac));
    }
}

static void
drop_flow(struct in_band *in_band, int rule_idx)
{
    struct ib_rule *rule = &in_band->rules[rule_idx];

    if (rule->installed) {
        rule->installed = false;
        ofproto_delete_flow(in_band->ofproto, &rule->flow, rule->wildcards,
                            rule->priority);
    }
}

/* out_port and fixed_fields are assumed never to change. */
static void
setup_flow(struct in_band *in_band, int rule_idx, const flow_t *flow,
           uint32_t fixed_fields, uint16_t out_port)
{
    struct ib_rule *rule = &in_band->rules[rule_idx];

    if (!rule->installed || memcmp(flow, &rule->flow, sizeof *flow)) {
        union ofp_action action;

        drop_flow(in_band, rule_idx);

        rule->installed = true;
        rule->flow = *flow;
        rule->wildcards = OFPFW_ALL & ~fixed_fields;
        rule->priority = IB_BASE_PRIORITY + (N_IB_RULES - rule_idx);

        action.type = htons(OFPAT_OUTPUT);
        action.output.len = htons(sizeof action);
        action.output.port = htons(out_port);
        action.output.max_len = htons(0);
        ofproto_add_flow(in_band->ofproto, &rule->flow, rule->wildcards,
                         rule->priority, &action, 1, 0);
    }
}

void
in_band_run(struct in_band *in_band)
{
    const uint8_t *controller_mac;
    const uint8_t *local_mac;
    flow_t flow;

    if (time_now() < MIN(in_band->next_refresh, in_band->next_local_refresh)) {
        return;
    }
    controller_mac = get_controller_mac(in_band);
    local_mac = get_local_mac(in_band);

    /* Switch traffic sent by the local port. */
    memset(&flow, 0, sizeof flow);
    flow.in_port = ODPP_LOCAL;
    setup_flow(in_band, IBR_FROM_LOCAL_PORT, &flow, OFPFW_IN_PORT,
               OFPP_NORMAL);

    if (local_mac) {
        /* Deliver traffic sent to the connection's interface. */
        memset(&flow, 0, sizeof flow);
        memcpy(flow.dl_dst, local_mac, ETH_ADDR_LEN);
        setup_flow(in_band, IBR_OFP_TO_LOCAL, &flow, OFPFW_DL_DST,
                    OFPP_NORMAL);

        /* Allow the connection's interface to be the source of ARP traffic. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_src, local_mac, ETH_ADDR_LEN);
        setup_flow(in_band, IBR_ARP_FROM_LOCAL, &flow,
                   OFPFW_DL_TYPE | OFPFW_DL_SRC, OFPP_NORMAL);
    } else {
        drop_flow(in_band, IBR_OFP_TO_LOCAL);
        drop_flow(in_band, IBR_ARP_FROM_LOCAL);
    }

    if (controller_mac) {
        /* Switch ARP requests sent by the controller.  (OFPP_NORMAL will "do
         * the right thing" regarding VLANs here.) */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_dst, eth_addr_broadcast, ETH_ADDR_LEN);
        memcpy(flow.dl_src, controller_mac, ETH_ADDR_LEN);
        setup_flow(in_band, IBR_ARP_FROM_CTL, &flow,
                   OFPFW_DL_TYPE | OFPFW_DL_DST | OFPFW_DL_SRC,
                   OFPP_NORMAL);

        /* OpenFlow traffic to or from the controller.
         *
         * (A given field's value is completely ignored if it is wildcarded,
         * which is why we can get away with using a single 'flow' in each
         * case here.) */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_IP);
        memcpy(flow.dl_src, controller_mac, ETH_ADDR_LEN);
        memcpy(flow.dl_dst, controller_mac, ETH_ADDR_LEN);
        flow.nw_proto = IP_TYPE_TCP;
        flow.tp_src = htons(OFP_TCP_PORT);
        flow.tp_dst = htons(OFP_TCP_PORT);
        setup_flow(in_band, IBR_TO_CTL_OFP_SRC, &flow,
                   (OFPFW_DL_TYPE | OFPFW_DL_DST | OFPFW_NW_PROTO
                    | OFPFW_TP_SRC), OFPP_NORMAL);
        setup_flow(in_band, IBR_TO_CTL_OFP_DST, &flow,
                   (OFPFW_DL_TYPE | OFPFW_DL_DST | OFPFW_NW_PROTO
                    | OFPFW_TP_DST), OFPP_NORMAL);
        setup_flow(in_band, IBR_FROM_CTL_OFP_SRC, &flow,
                   (OFPFW_DL_TYPE | OFPFW_DL_SRC | OFPFW_NW_PROTO
                    | OFPFW_TP_SRC), OFPP_NORMAL);
        setup_flow(in_band, IBR_FROM_CTL_OFP_DST, &flow,
                   (OFPFW_DL_TYPE | OFPFW_DL_SRC | OFPFW_NW_PROTO
                    | OFPFW_TP_DST), OFPP_NORMAL);
    } else {
        drop_flow(in_band, IBR_ARP_FROM_CTL);
        drop_flow(in_band, IBR_TO_CTL_OFP_DST);
        drop_flow(in_band, IBR_TO_CTL_OFP_SRC);
        drop_flow(in_band, IBR_FROM_CTL_OFP_DST);
        drop_flow(in_band, IBR_FROM_CTL_OFP_SRC);
    }
}

void
in_band_wait(struct in_band *in_band)
{
    time_t now = time_now();
    time_t wakeup = MIN(in_band->next_refresh, in_band->next_local_refresh);
    if (wakeup > now) {
        poll_timer_wait((wakeup - now) * 1000);
    } else {
        poll_immediate_wake();
    }
}

void
in_band_flushed(struct in_band *in_band)
{
    int i;

    for (i = 0; i < N_IB_RULES; i++) {
        in_band->rules[i].installed = false;
    }
}

void
in_band_create(struct ofproto *ofproto, struct switch_status *ss,
               struct rconn *controller, struct in_band **in_bandp)
{
    struct in_band *in_band;

    in_band = xcalloc(1, sizeof *in_band);
    in_band->ofproto = ofproto;
    in_band->controller = controller;
    in_band->ss_cat = switch_status_register(ss, "in-band",
                                             in_band_status_cb, in_band);
    in_band->next_refresh = TIME_MIN;
    in_band->next_local_refresh = TIME_MIN;
    in_band->dev_name = NULL;

    *in_bandp = in_band;
}

void
in_band_destroy(struct in_band *in_band)
{
    if (in_band) {
        switch_status_unregister(in_band->ss_cat);
        /* We don't own the rconn. */
    }
}

