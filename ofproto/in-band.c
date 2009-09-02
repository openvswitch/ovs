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
#include "dhcp.h"
#include "dpif.h"
#include "flow.h"
#include "mac-learning.h"
#include "netdev.h"
#include "odp-util.h"
#include "ofp-print.h"
#include "ofproto.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"
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
    IBR_FROM_LOCAL_DHCP,          /* From local port, DHCP. */
    IBR_TO_LOCAL_ARP,             /* To local port, ARP. */
    IBR_FROM_LOCAL_ARP,           /* From local port, ARP. */
    IBR_TO_REMOTE_ARP,            /* To remote MAC, ARP. */
    IBR_FROM_REMOTE_ARP,          /* From remote MAC, ARP. */
    IBR_TO_CTL_ARP,               /* To controller IP, ARP. */
    IBR_FROM_CTL_ARP,             /* From controller IP, ARP. */
    IBR_TO_CTL_OFP,               /* To controller, OpenFlow port. */
    IBR_FROM_CTL_OFP,             /* From controller, OpenFlow port. */
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

    /* Keep track of local port's information. */
    uint8_t local_mac[ETH_ADDR_LEN];       /* Current MAC. */
    struct netdev *local_netdev;           /* Local port's network device. */
    time_t next_local_refresh;

    /* Keep track of controller and next hop's information. */
    uint32_t controller_ip;                /* Controller IP, 0 if unknown. */
    uint8_t remote_mac[ETH_ADDR_LEN];      /* Remote MAC. */
    struct netdev *remote_netdev;
    uint8_t last_remote_mac[ETH_ADDR_LEN]; /* Previous remote MAC. */
    time_t next_remote_refresh;

    /* Rules that we set up. */
    struct ib_rule rules[N_IB_RULES];
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static const uint8_t *
get_remote_mac(struct in_band *ib)
{
    int retval;
    bool have_mac;
    struct in_addr c_in4;   /* Controller's IP address. */
    struct in_addr r_in4;   /* Next hop IP address. */
    char *next_hop_dev;
    time_t now = time_now();

    if (now >= ib->next_remote_refresh) {
        /* Find the next-hop IP address. */
        c_in4.s_addr = ib->controller_ip;
        memset(ib->remote_mac, 0, sizeof ib->remote_mac);
        retval = netdev_get_next_hop(ib->local_netdev,
                                     &c_in4, &r_in4, &next_hop_dev);
        if (retval) {
            VLOG_WARN("cannot find route for controller ("IP_FMT"): %s",
                    IP_ARGS(&ib->controller_ip), strerror(retval));
            ib->next_remote_refresh = now + 1;
            return NULL;
        }
        if (!r_in4.s_addr) {
            r_in4.s_addr = c_in4.s_addr;
        }

        /* Get the next-hop IP and network device. */
        if (!ib->remote_netdev
            || strcmp(netdev_get_name(ib->remote_netdev), next_hop_dev))
        {
            netdev_close(ib->remote_netdev);
            retval = netdev_open(next_hop_dev, NETDEV_ETH_TYPE_NONE,
                                 &ib->remote_netdev);
            if (retval) {
                VLOG_WARN_RL(&rl, "cannot open netdev %s (next hop "
                             "to controller "IP_FMT"): %s",
                             next_hop_dev, IP_ARGS(&ib->controller_ip),
                             strerror(retval));
                ib->next_remote_refresh = now + 1;
                return NULL;
            }
        }

        /* Look up the MAC address of the next-hop IP address. */
        retval = netdev_arp_lookup(ib->remote_netdev, r_in4.s_addr,
                                   ib->remote_mac);
        if (retval) {
            VLOG_DBG_RL(&rl, "cannot look up remote MAC address ("IP_FMT"): %s",
                        IP_ARGS(&r_in4.s_addr), strerror(retval));
        }
        have_mac = !eth_addr_is_zero(ib->remote_mac);
        free(next_hop_dev);
        if (have_mac
            && !eth_addr_equals(ib->last_remote_mac, ib->remote_mac)) {
            VLOG_DBG("remote MAC address changed from "ETH_ADDR_FMT" to "
                     ETH_ADDR_FMT,
                     ETH_ADDR_ARGS(ib->last_remote_mac),
                     ETH_ADDR_ARGS(ib->remote_mac));
            memcpy(ib->last_remote_mac, ib->remote_mac, ETH_ADDR_LEN);
        }

        /* Schedule next refresh.
         *
         * If we have an IP address but not a MAC address, then refresh
         * quickly, since we probably will get a MAC address soon (via ARP).
         * Otherwise, we can afford to wait a little while. */
        ib->next_remote_refresh 
                = now + (!ib->controller_ip || have_mac ? 10 : 1);
    }

    return !eth_addr_is_zero(ib->remote_mac) ? ib->remote_mac : NULL;
}

static const uint8_t *
get_local_mac(struct in_band *ib)
{
    time_t now = time_now();
    if (now >= ib->next_local_refresh) {
        uint8_t ea[ETH_ADDR_LEN];
        if (ib->local_netdev && !netdev_get_etheraddr(ib->local_netdev, ea)) {
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

    if (!eth_addr_is_zero(in_band->local_mac)) {
        status_reply_put(sr, "local-mac="ETH_ADDR_FMT,
                         ETH_ADDR_ARGS(in_band->local_mac));
    }

    if (!eth_addr_is_zero(in_band->remote_mac)) {
        status_reply_put(sr, "remote-mac="ETH_ADDR_FMT,
                         ETH_ADDR_ARGS(in_band->remote_mac));
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

/* Returns true if 'packet' should be sent to the local port regardless
 * of the flow table. */ 
bool
in_band_msg_in_hook(struct in_band *in_band, const flow_t *flow, 
                    const struct ofpbuf *packet)
{
    if (!in_band) {
        return false;
    }

    /* Regardless of how the flow table is configured, we want to be
     * able to see replies to our DHCP requests. */
    if (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IP_TYPE_UDP
            && flow->tp_src == htons(DHCP_SERVER_PORT)
            && flow->tp_dst == htons(DHCP_CLIENT_PORT)
            && packet->l7) {
        struct dhcp_header *dhcp;
        const uint8_t *local_mac;

        dhcp = ofpbuf_at(packet, (char *)packet->l7 - (char *)packet->data,
                         sizeof *dhcp);
        if (!dhcp) {
            return false;
        }

        local_mac = get_local_mac(in_band);
        if (eth_addr_equals(dhcp->chaddr, local_mac)) {
            return true;
        }
    }

    return false;
}

/* Returns true if the rule that would match 'flow' with 'actions' is 
 * allowed to be set up in the datapath. */
bool
in_band_rule_check(struct in_band *in_band, const flow_t *flow,
                   const struct odp_actions *actions)
{
    if (!in_band) {
        return true;
    }

    /* Don't allow flows that would prevent DHCP replies from being seen
     * by the local port. */
    if (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IP_TYPE_UDP
            && flow->tp_src == htons(DHCP_SERVER_PORT) 
            && flow->tp_dst == htons(DHCP_CLIENT_PORT)) {
        int i;

        for (i=0; i<actions->n_actions; i++) {
            if (actions->actions[i].output.type == ODPAT_OUTPUT 
                    && actions->actions[i].output.port == ODPP_LOCAL) {
                return true;
            }   
        }
        return false;
    }

    return true;
}

void
in_band_run(struct in_band *in_band)
{
    time_t now = time_now();
    uint32_t controller_ip;
    const uint8_t *remote_mac;
    const uint8_t *local_mac;
    flow_t flow;

    if (now < in_band->next_remote_refresh 
            && now < in_band->next_local_refresh) {
        return;
    }

    controller_ip = rconn_get_remote_ip(in_band->controller);
    if (in_band->controller_ip && controller_ip != in_band->controller_ip) {
        VLOG_DBG("controller IP address changed from "IP_FMT" to "IP_FMT, 
                 IP_ARGS(&in_band->controller_ip),
                 IP_ARGS(&controller_ip));
    }
    in_band->controller_ip = controller_ip;

    remote_mac = get_remote_mac(in_band);
    local_mac = get_local_mac(in_band);

    if (local_mac) {
        /* Allow DHCP requests to be sent from the local port. */
        memset(&flow, 0, sizeof flow);
        flow.in_port = ODPP_LOCAL;
        flow.dl_type = htons(ETH_TYPE_IP);
        memcpy(flow.dl_src, local_mac, ETH_ADDR_LEN);
        flow.nw_proto = IP_TYPE_UDP;
        flow.tp_src = htons(DHCP_CLIENT_PORT);
        flow.tp_dst = htons(DHCP_SERVER_PORT);
        setup_flow(in_band, IBR_FROM_LOCAL_DHCP, &flow,
                   (OFPFW_IN_PORT | OFPFW_DL_TYPE | OFPFW_DL_SRC
                    | OFPFW_NW_PROTO | OFPFW_TP_SRC | OFPFW_TP_DST), 
                   OFPP_NORMAL);

        /* Allow the connection's interface to receive directed ARP traffic. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_dst, local_mac, ETH_ADDR_LEN);
        flow.nw_proto = ARP_OP_REPLY;
        setup_flow(in_band, IBR_TO_LOCAL_ARP, &flow,
                   (OFPFW_DL_TYPE | OFPFW_DL_DST | OFPFW_NW_PROTO), 
                   OFPP_NORMAL);

        /* Allow the connection's interface to be the source of ARP traffic. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_src, local_mac, ETH_ADDR_LEN);
        flow.nw_proto = ARP_OP_REQUEST;
        setup_flow(in_band, IBR_FROM_LOCAL_ARP, &flow,
                   (OFPFW_DL_TYPE | OFPFW_DL_SRC | OFPFW_NW_PROTO),
                   OFPP_NORMAL);
    } else {
        drop_flow(in_band, IBR_TO_LOCAL_ARP);
        drop_flow(in_band, IBR_FROM_LOCAL_ARP);
    }

    if (remote_mac) {
        /* Allow ARP replies to the remote side's MAC. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_dst, remote_mac, ETH_ADDR_LEN);
        flow.nw_proto = ARP_OP_REPLY;
        setup_flow(in_band, IBR_TO_REMOTE_ARP, &flow,
                   (OFPFW_DL_TYPE | OFPFW_DL_DST | OFPFW_NW_PROTO), 
                   OFPP_NORMAL);

       /* Allow ARP requests from the remote side's MAC. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_src, remote_mac, ETH_ADDR_LEN);
        flow.nw_proto = ARP_OP_REQUEST;
        setup_flow(in_band, IBR_FROM_REMOTE_ARP, &flow,
                   (OFPFW_DL_TYPE | OFPFW_DL_SRC | OFPFW_NW_PROTO), 
                   OFPP_NORMAL);
    } else {
        drop_flow(in_band, IBR_TO_REMOTE_ARP);
        drop_flow(in_band, IBR_FROM_REMOTE_ARP);
    }

    if (controller_ip) {
        /* Allow ARP replies to the controller's IP. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        flow.nw_proto = ARP_OP_REPLY;
        flow.nw_dst = controller_ip;
        setup_flow(in_band, IBR_TO_CTL_ARP, &flow,
                   (OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_NW_DST_MASK),
                   OFPP_NORMAL);

       /* Allow ARP requests from the controller's IP. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        flow.nw_proto = ARP_OP_REQUEST;
        flow.nw_src = controller_ip;
        setup_flow(in_band, IBR_FROM_CTL_ARP, &flow,
                   (OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_NW_SRC_MASK),
                   OFPP_NORMAL);
     
        /* OpenFlow traffic to or from the controller.
         *
         * (A given field's value is completely ignored if it is wildcarded,
         * which is why we can get away with using a single 'flow' in each
         * case here.) */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_IP);
        flow.nw_proto = IP_TYPE_TCP;
        flow.nw_src = controller_ip;
        flow.nw_dst = controller_ip;
        flow.tp_src = htons(OFP_TCP_PORT);
        flow.tp_dst = htons(OFP_TCP_PORT);
        setup_flow(in_band, IBR_TO_CTL_OFP, &flow,
                   (OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_NW_DST_MASK 
                    | OFPFW_TP_DST), OFPP_NORMAL);
        setup_flow(in_band, IBR_FROM_CTL_OFP, &flow,
                   (OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_NW_SRC_MASK
                    | OFPFW_TP_SRC), OFPP_NORMAL);
    } else {
        drop_flow(in_band, IBR_TO_CTL_ARP);
        drop_flow(in_band, IBR_FROM_CTL_ARP);
        drop_flow(in_band, IBR_TO_CTL_OFP);
        drop_flow(in_band, IBR_FROM_CTL_OFP);
    }
}

void
in_band_wait(struct in_band *in_band)
{
    time_t now = time_now();
    time_t wakeup 
            = MIN(in_band->next_remote_refresh, in_band->next_local_refresh);
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

int
in_band_create(struct ofproto *ofproto, struct dpif *dpif,
               struct switch_status *ss, struct rconn *controller, 
               struct in_band **in_bandp)
{
    struct in_band *in_band;
    char local_name[IF_NAMESIZE];
    struct netdev *local_netdev;
    int error;

    error = dpif_port_get_name(dpif, ODPP_LOCAL,
                               local_name, sizeof local_name);
    if (error) {
        VLOG_ERR("failed to initialize in-band control: cannot get name "
                 "of datapath local port (%s)", strerror(error));
        return error;
    }

    error = netdev_open(local_name, NETDEV_ETH_TYPE_NONE, &local_netdev);
    if (error) {
        VLOG_ERR("failed to initialize in-band control: cannot open "
                 "datapath local port %s (%s)", local_name, strerror(error));
        return error;
    }

    in_band = xcalloc(1, sizeof *in_band);
    in_band->ofproto = ofproto;
    in_band->controller = controller;
    in_band->ss_cat = switch_status_register(ss, "in-band",
                                             in_band_status_cb, in_band);
    in_band->local_netdev = local_netdev;
    in_band->next_local_refresh = TIME_MIN;
    in_band->remote_netdev = NULL;
    in_band->next_remote_refresh = TIME_MIN;

    *in_bandp = in_band;

    return 0;
}

void
in_band_destroy(struct in_band *in_band)
{
    if (in_band) {
        switch_status_unregister(in_band->ss_cat);
        netdev_close(in_band->local_netdev);
        netdev_close(in_band->remote_netdev);
        /* We don't own the rconn. */
    }
}

