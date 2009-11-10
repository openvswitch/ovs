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

/* In-band control allows a single network to be used for OpenFlow
 * traffic and other data traffic.  Refer to ovs-vswitchd.conf(5) and 
 * secchan(8) for a description of configuring in-band control.
 *
 * This comment is an attempt to describe how in-band control works at a
 * wire- and implementation-level.  Correctly implementing in-band
 * control has proven difficult due to its many subtleties, and has thus
 * gone through many iterations.  Please read through and understand the
 * reasoning behind the chosen rules before making modifications.
 *
 * In Open vSwitch, in-band control is implemented as "hidden" flows (in
 * that they are not visible through OpenFlow) and at a higher priority
 * than wildcarded flows can be set up by the controller.  This is done
 * so that the controller cannot interfere with them and possibly break 
 * connectivity with its switches.  It is possible to see all flows, 
 * including in-band ones, with the ovs-appctl "bridge/dump-flows" 
 * command.
 *
 * The following rules are always enabled with the "normal" action by a 
 * switch with in-band control:
 *
 *    a. DHCP requests sent from the local port.
 *    b. ARP replies to the local port's MAC address.
 *    c. ARP requests from the local port's MAC address.
 *    d. ARP replies to the remote side's MAC address.  Note that the 
 *       remote side is either the controller or the gateway to reach 
 *       the controller.
 *    e. ARP requests from the remote side's MAC address.  Note that
 *       like (d), the MAC is either for the controller or gateway.
 *    f. ARP replies containing the controller's IP address as a target.
 *    g. ARP requests containing the controller's IP address as a source.
 *    h. OpenFlow (6633/tcp) traffic to the controller's IP.
 *    i. OpenFlow (6633/tcp) traffic from the controller's IP.
 *
 * The goal of these rules is to be as narrow as possible to allow a
 * switch to join a network and be able to communicate with a
 * controller.  As mentioned earlier, these rules have higher priority
 * than the controller's rules, so if they are too broad, they may 
 * prevent the controller from implementing its policy.  As such,
 * in-band actively monitors some aspects of flow and packet processing
 * so that the rules can be made more precise.
 *
 * In-band control monitors attempts to add flows into the datapath that
 * could interfere with its duties.  The datapath only allows exact
 * match entries, so in-band control is able to be very precise about
 * the flows it prevents.  Flows that miss in the datapath are sent to
 * userspace to be processed, so preventing these flows from being
 * cached in the "fast path" does not affect correctness.  The only type 
 * of flow that is currently prevented is one that would prevent DHCP 
 * replies from being seen by the local port.  For example, a rule that 
 * forwarded all DHCP traffic to the controller would not be allowed, 
 * but one that forwarded to all ports (including the local port) would.
 *
 * As mentioned earlier, packets that miss in the datapath are sent to
 * the userspace for processing.  The userspace has its own flow table,
 * the "classifier", so in-band checks whether any special processing 
 * is needed before the classifier is consulted.  If a packet is a DHCP 
 * response to a request from the local port, the packet is forwarded to 
 * the local port, regardless of the flow table.  Note that this requires 
 * L7 processing of DHCP replies to determine whether the 'chaddr' field 
 * matches the MAC address of the local port.
 *
 * It is interesting to note that for an L3-based in-band control
 * mechanism, the majority of rules are devoted to ARP traffic.  At first 
 * glance, some of these rules appear redundant.  However, each serves an 
 * important role.  First, in order to determine the MAC address of the 
 * remote side (controller or gateway) for other ARP rules, we must allow 
 * ARP traffic for our local port with rules (b) and (c).  If we are 
 * between a switch and its connection to the controller, we have to 
 * allow the other switch's ARP traffic to through.  This is done with 
 * rules (d) and (e), since we do not know the addresses of the other
 * switches a priori, but do know the controller's or gateway's.  Finally, 
 * if the controller is running in a local guest VM that is not reached 
 * through the local port, the switch that is connected to the VM must 
 * allow ARP traffic based on the controller's IP address, since it will 
 * not know the MAC address of the local port that is sending the traffic 
 * or the MAC address of the controller in the guest VM.
 *
 * With a few notable exceptions below, in-band should work in most
 * network setups.  The following are considered "supported' in the
 * current implementation: 
 *
 *    - Locally Connected.  The switch and controller are on the same
 *      subnet.  This uses rules (a), (b), (c), (h), and (i).
 *
 *    - Reached through Gateway.  The switch and controller are on
 *      different subnets and must go through a gateway.  This uses
 *      rules (a), (b), (c), (h), and (i).
 *
 *    - Between Switch and Controller.  This switch is between another
 *      switch and the controller, and we want to allow the other
 *      switch's traffic through.  This uses rules (d), (e), (h), and
 *      (i).  It uses (b) and (c) indirectly in order to know the MAC
 *      address for rules (d) and (e).  Note that DHCP for the other
 *      switch will not work unless the controller explicitly lets this 
 *      switch pass the traffic.
 *
 *    - Between Switch and Gateway.  This switch is between another
 *      switch and the gateway, and we want to allow the other switch's
 *      traffic through.  This uses the same rules and logic as the
 *      "Between Switch and Controller" configuration described earlier.
 *
 *    - Controller on Local VM.  The controller is a guest VM on the
 *      system running in-band control.  This uses rules (a), (b), (c), 
 *      (h), and (i).
 *
 *    - Controller on Local VM with Different Networks.  The controller
 *      is a guest VM on the system running in-band control, but the
 *      local port is not used to connect to the controller.  For
 *      example, an IP address is configured on eth0 of the switch.  The
 *      controller's VM is connected through eth1 of the switch, but an
 *      IP address has not been configured for that port on the switch.
 *      As such, the switch will use eth0 to connect to the controller,
 *      and eth1's rules about the local port will not work.  In the
 *      example, the switch attached to eth0 would use rules (a), (b), 
 *      (c), (h), and (i) on eth0.  The switch attached to eth1 would use 
 *      rules (f), (g), (h), and (i).
 *
 * The following are explicitly *not* supported by in-band control:
 *
 *    - Specify Controller by Name.  Currently, the controller must be 
 *      identified by IP address.  A naive approach would be to permit
 *      all DNS traffic.  Unfortunately, this would prevent the
 *      controller from defining any policy over DNS.  Since switches
 *      that are located behind us need to connect to the controller, 
 *      in-band cannot simply add a rule that allows DNS traffic from
 *      the local port.  The "correct" way to support this is to parse
 *      DNS requests to allow all traffic related to a request for the
 *      controller's name through.  Due to the potential security
 *      problems and amount of processing, we decided to hold off for
 *      the time-being.
 *
 *    - Multiple Controllers.  There is nothing intrinsic in the high-
 *      level design that prevents using multiple (known) controllers, 
 *      however, the current implementation's data structures assume
 *      only one.
 *
 *    - Differing Controllers for Switches.  All switches must know
 *      the L3 addresses for all the controllers that other switches 
 *      may use, since rules need to be set up to allow traffic related
 *      to those controllers through.  See rules (f), (g), (h), and (i).
 *
 *    - Differing Routes for Switches.  In order for the switch to 
 *      allow other switches to connect to a controller through a 
 *      gateway, it allows the gateway's traffic through with rules (d)
 *      and (e).  If the routes to the controller differ for the two
 *      switches, we will not know the MAC address of the alternate 
 *      gateway.
 */

#define IB_BASE_PRIORITY 18181800

enum {
    IBR_FROM_LOCAL_DHCP,          /* (a) From local port, DHCP. */
    IBR_TO_LOCAL_ARP,             /* (b) To local port, ARP. */
    IBR_FROM_LOCAL_ARP,           /* (c) From local port, ARP. */
    IBR_TO_REMOTE_ARP,            /* (d) To remote MAC, ARP. */
    IBR_FROM_REMOTE_ARP,          /* (e) From remote MAC, ARP. */
    IBR_TO_CTL_ARP,               /* (f) To controller IP, ARP. */
    IBR_FROM_CTL_ARP,             /* (g) From controller IP, ARP. */
    IBR_TO_CTL_OFP,               /* (h) To controller, OpenFlow port. */
    IBR_FROM_CTL_OFP,             /* (i) From controller, OpenFlow port. */
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
set_up_flow(struct in_band *in_band, int rule_idx, const flow_t *flow,
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
        set_up_flow(in_band, IBR_FROM_LOCAL_DHCP, &flow,
                    (OFPFW_IN_PORT | OFPFW_DL_TYPE | OFPFW_DL_SRC
                     | OFPFW_NW_PROTO | OFPFW_TP_SRC | OFPFW_TP_DST), 
                    OFPP_NORMAL);

        /* Allow the connection's interface to receive directed ARP traffic. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_dst, local_mac, ETH_ADDR_LEN);
        flow.nw_proto = ARP_OP_REPLY;
        set_up_flow(in_band, IBR_TO_LOCAL_ARP, &flow,
                    (OFPFW_DL_TYPE | OFPFW_DL_DST | OFPFW_NW_PROTO), 
                    OFPP_NORMAL);

        /* Allow the connection's interface to be the source of ARP traffic. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_src, local_mac, ETH_ADDR_LEN);
        flow.nw_proto = ARP_OP_REQUEST;
        set_up_flow(in_band, IBR_FROM_LOCAL_ARP, &flow,
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
        set_up_flow(in_band, IBR_TO_REMOTE_ARP, &flow,
                    (OFPFW_DL_TYPE | OFPFW_DL_DST | OFPFW_NW_PROTO), 
                    OFPP_NORMAL);

       /* Allow ARP requests from the remote side's MAC. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        memcpy(flow.dl_src, remote_mac, ETH_ADDR_LEN);
        flow.nw_proto = ARP_OP_REQUEST;
        set_up_flow(in_band, IBR_FROM_REMOTE_ARP, &flow,
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
        set_up_flow(in_band, IBR_TO_CTL_ARP, &flow,
                    (OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_NW_DST_MASK),
                    OFPP_NORMAL);

       /* Allow ARP requests from the controller's IP. */
        memset(&flow, 0, sizeof flow);
        flow.dl_type = htons(ETH_TYPE_ARP);
        flow.nw_proto = ARP_OP_REQUEST;
        flow.nw_src = controller_ip;
        set_up_flow(in_band, IBR_FROM_CTL_ARP, &flow,
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
        set_up_flow(in_band, IBR_TO_CTL_OFP, &flow,
                    (OFPFW_DL_TYPE | OFPFW_NW_PROTO | OFPFW_NW_DST_MASK 
                     | OFPFW_TP_DST), OFPP_NORMAL);
        set_up_flow(in_band, IBR_FROM_CTL_OFP, &flow,
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

