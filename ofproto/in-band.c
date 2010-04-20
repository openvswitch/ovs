/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

/* Priorities used in classifier for in-band rules.  These values are higher
 * than any that may be set with OpenFlow, and "18" kind of looks like "IB".
 * The ordering of priorities is not important because all of the rules set up
 * by in-band control have the same action.  The only reason to use more than
 * one priority is to make the kind of flow easier to see during debugging. */
enum {
    IBR_FROM_LOCAL_DHCP = 180000, /* (a) From local port, DHCP. */
    IBR_TO_LOCAL_ARP,             /* (b) To local port, ARP. */
    IBR_FROM_LOCAL_ARP,           /* (c) From local port, ARP. */
    IBR_TO_REMOTE_ARP,            /* (d) To remote MAC, ARP. */
    IBR_FROM_REMOTE_ARP,          /* (e) From remote MAC, ARP. */
    IBR_TO_CTL_ARP,               /* (f) To controller IP, ARP. */
    IBR_FROM_CTL_ARP,             /* (g) From controller IP, ARP. */
    IBR_TO_CTL_OFP,               /* (h) To controller, OpenFlow port. */
    IBR_FROM_CTL_OFP              /* (i) From controller, OpenFlow port. */
};

struct in_band_rule {
    flow_t flow;
    uint32_t wildcards;
    unsigned int priority;
};

/* Track one remote IP and next hop information. */
struct in_band_remote {
    struct rconn *rconn;              /* Connection to remote. */
    uint32_t remote_ip;               /* Remote IP, 0 if unknown. */
    uint8_t remote_mac[ETH_ADDR_LEN]; /* Next-hop MAC, all-zeros if unknown. */
    uint8_t last_remote_mac[ETH_ADDR_LEN]; /* Previous nonzero next-hop MAC. */
    struct netdev *remote_netdev; /* Device to send to next-hop MAC. */
};

struct in_band {
    struct ofproto *ofproto;
    struct status_category *ss_cat;

    /* Remote information. */
    time_t next_remote_refresh; /* Refresh timer. */
    struct in_band_remote *remotes;
    size_t n_remotes;

    /* Local information. */
    time_t next_local_refresh;       /* Refresh timer. */
    uint8_t local_mac[ETH_ADDR_LEN]; /* Current MAC. */
    struct netdev *local_netdev;     /* Local port's network device. */

    /* Local and remote addresses that are installed as flows. */
    uint8_t installed_local_mac[ETH_ADDR_LEN];
    uint32_t *remote_ips;
    uint32_t n_remote_ips;
    uint8_t *remote_macs;
    size_t n_remote_macs;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static int
refresh_remote(struct in_band *ib, struct in_band_remote *r)
{
    struct in_addr remote_inaddr;
    struct in_addr next_hop_inaddr;
    char *next_hop_dev;
    int retval;

    memset(r->remote_mac, 0, sizeof r->remote_mac);

    /* Get remote IP address. */
    r->remote_ip = rconn_get_remote_ip(r->rconn);
    if (!r->remote_ip) {
        /* No remote IP address means that this rconn is probably either
         * configured for a non-IP based protocol (e.g. "unix:") or
         * misconfigured entirely.  No point in refreshing quickly. */
        return 10;
    }

    /* Find the next-hop IP address. */
    remote_inaddr.s_addr = r->remote_ip;
    retval = netdev_get_next_hop(ib->local_netdev, &remote_inaddr,
                                 &next_hop_inaddr, &next_hop_dev);
    if (retval) {
        VLOG_WARN("cannot find route for controller ("IP_FMT"): %s",
                  IP_ARGS(&r->remote_ip), strerror(retval));
        return 1;
    }
    if (!next_hop_inaddr.s_addr) {
        next_hop_inaddr.s_addr = remote_inaddr.s_addr;
    }

    /* Get the next-hop IP and network device. */
    if (!r->remote_netdev
        || strcmp(netdev_get_name(r->remote_netdev), next_hop_dev))
    {
        netdev_close(r->remote_netdev);

        retval = netdev_open_default(next_hop_dev, &r->remote_netdev);
        if (retval) {
            VLOG_WARN_RL(&rl, "cannot open netdev %s (next hop "
                         "to controller "IP_FMT"): %s",
                         next_hop_dev, IP_ARGS(&r->remote_ip),
                         strerror(retval));
            free(next_hop_dev);
            return 1;
        }
    }
    free(next_hop_dev);

    /* Look up the MAC address of the next-hop IP address. */
    retval = netdev_arp_lookup(r->remote_netdev, next_hop_inaddr.s_addr,
                               r->remote_mac);
    if (retval) {
        VLOG_DBG_RL(&rl, "cannot look up remote MAC address ("IP_FMT"): %s",
                    IP_ARGS(&next_hop_inaddr.s_addr), strerror(retval));
    }

    /* If we don't have a MAC address, then refresh quickly, since we probably
     * will get a MAC address soon (via ARP).  Otherwise, we can afford to wait
     * a little while. */
    return eth_addr_is_zero(r->remote_mac) ? 1 : 10;
}

static bool
refresh_remotes(struct in_band *ib)
{
    struct in_band_remote *r;
    bool any_changes;

    if (time_now() < ib->next_remote_refresh) {
        return false;
    }

    any_changes = false;
    ib->next_remote_refresh = TIME_MAX;
    for (r = ib->remotes; r < &ib->remotes[ib->n_remotes]; r++) {
        uint8_t old_remote_mac[ETH_ADDR_LEN];
        time_t next_refresh;

        /* Save old MAC. */
        memcpy(old_remote_mac, r->remote_mac, ETH_ADDR_LEN);

        /* Refresh remote information. */
        next_refresh = refresh_remote(ib, r) + time_now();
        ib->next_remote_refresh = MIN(ib->next_remote_refresh, next_refresh);

        /* If the MAC changed, log the changes. */
        if (!eth_addr_equals(r->remote_mac, old_remote_mac)) {
            any_changes = true;
            if (!eth_addr_is_zero(r->remote_mac)
                && !eth_addr_equals(r->last_remote_mac, r->remote_mac)) {
                VLOG_DBG("remote MAC address changed from "ETH_ADDR_FMT
                         " to "ETH_ADDR_FMT,
                         ETH_ADDR_ARGS(r->last_remote_mac),
                         ETH_ADDR_ARGS(r->remote_mac));
                memcpy(r->last_remote_mac, r->remote_mac, ETH_ADDR_LEN);
            }
        }
    }

    return any_changes;
}

/* Refreshes the MAC address of the local port into ib->local_mac, if it is due
 * for a refresh.  Returns true if anything changed, otherwise false.  */
static bool
refresh_local(struct in_band *ib)
{
    uint8_t ea[ETH_ADDR_LEN];
    time_t now;

    now = time_now();
    if (now < ib->next_local_refresh) {
        return false;
    }
    ib->next_local_refresh = now + 1;

    if (netdev_get_etheraddr(ib->local_netdev, ea)
        || eth_addr_equals(ea, ib->local_mac)) {
        return false;
    }

    memcpy(ib->local_mac, ea, ETH_ADDR_LEN);
    return true;
}

static void
in_band_status_cb(struct status_reply *sr, void *in_band_)
{
    struct in_band *in_band = in_band_;

    if (!eth_addr_is_zero(in_band->local_mac)) {
        status_reply_put(sr, "local-mac="ETH_ADDR_FMT,
                         ETH_ADDR_ARGS(in_band->local_mac));
    }

    if (in_band->n_remotes
        && !eth_addr_is_zero(in_band->remotes[0].remote_mac)) {
        status_reply_put(sr, "remote-mac="ETH_ADDR_FMT,
                         ETH_ADDR_ARGS(in_band->remotes[0].remote_mac));
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

        dhcp = ofpbuf_at(packet, (char *)packet->l7 - (char *)packet->data,
                         sizeof *dhcp);
        if (!dhcp) {
            return false;
        }

        refresh_local(in_band);
        if (!eth_addr_is_zero(in_band->local_mac)
            && eth_addr_equals(dhcp->chaddr, in_band->local_mac)) {
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

static void
init_rule(struct in_band_rule *rule, unsigned int priority)
{
    rule->wildcards = OVSFW_ALL;
    rule->priority = priority;

    /* Not strictly necessary but seems cleaner. */
    memset(&rule->flow, 0, sizeof rule->flow);
}

static void
set_in_port(struct in_band_rule *rule, uint16_t odp_port)
{
    rule->wildcards &= ~OFPFW_IN_PORT;
    rule->flow.in_port = odp_port;
}

static void
set_dl_type(struct in_band_rule *rule, uint16_t dl_type)
{
    rule->wildcards &= ~OFPFW_DL_TYPE;
    rule->flow.dl_type = htons(dl_type);
}

static void
set_dl_src(struct in_band_rule *rule, const uint8_t dl_src[ETH_ADDR_LEN])
{
    rule->wildcards &= ~OFPFW_DL_SRC;
    memcpy(rule->flow.dl_src, dl_src, ETH_ADDR_LEN);
}

static void
set_dl_dst(struct in_band_rule *rule, const uint8_t dl_dst[ETH_ADDR_LEN])
{
    rule->wildcards &= ~OFPFW_DL_DST;
    memcpy(rule->flow.dl_dst, dl_dst, ETH_ADDR_LEN);
}

static void
set_tp_src(struct in_band_rule *rule, uint16_t tp_src)
{
    rule->wildcards &= ~OFPFW_TP_SRC;
    rule->flow.tp_src = htons(tp_src);
}

static void
set_tp_dst(struct in_band_rule *rule, uint16_t tp_dst)
{
    rule->wildcards &= ~OFPFW_TP_DST;
    rule->flow.tp_dst = htons(tp_dst);
}

static void
set_nw_proto(struct in_band_rule *rule, uint8_t nw_proto)
{
    rule->wildcards &= ~OFPFW_NW_PROTO;
    rule->flow.nw_proto = nw_proto;
}

static void
set_nw_src(struct in_band_rule *rule, uint32_t nw_src)
{
    rule->wildcards &= ~OFPFW_NW_SRC_MASK;
    rule->flow.nw_src = nw_src;
}

static void
set_nw_dst(struct in_band_rule *rule, uint32_t nw_dst)
{
    rule->wildcards &= ~OFPFW_NW_DST_MASK;
    rule->flow.nw_dst = nw_dst;
}

static void
make_rules(struct in_band *ib,
           void (*cb)(struct in_band *, const struct in_band_rule *))
{
    struct in_band_rule rule;
    size_t i;

    if (!eth_addr_is_zero(ib->installed_local_mac)) {
        /* Allow DHCP requests to be sent from the local port. */
        init_rule(&rule, IBR_FROM_LOCAL_DHCP);
        set_in_port(&rule, ODPP_LOCAL);
        set_dl_type(&rule, ETH_TYPE_IP);
        set_dl_src(&rule, ib->installed_local_mac);
        set_nw_proto(&rule, IP_TYPE_UDP);
        set_tp_src(&rule, DHCP_CLIENT_PORT);
        set_tp_dst(&rule, DHCP_SERVER_PORT);
        cb(ib, &rule);

        /* Allow the connection's interface to receive directed ARP traffic. */
        init_rule(&rule, IBR_TO_LOCAL_ARP);
        set_dl_type(&rule, ETH_TYPE_ARP);
        set_dl_dst(&rule, ib->installed_local_mac);
        set_nw_proto(&rule, ARP_OP_REPLY);
        cb(ib, &rule);

        /* Allow the connection's interface to be the source of ARP traffic. */
        init_rule(&rule, IBR_FROM_LOCAL_ARP);
        set_dl_type(&rule, ETH_TYPE_ARP);
        set_dl_src(&rule, ib->installed_local_mac);
        set_nw_proto(&rule, ARP_OP_REQUEST);
        cb(ib, &rule);
    }

    for (i = 0; i < ib->n_remote_macs; i++) {
        const uint8_t *remote_mac = &ib->remote_macs[i * ETH_ADDR_LEN];

        if (i > 0) {
            const uint8_t *prev_mac = &ib->remote_macs[(i - 1) * ETH_ADDR_LEN];
            if (eth_addr_equals(remote_mac, prev_mac)) {
                /* Skip duplicates. */
                continue;
            }
        }

        /* Allow ARP replies to the remote side's MAC. */
        init_rule(&rule, IBR_TO_REMOTE_ARP);
        set_dl_type(&rule, ETH_TYPE_ARP);
        set_dl_dst(&rule, remote_mac);
        set_nw_proto(&rule, ARP_OP_REPLY);
        cb(ib, &rule);

        /* Allow ARP requests from the remote side's MAC. */
        init_rule(&rule, IBR_FROM_REMOTE_ARP);
        set_dl_type(&rule, ETH_TYPE_ARP);
        set_dl_src(&rule, remote_mac);
        set_nw_proto(&rule, ARP_OP_REQUEST);
        cb(ib, &rule);
    }

    for (i = 0; i < ib->n_remote_ips; i++) {
        uint32_t remote_ip = ib->remote_ips[i];

        if (i > 0 && ib->remote_ips[i - 1] == remote_ip) {
            /* Skip duplicates. */
            continue;
        }

        /* Allow ARP replies to the controller's IP. */
        init_rule(&rule, IBR_TO_CTL_ARP);
        set_dl_type(&rule, ETH_TYPE_ARP);
        set_nw_proto(&rule, ARP_OP_REPLY);
        set_nw_dst(&rule, remote_ip);
        cb(ib, &rule);

        /* Allow ARP requests from the controller's IP. */
        init_rule(&rule, IBR_FROM_CTL_ARP);
        set_dl_type(&rule, ETH_TYPE_ARP);
        set_nw_proto(&rule, ARP_OP_REQUEST);
        set_nw_src(&rule, remote_ip);
        cb(ib, &rule);

        /* OpenFlow traffic to the controller. */
        init_rule(&rule, IBR_TO_CTL_OFP);
        set_dl_type(&rule, ETH_TYPE_IP);
        set_nw_proto(&rule, IP_TYPE_TCP);
        set_nw_dst(&rule, remote_ip);
        set_tp_dst(&rule, OFP_TCP_PORT);
        cb(ib, &rule);

        /* OpenFlow traffic from the controller. */
        init_rule(&rule, IBR_FROM_CTL_OFP);
        set_dl_type(&rule, ETH_TYPE_IP);
        set_nw_proto(&rule, IP_TYPE_TCP);
        set_nw_src(&rule, remote_ip);
        set_tp_src(&rule, OFP_TCP_PORT);
        cb(ib, &rule);
    }
}

static void
clear_rules(struct in_band *ib)
{
    memset(ib->installed_local_mac, 0, sizeof ib->installed_local_mac);

    free(ib->remote_ips);
    ib->remote_ips = NULL;
    ib->n_remote_ips = 0;

    free(ib->remote_macs);
    ib->remote_macs = NULL;
    ib->n_remote_macs = 0;
}

static void
drop_rule(struct in_band *ib, const struct in_band_rule *rule)
{
    ofproto_delete_flow(ib->ofproto, &rule->flow,
                        rule->wildcards, rule->priority);
}

static void
drop_rules(struct in_band *ib)
{
    make_rules(ib, drop_rule);
    clear_rules(ib);
}

static void
add_rule(struct in_band *ib, const struct in_band_rule *rule)
{
    union ofp_action action;

    action.type = htons(OFPAT_OUTPUT);
    action.output.len = htons(sizeof action);
    action.output.port = htons(OFPP_NORMAL);
    action.output.max_len = htons(0);
    ofproto_add_flow(ib->ofproto, &rule->flow, rule->wildcards,
                     rule->priority, &action, 1, 0);
}

static void
add_rules(struct in_band *ib)
{
    make_rules(ib, add_rule);
}

static int
compare_ips(const void *a, const void *b)
{
    return memcmp(a, b, sizeof(uint32_t));
}

static int
compare_macs(const void *a, const void *b)
{
    return memcmp(a, b, ETH_ADDR_LEN);
}

void
in_band_run(struct in_band *ib)
{
    struct in_band_remote *r;
    bool local_change, remote_change;

    local_change = refresh_local(ib);
    remote_change = refresh_remotes(ib);
    if (!local_change && !remote_change) {
        /* Nothing changed, nothing to do. */
        return;
    }

    /* Drop old rules. */
    drop_rules(ib);

    /* Figure out new rules. */
    memcpy(ib->installed_local_mac, ib->local_mac, ETH_ADDR_LEN);
    ib->remote_ips = xmalloc(ib->n_remotes * sizeof *ib->remote_ips);
    ib->n_remote_ips = 0;
    ib->remote_macs = xmalloc(ib->n_remotes * ETH_ADDR_LEN);
    ib->n_remote_macs = 0;
    for (r = ib->remotes; r < &ib->remotes[ib->n_remotes]; r++) {
        if (r->remote_ip) {
            ib->remote_ips[ib->n_remote_ips++] = r->remote_ip;
        }
        if (!eth_addr_is_zero(r->remote_mac)) {
            memcpy(&ib->remote_macs[ib->n_remote_macs * ETH_ADDR_LEN],
                   r->remote_mac, ETH_ADDR_LEN);
            ib->n_remote_macs++;
        }
    }

    /* Sort, to allow make_rules() to easily skip duplicates. */
    qsort(ib->remote_ips, ib->n_remote_ips, sizeof *ib->remote_ips,
          compare_ips);
    qsort(ib->remote_macs, ib->n_remote_macs, ETH_ADDR_LEN, compare_macs);

    /* Add new rules. */
    add_rules(ib);
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

/* ofproto has flushed all flows from the flow table and it is calling us back
 * to allow us to reinstall the ones that are important to us. */
void
in_band_flushed(struct in_band *in_band)
{
    add_rules(in_band);
}

int
in_band_create(struct ofproto *ofproto, struct dpif *dpif,
               struct switch_status *ss, struct in_band **in_bandp)
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

    error = netdev_open_default(local_name, &local_netdev);
    if (error) {
        VLOG_ERR("failed to initialize in-band control: cannot open "
                 "datapath local port %s (%s)", local_name, strerror(error));
        return error;
    }

    in_band = xzalloc(sizeof *in_band);
    in_band->ofproto = ofproto;
    in_band->ss_cat = switch_status_register(ss, "in-band",
                                             in_band_status_cb, in_band);
    in_band->next_remote_refresh = TIME_MIN;
    in_band->next_local_refresh = TIME_MIN;
    in_band->local_netdev = local_netdev;

    *in_bandp = in_band;

    return 0;
}

void
in_band_destroy(struct in_band *ib)
{
    if (ib) {
        drop_rules(ib);
        in_band_set_remotes(ib, NULL, 0);
        switch_status_unregister(ib->ss_cat);
        netdev_close(ib->local_netdev);
        free(ib);
    }
}

void
in_band_set_remotes(struct in_band *ib, struct rconn **remotes, size_t n)
{
    size_t i;

    /* Optimize the case where the rconns are the same as last time. */
    if (n == ib->n_remotes) {
        for (i = 0; i < n; i++) {
            if (ib->remotes[i].rconn != remotes[i]) {
                goto different;
            }
        }
        return;

    different:;
    }

    for (i = 0; i < ib->n_remotes; i++) {
        /* We don't own the rconn. */
        netdev_close(ib->remotes[i].remote_netdev);
    }
    free(ib->remotes);

    ib->next_remote_refresh = TIME_MIN;
    ib->remotes = n ? xzalloc(n * sizeof *ib->remotes) : 0;
    ib->n_remotes = n;
    for (i = 0; i < n; i++) {
        ib->remotes[i].rconn = remotes[i];
    }
}
