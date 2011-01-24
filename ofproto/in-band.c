/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira Networks.
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
#include <sys/socket.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include "classifier.h"
#include "dhcp.h"
#include "dpif.h"
#include "flow.h"
#include "netdev.h"
#include "netlink.h"
#include "odp-util.h"
#include "ofproto.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "status.h"
#include "timeval.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(in_band);

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
 * In Open vSwitch, in-band control is implemented as "hidden" flows (in that
 * they are not visible through OpenFlow) and at a higher priority than
 * wildcarded flows can be set up by through OpenFlow.  This is done so that
 * the OpenFlow controller cannot interfere with them and possibly break
 * connectivity with its switches.  It is possible to see all flows, including
 * in-band ones, with the ovs-appctl "bridge/dump-flows" command.
 *
 * The Open vSwitch implementation of in-band control can hide traffic to
 * arbitrary "remotes", where each remote is one TCP port on one IP address.
 * Currently the remotes are automatically configured as the in-band OpenFlow
 * controllers plus the OVSDB managers, if any.  (The latter is a requirement
 * because OVSDB managers are responsible for configuring OpenFlow controllers,
 * so if the manager cannot be reached then OpenFlow cannot be reconfigured.)
 *
 * The following rules (with the OFPP_NORMAL action) are set up on any bridge
 * that has any remotes:
 *
 *    (a) DHCP requests sent from the local port.
 *    (b) ARP replies to the local port's MAC address.
 *    (c) ARP requests from the local port's MAC address.
 *
 * In-band also sets up the following rules for each unique next-hop MAC
 * address for the remotes' IPs (the "next hop" is either the remote
 * itself, if it is on a local subnet, or the gateway to reach the remote):
 *
 *    (d) ARP replies to the next hop's MAC address.
 *    (e) ARP requests from the next hop's MAC address.
 *
 * In-band also sets up the following rules for each unique remote IP address:
 *
 *    (f) ARP replies containing the remote's IP address as a target.
 *    (g) ARP requests containing the remote's IP address as a source.
 *
 * In-band also sets up the following rules for each unique remote (IP,port)
 * pair:
 *
 *    (h) TCP traffic to the remote's IP and port.
 *    (i) TCP traffic from the remote's IP and port.
 *
 * The goal of these rules is to be as narrow as possible to allow a
 * switch to join a network and be able to communicate with the
 * remotes.  As mentioned earlier, these rules have higher priority
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
 * between a switch and its connection to the remote, we have to
 * allow the other switch's ARP traffic to through.  This is done with
 * rules (d) and (e), since we do not know the addresses of the other
 * switches a priori, but do know the remote's or gateway's.  Finally,
 * if the remote is running in a local guest VM that is not reached
 * through the local port, the switch that is connected to the VM must
 * allow ARP traffic based on the remote's IP address, since it will
 * not know the MAC address of the local port that is sending the traffic
 * or the MAC address of the remote in the guest VM.
 *
 * With a few notable exceptions below, in-band should work in most
 * network setups.  The following are considered "supported' in the
 * current implementation:
 *
 *    - Locally Connected.  The switch and remote are on the same
 *      subnet.  This uses rules (a), (b), (c), (h), and (i).
 *
 *    - Reached through Gateway.  The switch and remote are on
 *      different subnets and must go through a gateway.  This uses
 *      rules (a), (b), (c), (h), and (i).
 *
 *    - Between Switch and Remote.  This switch is between another
 *      switch and the remote, and we want to allow the other
 *      switch's traffic through.  This uses rules (d), (e), (h), and
 *      (i).  It uses (b) and (c) indirectly in order to know the MAC
 *      address for rules (d) and (e).  Note that DHCP for the other
 *      switch will not work unless an OpenFlow controller explicitly lets this
 *      switch pass the traffic.
 *
 *    - Between Switch and Gateway.  This switch is between another
 *      switch and the gateway, and we want to allow the other switch's
 *      traffic through.  This uses the same rules and logic as the
 *      "Between Switch and Remote" configuration described earlier.
 *
 *    - Remote on Local VM.  The remote is a guest VM on the
 *      system running in-band control.  This uses rules (a), (b), (c),
 *      (h), and (i).
 *
 *    - Remote on Local VM with Different Networks.  The remote
 *      is a guest VM on the system running in-band control, but the
 *      local port is not used to connect to the remote.  For
 *      example, an IP address is configured on eth0 of the switch.  The
 *      remote's VM is connected through eth1 of the switch, but an
 *      IP address has not been configured for that port on the switch.
 *      As such, the switch will use eth0 to connect to the remote,
 *      and eth1's rules about the local port will not work.  In the
 *      example, the switch attached to eth0 would use rules (a), (b),
 *      (c), (h), and (i) on eth0.  The switch attached to eth1 would use
 *      rules (f), (g), (h), and (i).
 *
 * The following are explicitly *not* supported by in-band control:
 *
 *    - Specify Remote by Name.  Currently, the remote must be
 *      identified by IP address.  A naive approach would be to permit
 *      all DNS traffic.  Unfortunately, this would prevent the
 *      controller from defining any policy over DNS.  Since switches
 *      that are located behind us need to connect to the remote,
 *      in-band cannot simply add a rule that allows DNS traffic from
 *      the local port.  The "correct" way to support this is to parse
 *      DNS requests to allow all traffic related to a request for the
 *      remote's name through.  Due to the potential security
 *      problems and amount of processing, we decided to hold off for
 *      the time-being.
 *
 *    - Differing Remotes for Switches.  All switches must know
 *      the L3 addresses for all the remotes that other switches
 *      may use, since rules need to be set up to allow traffic related
 *      to those remotes through.  See rules (f), (g), (h), and (i).
 *
 *    - Differing Routes for Switches.  In order for the switch to
 *      allow other switches to connect to a remote through a
 *      gateway, it allows the gateway's traffic through with rules (d)
 *      and (e).  If the routes to the remote differ for the two
 *      switches, we will not know the MAC address of the alternate
 *      gateway.
 */

/* Priorities used in classifier for in-band rules.  These values are higher
 * than any that may be set with OpenFlow, and "18" kind of looks like "IB".
 * The ordering of priorities is not important because all of the rules set up
 * by in-band control have the same action.  The only reason to use more than
 * one priority is to make the kind of flow easier to see during debugging. */
enum {
    /* One set per bridge. */
    IBR_FROM_LOCAL_DHCP = 180000, /* (a) From local port, DHCP. */
    IBR_TO_LOCAL_ARP,             /* (b) To local port, ARP. */
    IBR_FROM_LOCAL_ARP,           /* (c) From local port, ARP. */

    /* One set per unique next-hop MAC. */
    IBR_TO_NEXT_HOP_ARP,          /* (d) To remote MAC, ARP. */
    IBR_FROM_NEXT_HOP_ARP,        /* (e) From remote MAC, ARP. */

    /* One set per unique remote IP address. */
    IBR_TO_REMOTE_ARP,            /* (f) To remote IP, ARP. */
    IBR_FROM_REMOTE_ARP,          /* (g) From remote IP, ARP. */

    /* One set per unique remote (IP,port) pair. */
    IBR_TO_REMOTE_TCP,            /* (h) To remote IP, TCP port. */
    IBR_FROM_REMOTE_TCP           /* (i) From remote IP, TCP port. */
};

/* Track one remote IP and next hop information. */
struct in_band_remote {
    struct sockaddr_in remote_addr; /* IP address, in network byte order. */
    uint8_t remote_mac[ETH_ADDR_LEN]; /* Next-hop MAC, all-zeros if unknown. */
    uint8_t last_remote_mac[ETH_ADDR_LEN]; /* Previous nonzero next-hop MAC. */
    struct netdev *remote_netdev; /* Device to send to next-hop MAC. */
};

struct in_band {
    struct ofproto *ofproto;
    struct status_category *ss_cat;
    int queue_id, prev_queue_id;

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
    struct sockaddr_in *remote_addrs;
    size_t n_remote_addrs;
    uint8_t *remote_macs;
    size_t n_remote_macs;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static int
refresh_remote(struct in_band *ib, struct in_band_remote *r)
{
    struct in_addr next_hop_inaddr;
    char *next_hop_dev;
    int retval;

    /* Find the next-hop IP address. */
    memset(r->remote_mac, 0, sizeof r->remote_mac);
    retval = netdev_get_next_hop(ib->local_netdev, &r->remote_addr.sin_addr,
                                 &next_hop_inaddr, &next_hop_dev);
    if (retval) {
        VLOG_WARN("cannot find route for controller ("IP_FMT"): %s",
                  IP_ARGS(&r->remote_addr.sin_addr), strerror(retval));
        return 1;
    }
    if (!next_hop_inaddr.s_addr) {
        next_hop_inaddr = r->remote_addr.sin_addr;
    }

    /* Open the next-hop network device. */
    if (!r->remote_netdev
        || strcmp(netdev_get_name(r->remote_netdev), next_hop_dev))
    {
        netdev_close(r->remote_netdev);

        retval = netdev_open_default(next_hop_dev, &r->remote_netdev);
        if (retval) {
            VLOG_WARN_RL(&rl, "cannot open netdev %s (next hop "
                         "to controller "IP_FMT"): %s",
                         next_hop_dev, IP_ARGS(&r->remote_addr.sin_addr),
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
in_band_msg_in_hook(struct in_band *in_band, const struct flow *flow,
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
in_band_rule_check(struct in_band *in_band, const struct flow *flow,
                   const struct nlattr *actions, size_t actions_len)
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
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH_UNSAFE (a, left, actions, actions_len) {
            if (nl_attr_type(a) == ODP_ACTION_ATTR_OUTPUT
                && nl_attr_get_u32(a) == ODPP_LOCAL) {
                return true;
            }
        }
        return false;
    }

    return true;
}

static void
make_rules(struct in_band *ib,
           void (*cb)(struct in_band *, const struct cls_rule *))
{
    struct cls_rule rule;
    size_t i;

    if (!eth_addr_is_zero(ib->installed_local_mac)) {
        /* (a) Allow DHCP requests sent from the local port. */
        cls_rule_init_catchall(&rule, IBR_FROM_LOCAL_DHCP);
        cls_rule_set_in_port(&rule, ODPP_LOCAL);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_IP));
        cls_rule_set_dl_src(&rule, ib->installed_local_mac);
        cls_rule_set_nw_proto(&rule, IP_TYPE_UDP);
        cls_rule_set_tp_src(&rule, htons(DHCP_CLIENT_PORT));
        cls_rule_set_tp_dst(&rule, htons(DHCP_SERVER_PORT));
        cb(ib, &rule);

        /* (b) Allow ARP replies to the local port's MAC address. */
        cls_rule_init_catchall(&rule, IBR_TO_LOCAL_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_dl_dst(&rule, ib->installed_local_mac);
        cls_rule_set_nw_proto(&rule, ARP_OP_REPLY);
        cb(ib, &rule);

        /* (c) Allow ARP requests from the local port's MAC address.  */
        cls_rule_init_catchall(&rule, IBR_FROM_LOCAL_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_dl_src(&rule, ib->installed_local_mac);
        cls_rule_set_nw_proto(&rule, ARP_OP_REQUEST);
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

        /* (d) Allow ARP replies to the next hop's MAC address. */
        cls_rule_init_catchall(&rule, IBR_TO_NEXT_HOP_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_dl_dst(&rule, remote_mac);
        cls_rule_set_nw_proto(&rule, ARP_OP_REPLY);
        cb(ib, &rule);

        /* (e) Allow ARP requests from the next hop's MAC address. */
        cls_rule_init_catchall(&rule, IBR_FROM_NEXT_HOP_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_dl_src(&rule, remote_mac);
        cls_rule_set_nw_proto(&rule, ARP_OP_REQUEST);
        cb(ib, &rule);
    }

    for (i = 0; i < ib->n_remote_addrs; i++) {
        const struct sockaddr_in *a = &ib->remote_addrs[i];

        if (!i || a->sin_addr.s_addr != a[-1].sin_addr.s_addr) {
            /* (f) Allow ARP replies containing the remote's IP address as a
             * target. */
            cls_rule_init_catchall(&rule, IBR_TO_REMOTE_ARP);
            cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
            cls_rule_set_nw_proto(&rule, ARP_OP_REPLY);
            cls_rule_set_nw_dst(&rule, a->sin_addr.s_addr);
            cb(ib, &rule);

            /* (g) Allow ARP requests containing the remote's IP address as a
             * source. */
            cls_rule_init_catchall(&rule, IBR_FROM_REMOTE_ARP);
            cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
            cls_rule_set_nw_proto(&rule, ARP_OP_REQUEST);
            cls_rule_set_nw_src(&rule, a->sin_addr.s_addr);
            cb(ib, &rule);
        }

        if (!i
            || a->sin_addr.s_addr != a[-1].sin_addr.s_addr
            || a->sin_port != a[-1].sin_port) {
            /* (h) Allow TCP traffic to the remote's IP and port. */
            cls_rule_init_catchall(&rule, IBR_TO_REMOTE_TCP);
            cls_rule_set_dl_type(&rule, htons(ETH_TYPE_IP));
            cls_rule_set_nw_proto(&rule, IP_TYPE_TCP);
            cls_rule_set_nw_dst(&rule, a->sin_addr.s_addr);
            cls_rule_set_tp_dst(&rule, a->sin_port);
            cb(ib, &rule);

            /* (i) Allow TCP traffic from the remote's IP and port. */
            cls_rule_init_catchall(&rule, IBR_FROM_REMOTE_TCP);
            cls_rule_set_dl_type(&rule, htons(ETH_TYPE_IP));
            cls_rule_set_nw_proto(&rule, IP_TYPE_TCP);
            cls_rule_set_nw_src(&rule, a->sin_addr.s_addr);
            cls_rule_set_tp_src(&rule, a->sin_port);
            cb(ib, &rule);
        }
    }
}

static void
drop_rule(struct in_band *ib, const struct cls_rule *rule)
{
    ofproto_delete_flow(ib->ofproto, rule);
}

/* Drops from the flow table all of the flows set up by 'ib', then clears out
 * the information about the installed flows so that they can be filled in
 * again if necessary. */
static void
drop_rules(struct in_band *ib)
{
    /* Drop rules. */
    make_rules(ib, drop_rule);

    /* Clear out state. */
    memset(ib->installed_local_mac, 0, sizeof ib->installed_local_mac);

    free(ib->remote_addrs);
    ib->remote_addrs = NULL;
    ib->n_remote_addrs = 0;

    free(ib->remote_macs);
    ib->remote_macs = NULL;
    ib->n_remote_macs = 0;
}

static void
add_rule(struct in_band *ib, const struct cls_rule *rule)
{
    struct {
        struct nx_action_set_queue nxsq;
        struct ofp_action_output oao;
    } actions;

    memset(&actions, 0, sizeof actions);

    actions.oao.type = htons(OFPAT_OUTPUT);
    actions.oao.len = htons(sizeof actions.oao);
    actions.oao.port = htons(OFPP_NORMAL);
    actions.oao.max_len = htons(0);

    if (ib->queue_id < 0) {
        ofproto_add_flow(ib->ofproto, rule,
                         (union ofp_action *) &actions.oao, 1);
    } else {
        actions.nxsq.type = htons(OFPAT_VENDOR);
        actions.nxsq.len = htons(sizeof actions.nxsq);
        actions.nxsq.vendor = htonl(NX_VENDOR_ID);
        actions.nxsq.subtype = htons(NXAST_SET_QUEUE);
        actions.nxsq.queue_id = htonl(ib->queue_id);

        ofproto_add_flow(ib->ofproto, rule, (union ofp_action *) &actions,
                         sizeof actions / sizeof(union ofp_action));
    }
}

/* Inserts flows into the flow table for the current state of 'ib'. */
static void
add_rules(struct in_band *ib)
{
    make_rules(ib, add_rule);
}

static int
compare_addrs(const void *a_, const void *b_)
{
    const struct sockaddr_in *a = a_;
    const struct sockaddr_in *b = b_;
    int cmp;

    cmp = memcmp(&a->sin_addr.s_addr,
                 &b->sin_addr.s_addr,
                 sizeof a->sin_addr.s_addr);
    if (cmp) {
        return cmp;
    }
    return memcmp(&a->sin_port, &b->sin_port, sizeof a->sin_port);
}

static int
compare_macs(const void *a, const void *b)
{
    return memcmp(a, b, ETH_ADDR_LEN);
}

void
in_band_run(struct in_band *ib)
{
    bool local_change, remote_change, queue_id_change;
    struct in_band_remote *r;

    local_change = refresh_local(ib);
    remote_change = refresh_remotes(ib);
    queue_id_change = ib->queue_id != ib->prev_queue_id;
    if (!local_change && !remote_change && !queue_id_change) {
        /* Nothing changed, nothing to do. */
        return;
    }
    ib->prev_queue_id = ib->queue_id;

    /* Drop old rules. */
    drop_rules(ib);

    /* Figure out new rules. */
    memcpy(ib->installed_local_mac, ib->local_mac, ETH_ADDR_LEN);
    ib->remote_addrs = xmalloc(ib->n_remotes * sizeof *ib->remote_addrs);
    ib->n_remote_addrs = 0;
    ib->remote_macs = xmalloc(ib->n_remotes * ETH_ADDR_LEN);
    ib->n_remote_macs = 0;
    for (r = ib->remotes; r < &ib->remotes[ib->n_remotes]; r++) {
        ib->remote_addrs[ib->n_remote_addrs++] = r->remote_addr;
        if (!eth_addr_is_zero(r->remote_mac)) {
            memcpy(&ib->remote_macs[ib->n_remote_macs * ETH_ADDR_LEN],
                   r->remote_mac, ETH_ADDR_LEN);
            ib->n_remote_macs++;
        }
    }

    /* Sort, to allow make_rules() to easily skip duplicates. */
    qsort(ib->remote_addrs, ib->n_remote_addrs, sizeof *ib->remote_addrs,
          compare_addrs);
    qsort(ib->remote_macs, ib->n_remote_macs, ETH_ADDR_LEN, compare_macs);

    /* Add new rules. */
    add_rules(ib);
}

void
in_band_wait(struct in_band *in_band)
{
    long long int wakeup
            = MIN(in_band->next_remote_refresh, in_band->next_local_refresh);
    poll_timer_wait_until(wakeup * 1000);
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

    *in_bandp = NULL;
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
    in_band->queue_id = in_band->prev_queue_id = -1;
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

static bool
any_addresses_changed(struct in_band *ib,
                      const struct sockaddr_in *addresses, size_t n)
{
    size_t i;

    if (n != ib->n_remotes) {
        return true;
    }

    for (i = 0; i < n; i++) {
        const struct sockaddr_in *old = &ib->remotes[i].remote_addr;
        const struct sockaddr_in *new = &addresses[i];

        if (old->sin_addr.s_addr != new->sin_addr.s_addr ||
            old->sin_port != new->sin_port) {
            return true;
        }
    }

    return false;
}

void
in_band_set_remotes(struct in_band *ib,
                    const struct sockaddr_in *addresses, size_t n)
{
    size_t i;

    if (!any_addresses_changed(ib, addresses, n)) {
        return;
    }

    /* Clear old remotes. */
    for (i = 0; i < ib->n_remotes; i++) {
        netdev_close(ib->remotes[i].remote_netdev);
    }
    free(ib->remotes);

    /* Set up new remotes. */
    ib->remotes = n ? xzalloc(n * sizeof *ib->remotes) : NULL;
    ib->n_remotes = n;
    for (i = 0; i < n; i++) {
        ib->remotes[i].remote_addr = addresses[i];
    }

    /* Force refresh in next call to in_band_run(). */
    ib->next_remote_refresh = TIME_MIN;
}

/* Sets the OpenFlow queue used by flows set up by 'ib' to 'queue_id'.  If
 * 'queue_id' is negative, 'ib' will not set any queue (which is also the
 * default). */
void
in_band_set_queue(struct in_band *ib, int queue_id)
{
    ib->queue_id = queue_id;
}

