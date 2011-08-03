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
#include "ofproto-provider.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "timeval.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(in_band);

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

/* What to do to an in_band_rule. */
enum in_band_op {
    ADD,                       /* Add the rule to ofproto's flow table. */
    DELETE                     /* Delete the rule from ofproto's flow table. */
};

/* A rule to add to or delete from ofproto's flow table.  */
struct in_band_rule {
    struct cls_rule cls_rule;
    enum in_band_op op;
};

struct in_band {
    struct ofproto *ofproto;
    int queue_id;

    /* Remote information. */
    time_t next_remote_refresh; /* Refresh timer. */
    struct in_band_remote *remotes;
    size_t n_remotes;

    /* Local information. */
    time_t next_local_refresh;       /* Refresh timer. */
    uint8_t local_mac[ETH_ADDR_LEN]; /* Current MAC. */
    struct netdev *local_netdev;     /* Local port's network device. */

    /* Flow tracking. */
    struct hmap rules;          /* Contains "struct in_band_rule"s. */
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

/* Returns true if 'packet' should be sent to the local port regardless
 * of the flow table. */
bool
in_band_msg_in_hook(struct in_band *in_band, const struct flow *flow,
                    const struct ofpbuf *packet)
{
    /* Regardless of how the flow table is configured, we want to be
     * able to see replies to our DHCP requests. */
    if (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IPPROTO_UDP
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
in_band_rule_check(const struct flow *flow,
                   const struct nlattr *actions, size_t actions_len)
{
    /* Don't allow flows that would prevent DHCP replies from being seen
     * by the local port. */
    if (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IPPROTO_UDP
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
add_rule(struct in_band *ib, const struct cls_rule *cls_rule)
{
    uint32_t hash = cls_rule_hash(cls_rule, 0);
    struct in_band_rule *rule;

    HMAP_FOR_EACH_WITH_HASH (rule, cls_rule.hmap_node, hash, &ib->rules) {
        if (cls_rule_equal(&rule->cls_rule, cls_rule)) {
            rule->op = ADD;
            return;
        }
    }

    rule = xmalloc(sizeof *rule);
    rule->cls_rule = *cls_rule;
    rule->op = ADD;
    hmap_insert(&ib->rules, &rule->cls_rule.hmap_node, hash);
}

static void
update_rules(struct in_band *ib)
{
    struct in_band_rule *ib_rule;
    struct in_band_remote *r;
    struct cls_rule rule;

    /* Mark all the existing rules for deletion.  (Afterward we will re-add any
     * rules that are still valid.) */
    HMAP_FOR_EACH (ib_rule, cls_rule.hmap_node, &ib->rules) {
        ib_rule->op = DELETE;
    }

    if (ib->n_remotes && !eth_addr_is_zero(ib->local_mac)) {
        /* (a) Allow DHCP requests sent from the local port. */
        cls_rule_init_catchall(&rule, IBR_FROM_LOCAL_DHCP);
        cls_rule_set_in_port(&rule, ODPP_LOCAL);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_IP));
        cls_rule_set_dl_src(&rule, ib->local_mac);
        cls_rule_set_nw_proto(&rule, IPPROTO_UDP);
        cls_rule_set_tp_src(&rule, htons(DHCP_CLIENT_PORT));
        cls_rule_set_tp_dst(&rule, htons(DHCP_SERVER_PORT));
        add_rule(ib, &rule);

        /* (b) Allow ARP replies to the local port's MAC address. */
        cls_rule_init_catchall(&rule, IBR_TO_LOCAL_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_dl_dst(&rule, ib->local_mac);
        cls_rule_set_nw_proto(&rule, ARP_OP_REPLY);
        add_rule(ib, &rule);

        /* (c) Allow ARP requests from the local port's MAC address.  */
        cls_rule_init_catchall(&rule, IBR_FROM_LOCAL_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_dl_src(&rule, ib->local_mac);
        cls_rule_set_nw_proto(&rule, ARP_OP_REQUEST);
        add_rule(ib, &rule);
    }

    for (r = ib->remotes; r < &ib->remotes[ib->n_remotes]; r++) {
        const uint8_t *remote_mac = r->remote_mac;

        if (eth_addr_is_zero(remote_mac)) {
            continue;
        }

        /* (d) Allow ARP replies to the next hop's MAC address. */
        cls_rule_init_catchall(&rule, IBR_TO_NEXT_HOP_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_dl_dst(&rule, remote_mac);
        cls_rule_set_nw_proto(&rule, ARP_OP_REPLY);
        add_rule(ib, &rule);

        /* (e) Allow ARP requests from the next hop's MAC address. */
        cls_rule_init_catchall(&rule, IBR_FROM_NEXT_HOP_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_dl_src(&rule, remote_mac);
        cls_rule_set_nw_proto(&rule, ARP_OP_REQUEST);
        add_rule(ib, &rule);
    }

    for (r = ib->remotes; r < &ib->remotes[ib->n_remotes]; r++) {
        const struct sockaddr_in *a = &r->remote_addr;

        /* (f) Allow ARP replies containing the remote's IP address as a
         * target. */
        cls_rule_init_catchall(&rule, IBR_TO_REMOTE_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_nw_proto(&rule, ARP_OP_REPLY);
        cls_rule_set_nw_dst(&rule, a->sin_addr.s_addr);
        add_rule(ib, &rule);

        /* (g) Allow ARP requests containing the remote's IP address as a
         * source. */
        cls_rule_init_catchall(&rule, IBR_FROM_REMOTE_ARP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_ARP));
        cls_rule_set_nw_proto(&rule, ARP_OP_REQUEST);
        cls_rule_set_nw_src(&rule, a->sin_addr.s_addr);
        add_rule(ib, &rule);

        /* (h) Allow TCP traffic to the remote's IP and port. */
        cls_rule_init_catchall(&rule, IBR_TO_REMOTE_TCP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_IP));
        cls_rule_set_nw_proto(&rule, IPPROTO_TCP);
        cls_rule_set_nw_dst(&rule, a->sin_addr.s_addr);
        cls_rule_set_tp_dst(&rule, a->sin_port);
        add_rule(ib, &rule);

        /* (i) Allow TCP traffic from the remote's IP and port. */
        cls_rule_init_catchall(&rule, IBR_FROM_REMOTE_TCP);
        cls_rule_set_dl_type(&rule, htons(ETH_TYPE_IP));
        cls_rule_set_nw_proto(&rule, IPPROTO_TCP);
        cls_rule_set_nw_src(&rule, a->sin_addr.s_addr);
        cls_rule_set_tp_src(&rule, a->sin_port);
        add_rule(ib, &rule);
    }
}

/* Updates the OpenFlow flow table for the current state of in-band control.
 * Returns true ordinarily.  Returns false if no remotes are configured on 'ib'
 * and 'ib' doesn't have any rules left to remove from the OpenFlow flow
 * table.  Thus, a false return value means that the caller can destroy 'ib'
 * without leaving extra flows hanging around in the flow table. */
bool
in_band_run(struct in_band *ib)
{
    struct {
        struct nx_action_set_queue nxsq;
        union ofp_action oa;
    } actions;
    const void *a;
    size_t na;

    struct in_band_rule *rule, *next;

    memset(&actions, 0, sizeof actions);
    actions.oa.output.type = htons(OFPAT_OUTPUT);
    actions.oa.output.len = htons(sizeof actions.oa);
    actions.oa.output.port = htons(OFPP_NORMAL);
    actions.oa.output.max_len = htons(0);
    if (ib->queue_id < 0) {
        a = &actions.oa;
        na = sizeof actions.oa / sizeof(union ofp_action);
    } else {
        actions.nxsq.type = htons(OFPAT_VENDOR);
        actions.nxsq.len = htons(sizeof actions.nxsq);
        actions.nxsq.vendor = htonl(NX_VENDOR_ID);
        actions.nxsq.subtype = htons(NXAST_SET_QUEUE);
        actions.nxsq.queue_id = htonl(ib->queue_id);
        a = &actions;
        na = sizeof actions / sizeof(union ofp_action);
    }

    refresh_local(ib);
    refresh_remotes(ib);

    update_rules(ib);

    HMAP_FOR_EACH_SAFE (rule, next, cls_rule.hmap_node, &ib->rules) {
        switch (rule->op) {
        case ADD:
            ofproto_add_flow(ib->ofproto, &rule->cls_rule, a, na);
            break;

        case DELETE:
            if (ofproto_delete_flow(ib->ofproto, &rule->cls_rule)) {
                /* ofproto doesn't have the rule anymore so there's no reason
                 * for us to track it any longer. */
                hmap_remove(&ib->rules, &rule->cls_rule.hmap_node);
                free(rule);
            }
            break;
        }
    }

    return ib->n_remotes || !hmap_is_empty(&ib->rules);
}

void
in_band_wait(struct in_band *in_band)
{
    long long int wakeup
            = MIN(in_band->next_remote_refresh, in_band->next_local_refresh);
    poll_timer_wait_until(wakeup * 1000);
}

int
in_band_create(struct ofproto *ofproto, const char *local_name,
               struct in_band **in_bandp)
{
    struct in_band *in_band;
    struct netdev *local_netdev;
    int error;

    *in_bandp = NULL;
    error = netdev_open_default(local_name, &local_netdev);
    if (error) {
        VLOG_ERR("failed to initialize in-band control: cannot open "
                 "datapath local port %s (%s)", local_name, strerror(error));
        return error;
    }

    in_band = xzalloc(sizeof *in_band);
    in_band->ofproto = ofproto;
    in_band->queue_id = -1;
    in_band->next_remote_refresh = TIME_MIN;
    in_band->next_local_refresh = TIME_MIN;
    in_band->local_netdev = local_netdev;
    hmap_init(&in_band->rules);

    *in_bandp = in_band;

    return 0;
}

void
in_band_destroy(struct in_band *ib)
{
    if (ib) {
        struct in_band_rule *rule, *next;

        HMAP_FOR_EACH_SAFE (rule, next, cls_rule.hmap_node, &ib->rules) {
            hmap_remove(&ib->rules, &rule->cls_rule.hmap_node);
            free(rule);
        }
        hmap_destroy(&ib->rules);
        in_band_set_remotes(ib, NULL, 0);
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

