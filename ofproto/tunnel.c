/* Copyright (c) 2013 Nicira, Inc.
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
 * limitations under the License. */

#include <config.h>
#include "tunnel.h"

#include <errno.h>

#include "ofproto/ofproto-provider.h"
#include "byte-order.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "packets.h"
#include "smap.h"
#include "socket-util.h"
#include "tunnel.h"
#include "vlog.h"

/* XXX:
 *
 * Ability to generate metadata for packet-outs
 * Disallow netdevs with names like "gre64_system" to prevent collisions. */

VLOG_DEFINE_THIS_MODULE(tunnel);

struct tnl_match {
    ovs_be64 in_key;
    ovs_be32 ip_src;
    ovs_be32 ip_dst;
    uint32_t odp_port;
    uint32_t skb_mark;
    bool in_key_flow;
};

struct tnl_port {
    struct hmap_node match_node;

    const struct ofport *ofport;
    unsigned int netdev_seq;
    struct tnl_match match;
};

static struct hmap tnl_match_map = HMAP_INITIALIZER(&tnl_match_map);

/* Returned to callers when their ofport will never be used to receive or send
 * tunnel traffic. Alternatively, we could ask the caller to delete their
 * ofport, but this would be unclean in the reconfguration case.  For the first
 * time, an ofproto provider would have to call ofproto_port_del() on itself.*/
static struct tnl_port void_tnl_port;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct vlog_rate_limit dbg_rl = VLOG_RATE_LIMIT_INIT(60, 60);

static struct tnl_port *tnl_find(struct tnl_match *);
static struct tnl_port *tnl_find_exact(struct tnl_match *);
static uint32_t tnl_hash(struct tnl_match *);
static void tnl_match_fmt(const struct tnl_match *, struct ds *);
static char *tnl_port_fmt(const struct tnl_port *);
static void tnl_port_mod_log(const struct tnl_port *, const char *action);
static const char *tnl_port_get_name(const struct tnl_port *);

static struct tnl_port *
tnl_port_add__(const struct ofport *ofport, uint32_t odp_port,
               bool warn)
{
    const struct netdev_tunnel_config *cfg;
    struct tnl_port *existing_port;
    struct tnl_port *tnl_port;

    cfg = netdev_get_tunnel_config(ofport->netdev);
    ovs_assert(cfg);

    tnl_port = xzalloc(sizeof *tnl_port);
    tnl_port->ofport = ofport;
    tnl_port->netdev_seq = netdev_change_seq(tnl_port->ofport->netdev);

    tnl_port->match.in_key = cfg->in_key;
    tnl_port->match.ip_src = cfg->ip_src;
    tnl_port->match.ip_dst = cfg->ip_dst;
    tnl_port->match.skb_mark = cfg->ipsec ? IPSEC_MARK : 0;
    tnl_port->match.in_key_flow = cfg->in_key_flow;
    tnl_port->match.odp_port = odp_port;

    existing_port = tnl_find_exact(&tnl_port->match);
    if (existing_port) {
        if (warn) {
            struct ds ds = DS_EMPTY_INITIALIZER;
            tnl_match_fmt(&tnl_port->match, &ds);
            VLOG_WARN("%s: attempting to add tunnel port with same config as "
                      "port '%s' (%s)", tnl_port_get_name(tnl_port),
                      tnl_port_get_name(existing_port), ds_cstr(&ds));
            ds_destroy(&ds);
            free(tnl_port);
        }
        return &void_tnl_port;
    }

    hmap_insert(&tnl_match_map, &tnl_port->match_node,
                tnl_hash(&tnl_port->match));
    tnl_port_mod_log(tnl_port, "adding");
    return tnl_port;
}

/* Adds 'ofport' to the module with datapath port number 'odp_port'. 'ofport's
 * must be added before they can be used by the module. 'ofport' must be a
 * tunnel. */
struct tnl_port *
tnl_port_add(const struct ofport *ofport, uint32_t odp_port)
{
    return tnl_port_add__(ofport, odp_port, true);
}

/* Checks if the tnl_port pointed to by 'tnl_portp' needs reconfiguration due
 * to changes in its netdev_tunnel_config.  If it does, updates 'tnl_portp' to
 * point to a new tnl_port and returns true.  Otherwise, returns false.
 * 'ofport' and 'odp_port' should be the same as would be passed to
 * tnl_port_add(). */
bool
tnl_port_reconfigure(const struct ofport *ofport, uint32_t odp_port,
                     struct tnl_port **tnl_portp)
{
    struct tnl_port *tnl_port = *tnl_portp;

    if (tnl_port == &void_tnl_port) {
        *tnl_portp = tnl_port_add__(ofport, odp_port, false);
        return *tnl_portp != &void_tnl_port;
    } else if (tnl_port->ofport != ofport
               || tnl_port->match.odp_port != odp_port
               || tnl_port->netdev_seq != netdev_change_seq(ofport->netdev)) {
        VLOG_DBG("reconfiguring %s", tnl_port_get_name(tnl_port));
        tnl_port_del(tnl_port);
        *tnl_portp = tnl_port_add(ofport, odp_port);
        return true;
    }
    return false;
}

/* Removes 'tnl_port' from the module. */
void
tnl_port_del(struct tnl_port *tnl_port)
{
    if (tnl_port && tnl_port != &void_tnl_port) {
        tnl_port_mod_log(tnl_port, "removing");
        hmap_remove(&tnl_match_map, &tnl_port->match_node);
        free(tnl_port);
    }
}

/* Transforms 'flow' so that it appears to have been received by a tunnel
 * OpenFlow port controlled by this module instead of the datapath port it
 * actually came in on.  Sets 'flow''s in_port to the appropriate OpenFlow port
 * number.  Returns the 'ofport' corresponding to the new in_port.
 *
 * Callers should verify that 'flow' needs to be received by calling
 * tnl_port_should_receive() before this function.
 *
 * Leaves 'flow' untouched and returns null if unsuccessful. */
const struct ofport *
tnl_port_receive(struct flow *flow)
{
    char *pre_flow_str = NULL;
    struct tnl_port *tnl_port;
    struct tnl_match match;

    memset(&match, 0, sizeof match);
    match.odp_port = flow->in_port;
    match.ip_src = flow->tunnel.ip_dst;
    match.ip_dst = flow->tunnel.ip_src;
    match.in_key = flow->tunnel.tun_id;
    match.skb_mark = flow->skb_mark;

    tnl_port = tnl_find(&match);
    if (!tnl_port) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        tnl_match_fmt(&match, &ds);
        VLOG_WARN_RL(&rl, "receive tunnel port not found (%s)", ds_cstr(&ds));
        ds_destroy(&ds);
        return NULL;
    }

    if (!VLOG_DROP_DBG(&dbg_rl)) {
        pre_flow_str = flow_to_string(flow);
    }

    flow->in_port = tnl_port->ofport->ofp_port;
    memset(&flow->tunnel, 0, sizeof flow->tunnel);
    flow->tunnel.tun_id = match.in_key;

    if (pre_flow_str) {
        char *post_flow_str = flow_to_string(flow);
        char *tnl_str = tnl_port_fmt(tnl_port);
        VLOG_DBG("flow received\n"
                 "%s"
                 " pre: %s\n"
                 "post: %s",
                 tnl_str, pre_flow_str, post_flow_str);
        free(tnl_str);
        free(pre_flow_str);
        free(post_flow_str);
    }
    return tnl_port->ofport;
}

/* Given that 'flow' should be output to the ofport corresponding to
 * 'tnl_port', updates 'flow''s tunnel headers and returns the actual datapath
 * port that the output should happen on.  May return OVSP_NONE if the output
 * shouldn't occur. */
uint32_t
tnl_port_send(const struct tnl_port *tnl_port, struct flow *flow)
{
    const struct netdev_tunnel_config *cfg;
    char *pre_flow_str = NULL;

    if (tnl_port == &void_tnl_port) {
        return OVSP_NONE;
    }

    cfg = netdev_get_tunnel_config(tnl_port->ofport->netdev);
    ovs_assert(cfg);

    if (!VLOG_DROP_DBG(&dbg_rl)) {
        pre_flow_str = flow_to_string(flow);
    }

    flow->tunnel.ip_src = tnl_port->match.ip_src;
    flow->tunnel.ip_dst = tnl_port->match.ip_dst;
    flow->skb_mark = tnl_port->match.skb_mark;

    if (!cfg->out_key_flow) {
        flow->tunnel.tun_id = cfg->out_key;
    }

    if (cfg->ttl_inherit && is_ip_any(flow)) {
        flow->tunnel.ip_ttl = flow->nw_ttl;
    } else {
        flow->tunnel.ip_ttl = cfg->ttl;
    }

    if (cfg->tos_inherit && is_ip_any(flow)) {
        flow->tunnel.ip_tos = flow->nw_tos & IP_DSCP_MASK;
    } else {
        flow->tunnel.ip_tos = cfg->tos;
    }

    if ((flow->nw_tos & IP_ECN_MASK) == IP_ECN_CE) {
        flow->tunnel.ip_tos |= IP_ECN_ECT_0;
    } else {
        flow->tunnel.ip_tos |= flow->nw_tos & IP_ECN_MASK;
    }

    flow->tunnel.flags = (cfg->dont_fragment ? FLOW_TNL_F_DONT_FRAGMENT : 0)
        | (cfg->csum ? FLOW_TNL_F_CSUM : 0)
        | (cfg->out_key_present ? FLOW_TNL_F_KEY : 0);

    if (pre_flow_str) {
        char *post_flow_str = flow_to_string(flow);
        char *tnl_str = tnl_port_fmt(tnl_port);
        VLOG_DBG("flow sent\n"
                 "%s"
                 " pre: %s\n"
                 "post: %s",
                 tnl_str, pre_flow_str, post_flow_str);
        free(tnl_str);
        free(pre_flow_str);
        free(post_flow_str);
    }

    return tnl_port->match.odp_port;
}

static uint32_t
tnl_hash(struct tnl_match *match)
{
    BUILD_ASSERT_DECL(sizeof *match % sizeof(uint32_t) == 0);
    return hash_words((uint32_t *) match, sizeof *match / sizeof(uint32_t), 0);
}

static struct tnl_port *
tnl_find_exact(struct tnl_match *match)
{
    struct tnl_port *tnl_port;

    HMAP_FOR_EACH_WITH_HASH (tnl_port, match_node, tnl_hash(match),
                             &tnl_match_map) {
        if (!memcmp(match, &tnl_port->match, sizeof *match)) {
            return tnl_port;
        }
    }
    return NULL;
}

static struct tnl_port *
tnl_find(struct tnl_match *match_)
{
    struct tnl_match match = *match_;
    struct tnl_port *tnl_port;

    /* remote_ip, local_ip, in_key */
    tnl_port = tnl_find_exact(&match);
    if (tnl_port) {
        return tnl_port;
    }

    /* remote_ip, in_key */
    match.ip_src = 0;
    tnl_port = tnl_find_exact(&match);
    if (tnl_port) {
        return tnl_port;
    }
    match.ip_src = match_->ip_src;

    /* remote_ip, local_ip */
    match.in_key = 0;
    match.in_key_flow = true;
    tnl_port = tnl_find_exact(&match);
    if (tnl_port) {
        return tnl_port;
    }

    /* remote_ip */
    match.ip_src = 0;
    tnl_port = tnl_find_exact(&match);
    if (tnl_port) {
        return tnl_port;
    }

    return NULL;
}

static void
tnl_match_fmt(const struct tnl_match *match, struct ds *ds)
{
    ds_put_format(ds, IP_FMT"->"IP_FMT, IP_ARGS(match->ip_src),
                  IP_ARGS(match->ip_dst));

    if (match->in_key_flow) {
        ds_put_cstr(ds, ", key=flow");
    } else {
        ds_put_format(ds, ", key=%#"PRIx64, ntohll(match->in_key));
    }

    ds_put_format(ds, ", dp port=%"PRIu32, match->odp_port);
    ds_put_format(ds, ", skb mark=%"PRIu32, match->skb_mark);
}

static void
tnl_port_mod_log(const struct tnl_port *tnl_port, const char *action)
{
    if (VLOG_IS_DBG_ENABLED()) {
        struct ds ds = DS_EMPTY_INITIALIZER;

        tnl_match_fmt(&tnl_port->match, &ds);
        VLOG_INFO("%s tunnel port %s (%s)", action,
                  tnl_port_get_name(tnl_port), ds_cstr(&ds));
        ds_destroy(&ds);
    }
}

static char *
tnl_port_fmt(const struct tnl_port *tnl_port)
{
    const struct netdev_tunnel_config *cfg =
        netdev_get_tunnel_config(tnl_port->ofport->netdev);
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "port %"PRIu32": %s (%s: ", tnl_port->match.odp_port,
                  tnl_port_get_name(tnl_port),
                  netdev_get_type(tnl_port->ofport->netdev));
    tnl_match_fmt(&tnl_port->match, &ds);

    if (cfg->out_key != cfg->in_key ||
        cfg->out_key_present != cfg->in_key_present ||
        cfg->out_key_flow != cfg->in_key_flow) {
        ds_put_cstr(&ds, ", out_key=");
        if (!cfg->out_key_present) {
            ds_put_cstr(&ds, "none");
        } else if (cfg->out_key_flow) {
            ds_put_cstr(&ds, "flow");
        } else {
            ds_put_format(&ds, "%#"PRIx64, ntohll(cfg->out_key));
        }
    }

    if (cfg->ttl_inherit) {
        ds_put_cstr(&ds, ", ttl=inherit");
    } else {
        ds_put_format(&ds, ", ttl=%"PRIu8, cfg->ttl);
    }

    if (cfg->tos_inherit) {
        ds_put_cstr(&ds, ", tos=inherit");
    } else if (cfg->tos) {
        ds_put_format(&ds, ", tos=%#"PRIx8, cfg->tos);
    }

    if (!cfg->dont_fragment) {
        ds_put_cstr(&ds, ", df=false");
    }

    if (cfg->csum) {
        ds_put_cstr(&ds, ", csum=true");
    }

    ds_put_cstr(&ds, ")\n");

    return ds_steal_cstr(&ds);
}

static const char *
tnl_port_get_name(const struct tnl_port *tnl_port)
{
    return netdev_get_name(tnl_port->ofport->netdev);
}
