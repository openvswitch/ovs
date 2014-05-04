/* Copyright (c) 2013, 2014 Nicira, Inc.
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

#include "byte-order.h"
#include "connectivity.h"
#include "dynamic-string.h"
#include "hash.h"
#include "hmap.h"
#include "netdev.h"
#include "odp-util.h"
#include "packets.h"
#include "seq.h"
#include "smap.h"
#include "socket-util.h"
#include "tunnel.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(tunnel);

/* skb mark used for IPsec tunnel packets */
#define IPSEC_MARK 1

struct tnl_match {
    ovs_be64 in_key;
    ovs_be32 ip_src;
    ovs_be32 ip_dst;
    odp_port_t odp_port;
    uint32_t pkt_mark;
    bool in_key_flow;
    bool ip_src_flow;
    bool ip_dst_flow;
};

struct tnl_port {
    struct hmap_node ofport_node;
    struct hmap_node match_node;

    const struct ofport_dpif *ofport;
    unsigned int change_seq;
    struct netdev *netdev;

    struct tnl_match match;
};

static struct ovs_rwlock rwlock = OVS_RWLOCK_INITIALIZER;

/* Tunnel matches.
 *
 * This module maps packets received over tunnel protocols to vports.  The
 * tunnel protocol and, for some protocols, tunnel-specific information (e.g.,
 * for VXLAN, the UDP destination port number) are always use as part of the
 * mapping.  Which other fields are used for the mapping depends on the vports
 * themselves (the parenthesized notations refer to "struct tnl_match" fields):
 *
 *     - in_key: A vport may match a specific tunnel ID (in_key_flow == false)
 *       or arrange for the tunnel ID to be matched as tunnel.tun_id in the
 *       OpenFlow flow (in_key_flow == true).
 *
 *     - ip_dst: A vport may match a specific destination IP address
 *       (ip_dst_flow == false) or arrange for the destination IP to be matched
 *       as tunnel.ip_dst in the OpenFlow flow (ip_dst_flow == true).
 *
 *     - ip_src: A vport may match a specific IP source address (ip_src_flow ==
 *       false, ip_src != 0), wildcard all source addresses (ip_src_flow ==
 *       false, ip_src == 0), or arrange for the IP source address to be
 *       handled in the OpenFlow flow table (ip_src_flow == true).
 *
 * Thus, there are 2 * 2 * 3 == 12 possible ways a vport can match against a
 * tunnel packet.  We number the possibilities for each field in increasing
 * order as listed in each bullet above.  We order the 12 overall combinations
 * in lexicographic order considering in_key first, then ip_dst, then
 * ip_src. */
#define N_MATCH_TYPES (2 * 2 * 3)

/* The three possibilities (see above) for vport ip_src matches. */
enum ip_src_type {
    IP_SRC_CFG,             /* ip_src must equal configured address. */
    IP_SRC_ANY,             /* Any ip_src is acceptable. */
    IP_SRC_FLOW             /* ip_src is handled in flow table. */
};

/* Each hmap contains "struct tnl_port"s.
 * The index is a combination of how each of the fields listed under "Tunnel
 * matches" above matches, see the final paragraph for ordering. */
static struct hmap *tnl_match_maps[N_MATCH_TYPES] OVS_GUARDED_BY(rwlock);
static struct hmap **tnl_match_map(const struct tnl_match *);

static struct hmap ofport_map__ = HMAP_INITIALIZER(&ofport_map__);
static struct hmap *ofport_map OVS_GUARDED_BY(rwlock) = &ofport_map__;

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
static struct vlog_rate_limit dbg_rl = VLOG_RATE_LIMIT_INIT(60, 60);

static struct tnl_port *tnl_find(const struct flow *) OVS_REQ_RDLOCK(rwlock);
static struct tnl_port *tnl_find_exact(struct tnl_match *, struct hmap *)
    OVS_REQ_RDLOCK(rwlock);
static struct tnl_port *tnl_find_ofport(const struct ofport_dpif *)
    OVS_REQ_RDLOCK(rwlock);

static uint32_t tnl_hash(struct tnl_match *);
static void tnl_match_fmt(const struct tnl_match *, struct ds *);
static char *tnl_port_fmt(const struct tnl_port *) OVS_REQ_RDLOCK(rwlock);
static void tnl_port_mod_log(const struct tnl_port *, const char *action)
    OVS_REQ_RDLOCK(rwlock);
static const char *tnl_port_get_name(const struct tnl_port *)
    OVS_REQ_RDLOCK(rwlock);
static void tnl_port_del__(const struct ofport_dpif *) OVS_REQ_WRLOCK(rwlock);

static bool
tnl_port_add__(const struct ofport_dpif *ofport, const struct netdev *netdev,
               odp_port_t odp_port, bool warn)
    OVS_REQ_WRLOCK(rwlock)
{
    const struct netdev_tunnel_config *cfg;
    struct tnl_port *existing_port;
    struct tnl_port *tnl_port;
    struct hmap **map;

    cfg = netdev_get_tunnel_config(netdev);
    ovs_assert(cfg);

    tnl_port = xzalloc(sizeof *tnl_port);
    tnl_port->ofport = ofport;
    tnl_port->netdev = netdev_ref(netdev);
    tnl_port->change_seq = seq_read(connectivity_seq_get());

    tnl_port->match.in_key = cfg->in_key;
    tnl_port->match.ip_src = cfg->ip_src;
    tnl_port->match.ip_dst = cfg->ip_dst;
    tnl_port->match.ip_src_flow = cfg->ip_src_flow;
    tnl_port->match.ip_dst_flow = cfg->ip_dst_flow;
    tnl_port->match.pkt_mark = cfg->ipsec ? IPSEC_MARK : 0;
    tnl_port->match.in_key_flow = cfg->in_key_flow;
    tnl_port->match.odp_port = odp_port;

    map = tnl_match_map(&tnl_port->match);
    existing_port = tnl_find_exact(&tnl_port->match, *map);
    if (existing_port) {
        if (warn) {
            struct ds ds = DS_EMPTY_INITIALIZER;
            tnl_match_fmt(&tnl_port->match, &ds);
            VLOG_WARN("%s: attempting to add tunnel port with same config as "
                      "port '%s' (%s)", tnl_port_get_name(tnl_port),
                      tnl_port_get_name(existing_port), ds_cstr(&ds));
            ds_destroy(&ds);
        }
        netdev_close(tnl_port->netdev);
        free(tnl_port);
        return false;
    }

    hmap_insert(ofport_map, &tnl_port->ofport_node, hash_pointer(ofport, 0));

    if (!*map) {
        *map = xmalloc(sizeof **map);
        hmap_init(*map);
    }
    hmap_insert(*map, &tnl_port->match_node, tnl_hash(&tnl_port->match));
    tnl_port_mod_log(tnl_port, "adding");
    return true;
}

/* Adds 'ofport' to the module with datapath port number 'odp_port'. 'ofport's
 * must be added before they can be used by the module. 'ofport' must be a
 * tunnel. */
void
tnl_port_add(const struct ofport_dpif *ofport, const struct netdev *netdev,
             odp_port_t odp_port) OVS_EXCLUDED(rwlock)
{
    ovs_rwlock_wrlock(&rwlock);
    tnl_port_add__(ofport, netdev, odp_port, true);
    ovs_rwlock_unlock(&rwlock);
}

/* Checks if the tunnel represented by 'ofport' reconfiguration due to changes
 * in its netdev_tunnel_config.  If it does, returns true. Otherwise, returns
 * false.  'ofport' and 'odp_port' should be the same as would be passed to
 * tnl_port_add(). */
bool
tnl_port_reconfigure(const struct ofport_dpif *ofport,
                     const struct netdev *netdev, odp_port_t odp_port)
    OVS_EXCLUDED(rwlock)
{
    struct tnl_port *tnl_port;
    bool changed = false;

    ovs_rwlock_wrlock(&rwlock);
    tnl_port = tnl_find_ofport(ofport);
    if (!tnl_port) {
        changed = tnl_port_add__(ofport, netdev, odp_port, false);
    } else if (tnl_port->netdev != netdev
               || tnl_port->match.odp_port != odp_port
               || tnl_port->change_seq != seq_read(connectivity_seq_get())) {
        VLOG_DBG("reconfiguring %s", tnl_port_get_name(tnl_port));
        tnl_port_del__(ofport);
        tnl_port_add__(ofport, netdev, odp_port, true);
        changed = true;
    }
    ovs_rwlock_unlock(&rwlock);
    return changed;
}

static void
tnl_port_del__(const struct ofport_dpif *ofport) OVS_REQ_WRLOCK(rwlock)
{
    struct tnl_port *tnl_port;

    if (!ofport) {
        return;
    }

    tnl_port = tnl_find_ofport(ofport);
    if (tnl_port) {
        struct hmap **map;

        tnl_port_mod_log(tnl_port, "removing");
        map = tnl_match_map(&tnl_port->match);
        hmap_remove(*map, &tnl_port->match_node);
        if (hmap_is_empty(*map)) {
            hmap_destroy(*map);
            free(*map);
            *map = NULL;
        }
        hmap_remove(ofport_map, &tnl_port->ofport_node);
        netdev_close(tnl_port->netdev);
        free(tnl_port);
    }
}

/* Removes 'ofport' from the module. */
void
tnl_port_del(const struct ofport_dpif *ofport) OVS_EXCLUDED(rwlock)
{
    ovs_rwlock_wrlock(&rwlock);
    tnl_port_del__(ofport);
    ovs_rwlock_unlock(&rwlock);
}

/* Looks in the table of tunnels for a tunnel matching the metadata in 'flow'.
 * Returns the 'ofport' corresponding to the new in_port, or a null pointer if
 * none is found.
 *
 * Callers should verify that 'flow' needs to be received by calling
 * tnl_port_should_receive() before this function. */
const struct ofport_dpif *
tnl_port_receive(const struct flow *flow) OVS_EXCLUDED(rwlock)
{
    char *pre_flow_str = NULL;
    const struct ofport_dpif *ofport;
    struct tnl_port *tnl_port;

    ovs_rwlock_rdlock(&rwlock);
    tnl_port = tnl_find(flow);
    ofport = tnl_port ? tnl_port->ofport : NULL;
    if (!tnl_port) {
        char *flow_str = flow_to_string(flow);

        VLOG_WARN_RL(&rl, "receive tunnel port not found (%s)", flow_str);
        free(flow_str);
        goto out;
    }

    if (!VLOG_DROP_DBG(&dbg_rl)) {
        pre_flow_str = flow_to_string(flow);
    }

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

out:
    ovs_rwlock_unlock(&rwlock);
    return ofport;
}

static bool
tnl_ecn_ok(const struct flow *base_flow, struct flow *flow,
           struct flow_wildcards *wc)
{
    if (is_ip_any(base_flow)) {
        if ((flow->tunnel.ip_tos & IP_ECN_MASK) == IP_ECN_CE) {
            wc->masks.nw_tos |= IP_ECN_MASK;
            if ((base_flow->nw_tos & IP_ECN_MASK) == IP_ECN_NOT_ECT) {
                VLOG_WARN_RL(&rl, "dropping tunnel packet marked ECN CE"
                             " but is not ECN capable");
                return false;
            } else {
                /* Set the ECN CE value in the tunneled packet. */
                flow->nw_tos |= IP_ECN_CE;
            }
        }
    }

    return true;
}

/* Should be called at the beginning of action translation to initialize
 * wildcards and perform any actions based on receiving on tunnel port.
 *
 * Returns false if the packet must be dropped. */
bool
tnl_xlate_init(const struct flow *base_flow, struct flow *flow,
               struct flow_wildcards *wc)
{
    /* tnl_port_should_receive() examines the 'tunnel.ip_dst' field to
     * determine the presence of the tunnel metadata.  However, since tunnels'
     * datapath port numbers are different from the non-tunnel ports, and we
     * always unwildcard the 'in_port', we do not need to unwildcard
     * the 'tunnel.ip_dst' for non-tunneled packets. */
    if (tnl_port_should_receive(flow)) {
        wc->masks.tunnel.tun_id = OVS_BE64_MAX;
        wc->masks.tunnel.ip_src = OVS_BE32_MAX;
        wc->masks.tunnel.ip_dst = OVS_BE32_MAX;
        wc->masks.tunnel.flags = (FLOW_TNL_F_DONT_FRAGMENT |
                                  FLOW_TNL_F_CSUM |
                                  FLOW_TNL_F_KEY);
        wc->masks.tunnel.ip_tos = UINT8_MAX;
        wc->masks.tunnel.ip_ttl = UINT8_MAX;

        memset(&wc->masks.pkt_mark, 0xff, sizeof wc->masks.pkt_mark);

        if (!tnl_ecn_ok(base_flow, flow, wc)) {
            return false;
        }

        flow->pkt_mark &= ~IPSEC_MARK;
    }

    return true;
}

/* Given that 'flow' should be output to the ofport corresponding to
 * 'tnl_port', updates 'flow''s tunnel headers and returns the actual datapath
 * port that the output should happen on.  May return ODPP_NONE if the output
 * shouldn't occur. */
odp_port_t
tnl_port_send(const struct ofport_dpif *ofport, struct flow *flow,
              struct flow_wildcards *wc) OVS_EXCLUDED(rwlock)
{
    const struct netdev_tunnel_config *cfg;
    struct tnl_port *tnl_port;
    char *pre_flow_str = NULL;
    odp_port_t out_port;

    ovs_rwlock_rdlock(&rwlock);
    tnl_port = tnl_find_ofport(ofport);
    out_port = tnl_port ? tnl_port->match.odp_port : ODPP_NONE;
    if (!tnl_port) {
        goto out;
    }

    cfg = netdev_get_tunnel_config(tnl_port->netdev);
    ovs_assert(cfg);

    if (!VLOG_DROP_DBG(&dbg_rl)) {
        pre_flow_str = flow_to_string(flow);
    }

    if (!cfg->ip_src_flow) {
        flow->tunnel.ip_src = tnl_port->match.ip_src;
    }
    if (!cfg->ip_dst_flow) {
        flow->tunnel.ip_dst = tnl_port->match.ip_dst;
    }
    flow->pkt_mark = tnl_port->match.pkt_mark;

    if (!cfg->out_key_flow) {
        flow->tunnel.tun_id = cfg->out_key;
    }

    if (cfg->ttl_inherit && is_ip_any(flow)) {
        wc->masks.nw_ttl = 0xff;
        flow->tunnel.ip_ttl = flow->nw_ttl;
    } else {
        flow->tunnel.ip_ttl = cfg->ttl;
    }

    if (cfg->tos_inherit && is_ip_any(flow)) {
        wc->masks.nw_tos = IP_DSCP_MASK;
        flow->tunnel.ip_tos = flow->nw_tos & IP_DSCP_MASK;
    } else {
        flow->tunnel.ip_tos = cfg->tos;
    }

    /* ECN fields are always inherited. */
    if (is_ip_any(flow)) {
        wc->masks.nw_tos |= IP_ECN_MASK;

        if ((flow->nw_tos & IP_ECN_MASK) == IP_ECN_CE) {
            flow->tunnel.ip_tos |= IP_ECN_ECT_0;
        } else {
            flow->tunnel.ip_tos |= flow->nw_tos & IP_ECN_MASK;
        }
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

out:
    ovs_rwlock_unlock(&rwlock);
    return out_port;
}

static uint32_t
tnl_hash(struct tnl_match *match)
{
    BUILD_ASSERT_DECL(sizeof *match % sizeof(uint32_t) == 0);
    return hash_words((uint32_t *) match, sizeof *match / sizeof(uint32_t), 0);
}

static struct tnl_port *
tnl_find_ofport(const struct ofport_dpif *ofport) OVS_REQ_RDLOCK(rwlock)
{
    struct tnl_port *tnl_port;

    HMAP_FOR_EACH_IN_BUCKET (tnl_port, ofport_node, hash_pointer(ofport, 0),
                             ofport_map) {
        if (tnl_port->ofport == ofport) {
            return tnl_port;
        }
    }
    return NULL;
}

static struct tnl_port *
tnl_find_exact(struct tnl_match *match, struct hmap *map)
    OVS_REQ_RDLOCK(rwlock)
{
    if (map) {
        struct tnl_port *tnl_port;

        HMAP_FOR_EACH_WITH_HASH (tnl_port, match_node, tnl_hash(match), map) {
            if (!memcmp(match, &tnl_port->match, sizeof *match)) {
                return tnl_port;
            }
        }
    }
    return NULL;
}

/* Returns the tnl_port that is the best match for the tunnel data in 'flow',
 * or NULL if no tnl_port matches 'flow'. */
static struct tnl_port *
tnl_find(const struct flow *flow) OVS_REQ_RDLOCK(rwlock)
{
    enum ip_src_type ip_src;
    int in_key_flow;
    int ip_dst_flow;
    int i;

    i = 0;
    for (in_key_flow = 0; in_key_flow < 2; in_key_flow++) {
        for (ip_dst_flow = 0; ip_dst_flow < 2; ip_dst_flow++) {
            for (ip_src = 0; ip_src < 3; ip_src++) {
                struct hmap *map = tnl_match_maps[i];

                if (map) {
                    struct tnl_port *tnl_port;
                    struct tnl_match match;

                    memset(&match, 0, sizeof match);

                    /* The apparent mix-up of 'ip_dst' and 'ip_src' below is
                     * correct, because "struct tnl_match" is expressed in
                     * terms of packets being sent out, but we are using it
                     * here as a description of how to treat received
                     * packets. */
                    match.in_key = in_key_flow ? 0 : flow->tunnel.tun_id;
                    match.ip_src = (ip_src == IP_SRC_CFG
                                    ? flow->tunnel.ip_dst
                                    : 0);
                    match.ip_dst = ip_dst_flow ? 0 : flow->tunnel.ip_src;
                    match.odp_port = flow->in_port.odp_port;
                    match.pkt_mark = flow->pkt_mark;
                    match.in_key_flow = in_key_flow;
                    match.ip_dst_flow = ip_dst_flow;
                    match.ip_src_flow = ip_src == IP_SRC_FLOW;

                    tnl_port = tnl_find_exact(&match, map);
                    if (tnl_port) {
                        return tnl_port;
                    }
                }

                i++;
            }
        }
    }

    return NULL;
}

/* Returns a pointer to the 'tnl_match_maps' element corresponding to 'm''s
 * matching criteria. */
static struct hmap **
tnl_match_map(const struct tnl_match *m)
{
    enum ip_src_type ip_src;

    ip_src = (m->ip_src_flow ? IP_SRC_FLOW
              : m->ip_src ? IP_SRC_CFG
              : IP_SRC_ANY);

    return &tnl_match_maps[6 * m->in_key_flow + 3 * m->ip_dst_flow + ip_src];
}

static void
tnl_match_fmt(const struct tnl_match *match, struct ds *ds)
    OVS_REQ_RDLOCK(rwlock)
{
    if (!match->ip_dst_flow) {
        ds_put_format(ds, IP_FMT"->"IP_FMT, IP_ARGS(match->ip_src),
                      IP_ARGS(match->ip_dst));
    } else if (!match->ip_src_flow) {
        ds_put_format(ds, IP_FMT"->flow", IP_ARGS(match->ip_src));
    } else {
        ds_put_cstr(ds, "flow->flow");
    }

    if (match->in_key_flow) {
        ds_put_cstr(ds, ", key=flow");
    } else {
        ds_put_format(ds, ", key=%#"PRIx64, ntohll(match->in_key));
    }

    ds_put_format(ds, ", dp port=%"PRIu32, match->odp_port);
    ds_put_format(ds, ", pkt mark=%"PRIu32, match->pkt_mark);
}

static void
tnl_port_mod_log(const struct tnl_port *tnl_port, const char *action)
    OVS_REQ_RDLOCK(rwlock)
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
tnl_port_fmt(const struct tnl_port *tnl_port) OVS_REQ_RDLOCK(rwlock)
{
    const struct netdev_tunnel_config *cfg =
        netdev_get_tunnel_config(tnl_port->netdev);
    struct ds ds = DS_EMPTY_INITIALIZER;

    ds_put_format(&ds, "port %"PRIu32": %s (%s: ", tnl_port->match.odp_port,
                  tnl_port_get_name(tnl_port),
                  netdev_get_type(tnl_port->netdev));
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
tnl_port_get_name(const struct tnl_port *tnl_port) OVS_REQ_RDLOCK(rwlock)
{
    return netdev_get_name(tnl_port->netdev);
}
