/*
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
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
#include "netdev-tc-offloads.h"

#include <errno.h>
#include <linux/if_ether.h>

#include "dpif.h"
#include "hash.h"
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "openvswitch/vlog.h"
#include "netdev-linux.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "odp-netlink.h"
#include "tc.h"
#include "unaligned.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netdev_tc_offloads);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static struct hmap ufid_tc = HMAP_INITIALIZER(&ufid_tc);
static struct ovs_mutex ufid_lock = OVS_MUTEX_INITIALIZER;

/**
 * struct ufid_tc_data - data entry for ufid_tc hmap.
 * @ufid_node: Element in @ufid_tc hash table by ufid key.
 * @tc_node: Element in @ufid_tc hash table by prio/handle/ifindex key.
 * @ufid: ufid assigned to the flow
 * @prio: tc priority
 * @handle: tc handle
 * @ifindex: netdev ifindex.
 * @netdev: netdev associated with the tc rule
 */
struct ufid_tc_data {
    struct hmap_node ufid_node;
    struct hmap_node tc_node;
    ovs_u128 ufid;
    uint16_t prio;
    uint32_t handle;
    int ifindex;
    struct netdev *netdev;
};

/* Remove matching ufid entry from ufid_tc hashmap. */
static void
del_ufid_tc_mapping(const ovs_u128 *ufid)
{
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_tc_data *data;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, ufid_node, ufid_hash, &ufid_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            break;
        }
    }

    if (!data) {
        ovs_mutex_unlock(&ufid_lock);
        return;
    }

    hmap_remove(&ufid_tc, &data->ufid_node);
    hmap_remove(&ufid_tc, &data->tc_node);
    netdev_close(data->netdev);
    free(data);
    ovs_mutex_unlock(&ufid_lock);
}

/* Add ufid entry to ufid_tc hashmap.
 * If entry exists already it will be replaced. */
static void
add_ufid_tc_mapping(const ovs_u128 *ufid, int prio, int handle,
                    struct netdev *netdev, int ifindex)
{
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    size_t tc_hash = hash_int(hash_int(prio, handle), ifindex);
    struct ufid_tc_data *new_data = xzalloc(sizeof *new_data);

    del_ufid_tc_mapping(ufid);

    new_data->ufid = *ufid;
    new_data->prio = prio;
    new_data->handle = handle;
    new_data->netdev = netdev_ref(netdev);
    new_data->ifindex = ifindex;

    ovs_mutex_lock(&ufid_lock);
    hmap_insert(&ufid_tc, &new_data->ufid_node, ufid_hash);
    hmap_insert(&ufid_tc, &new_data->tc_node, tc_hash);
    ovs_mutex_unlock(&ufid_lock);
}

/* Get ufid from ufid_tc hashmap.
 *
 * If netdev output param is not NULL then the function will return
 * associated netdev on success and a refcount is taken on that netdev.
 * The caller is then responsible to close the netdev.
 *
 * Returns handle if successful and fill prio and netdev for that ufid.
 * Otherwise returns 0.
 */
static int
get_ufid_tc_mapping(const ovs_u128 *ufid, int *prio, struct netdev **netdev)
{
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_tc_data *data;
    int handle = 0;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, ufid_node, ufid_hash, &ufid_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            if (prio) {
                *prio = data->prio;
            }
            if (netdev) {
                *netdev = netdev_ref(data->netdev);
            }
            handle = data->handle;
            break;
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    return handle;
}

/* Find ufid entry in ufid_tc hashmap using prio, handle and netdev.
 * The result is saved in ufid.
 *
 * Returns true on success.
 */
static bool
find_ufid(int prio, int handle, struct netdev *netdev, ovs_u128 *ufid)
{
    int ifindex = netdev_get_ifindex(netdev);
    struct ufid_tc_data *data;
    size_t tc_hash = hash_int(hash_int(prio, handle), ifindex);

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, tc_node, tc_hash,  &ufid_tc) {
        if (data->prio == prio && data->handle == handle
            && data->ifindex == ifindex) {
            *ufid = data->ufid;
            break;
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    return (data != NULL);
}

struct prio_map_data {
    struct hmap_node node;
    struct tc_flower_key mask;
    ovs_be16 protocol;
    uint16_t prio;
};

/* Get free prio for tc flower
 * If prio is already allocated for mask/eth_type combination then return it.
 * If not assign new prio.
 *
 * Return prio on success or 0 if we are out of prios.
 */
static uint16_t
get_prio_for_tc_flower(struct tc_flower *flower)
{
    static struct hmap prios = HMAP_INITIALIZER(&prios);
    static struct ovs_mutex prios_lock = OVS_MUTEX_INITIALIZER;
    static uint16_t last_prio = 0;
    size_t key_len = sizeof(struct tc_flower_key);
    size_t hash = hash_bytes(&flower->mask, key_len,
                             (OVS_FORCE uint32_t) flower->key.eth_type);
    struct prio_map_data *data;
    struct prio_map_data *new_data;

    /* We can use the same prio for same mask/eth combination but must have
     * different prio if not. Flower classifier will reject same prio for
     * different mask/eth combination. */
    ovs_mutex_lock(&prios_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &prios) {
        if (!memcmp(&flower->mask, &data->mask, key_len)
            && data->protocol == flower->key.eth_type) {
            ovs_mutex_unlock(&prios_lock);
            return data->prio;
        }
    }

    if (last_prio == UINT16_MAX) {
        /* last_prio can overflow if there will be many different kinds of
         * flows which shouldn't happen organically. */
        ovs_mutex_unlock(&prios_lock);
        return 0;
    }

    new_data = xzalloc(sizeof *new_data);
    memcpy(&new_data->mask, &flower->mask, key_len);
    new_data->prio = ++last_prio;
    new_data->protocol = flower->key.eth_type;
    hmap_insert(&prios, &new_data->node, hash);
    ovs_mutex_unlock(&prios_lock);

    return new_data->prio;
}

int
netdev_tc_flow_flush(struct netdev *netdev)
{
    int ifindex = netdev_get_ifindex(netdev);

    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    return tc_flush(ifindex);
}

int
netdev_tc_flow_dump_create(struct netdev *netdev,
                           struct netdev_flow_dump **dump_out)
{
    struct netdev_flow_dump *dump;
    int ifindex;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    dump = xzalloc(sizeof *dump);
    dump->nl_dump = xzalloc(sizeof *dump->nl_dump);
    dump->netdev = netdev_ref(netdev);
    tc_dump_flower_start(ifindex, dump->nl_dump);

    *dump_out = dump;

    return 0;
}

int
netdev_tc_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    nl_dump_done(dump->nl_dump);
    netdev_close(dump->netdev);
    free(dump->nl_dump);
    free(dump);
    return 0;
}

static int
parse_tc_flower_to_match(struct tc_flower *flower,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         struct ofpbuf *buf) {
    size_t act_off;
    struct tc_flower_key *key = &flower->key;
    struct tc_flower_key *mask = &flower->mask;
    odp_port_t outport = 0;

    if (flower->ifindex_out) {
        outport = netdev_ifindex_to_odp_port(flower->ifindex_out);
        if (!outport) {
            return ENOENT;
        }
    }

    ofpbuf_clear(buf);

    match_init_catchall(match);
    match_set_dl_src_masked(match, key->src_mac, mask->src_mac);
    match_set_dl_dst_masked(match, key->dst_mac, mask->dst_mac);

    if (key->eth_type == htons(ETH_TYPE_VLAN)) {
        match_set_dl_vlan(match, htons(key->vlan_id));
        match_set_dl_vlan_pcp(match, key->vlan_prio);
        match_set_dl_type(match, key->encap_eth_type);
        flow_fix_vlan_tpid(&match->flow);
    } else {
        match_set_dl_type(match, key->eth_type);
    }

    if (is_ip_any(&match->flow)) {
        if (key->ip_proto) {
            match_set_nw_proto(match, key->ip_proto);
        }

        match_set_nw_src_masked(match, key->ipv4.ipv4_src, mask->ipv4.ipv4_src);
        match_set_nw_dst_masked(match, key->ipv4.ipv4_dst, mask->ipv4.ipv4_dst);

        match_set_ipv6_src_masked(match,
                                  &key->ipv6.ipv6_src, &mask->ipv6.ipv6_src);
        match_set_ipv6_dst_masked(match,
                                  &key->ipv6.ipv6_dst, &mask->ipv6.ipv6_dst);

        if (key->ip_proto == IPPROTO_TCP) {
            match_set_tp_dst_masked(match, key->tcp_dst, mask->tcp_dst);
            match_set_tp_src_masked(match, key->tcp_src, mask->tcp_src);
        } else if (key->ip_proto == IPPROTO_UDP) {
            match_set_tp_dst_masked(match, key->udp_dst, mask->udp_dst);
            match_set_tp_src_masked(match, key->udp_src, mask->udp_src);
        } else if (key->ip_proto == IPPROTO_SCTP) {
            match_set_tp_dst_masked(match, key->sctp_dst, mask->sctp_dst);
            match_set_tp_src_masked(match, key->sctp_src, mask->sctp_src);
        }
    }

    if (flower->tunnel.tunnel) {
        match_set_tun_id(match, flower->tunnel.id);
        if (flower->tunnel.ipv4.ipv4_dst) {
            match_set_tun_src(match, flower->tunnel.ipv4.ipv4_src);
            match_set_tun_dst(match, flower->tunnel.ipv4.ipv4_dst);
        } else if (!is_all_zeros(&flower->tunnel.ipv6.ipv6_dst,
                   sizeof flower->tunnel.ipv6.ipv6_dst)) {
            match_set_tun_ipv6_src(match, &flower->tunnel.ipv6.ipv6_src);
            match_set_tun_ipv6_dst(match, &flower->tunnel.ipv6.ipv6_dst);
        }
        if (flower->tunnel.tp_dst) {
            match_set_tun_tp_dst(match, flower->tunnel.tp_dst);
        }
    }

    act_off = nl_msg_start_nested(buf, OVS_FLOW_ATTR_ACTIONS);
    {
        if (flower->vlan_pop) {
            nl_msg_put_flag(buf, OVS_ACTION_ATTR_POP_VLAN);
        }

        if (flower->vlan_push_id || flower->vlan_push_prio) {
            struct ovs_action_push_vlan *push;
            push = nl_msg_put_unspec_zero(buf, OVS_ACTION_ATTR_PUSH_VLAN,
                                          sizeof *push);

            push->vlan_tpid = htons(ETH_TYPE_VLAN);
            push->vlan_tci = htons(flower->vlan_push_id
                                   | (flower->vlan_push_prio << 13)
                                   | VLAN_CFI);
        }

        if (flower->set.set) {
            size_t set_offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_SET);
            size_t tunnel_offset =
                nl_msg_start_nested(buf, OVS_KEY_ATTR_TUNNEL);

            nl_msg_put_be64(buf, OVS_TUNNEL_KEY_ATTR_ID, flower->set.id);
            if (flower->set.ipv4.ipv4_src) {
                nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
                                flower->set.ipv4.ipv4_src);
            }
            if (flower->set.ipv4.ipv4_dst) {
                nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                                flower->set.ipv4.ipv4_dst);
            }
            if (!is_all_zeros(&flower->set.ipv6.ipv6_src,
                              sizeof flower->set.ipv6.ipv6_src)) {
                nl_msg_put_in6_addr(buf, OVS_TUNNEL_KEY_ATTR_IPV6_SRC,
                                    &flower->set.ipv6.ipv6_src);
            }
            if (!is_all_zeros(&flower->set.ipv6.ipv6_dst,
                              sizeof flower->set.ipv6.ipv6_dst)) {
                nl_msg_put_in6_addr(buf, OVS_TUNNEL_KEY_ATTR_IPV6_DST,
                                    &flower->set.ipv6.ipv6_dst);
            }
            nl_msg_put_be16(buf, OVS_TUNNEL_KEY_ATTR_TP_DST,
                            flower->set.tp_dst);

            nl_msg_end_nested(buf, tunnel_offset);
            nl_msg_end_nested(buf, set_offset);
        }

        if (flower->ifindex_out > 0) {
            nl_msg_put_u32(buf, OVS_ACTION_ATTR_OUTPUT, odp_to_u32(outport));
        }

    }
    nl_msg_end_nested(buf, act_off);

    *actions = ofpbuf_at_assert(buf, act_off, sizeof(struct nlattr));

    if (stats) {
        memset(stats, 0, sizeof *stats);
        stats->n_packets = get_32aligned_u64(&flower->stats.n_packets);
        stats->n_bytes = get_32aligned_u64(&flower->stats.n_bytes);
        stats->used = flower->lastused;
    }

    return 0;
}

bool
netdev_tc_flow_dump_next(struct netdev_flow_dump *dump,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         ovs_u128 *ufid,
                         struct ofpbuf *rbuffer,
                         struct ofpbuf *wbuffer)
{
    struct ofpbuf nl_flow;

    while (nl_dump_next(dump->nl_dump, &nl_flow, rbuffer)) {
        struct tc_flower flower;
        struct netdev *netdev = dump->netdev;

        if (parse_netlink_to_tc_flower(&nl_flow, &flower)) {
            continue;
        }

        if (parse_tc_flower_to_match(&flower, match, actions, stats,
                                     wbuffer)) {
            continue;
        }

        if (flower.act_cookie.len) {
            *ufid = *((ovs_u128 *) flower.act_cookie.data);
        } else if (!find_ufid(flower.prio, flower.handle, netdev, ufid)) {
            continue;
        }

        match->wc.masks.in_port.odp_port = u32_to_odp(UINT32_MAX);
        match->flow.in_port.odp_port = dump->port;

        return true;
    }

    return false;
}

static int
parse_put_flow_set_action(struct tc_flower *flower, const struct nlattr *set,
                          size_t set_len)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    const struct nlattr *set_attr;
    size_t set_left;

    NL_ATTR_FOR_EACH_UNSAFE(set_attr, set_left, set, set_len) {
        if (nl_attr_type(set_attr) == OVS_KEY_ATTR_TUNNEL) {
            const struct nlattr *tunnel = nl_attr_get(set_attr);
            const size_t tunnel_len = nl_attr_get_size(set_attr);
            const struct nlattr *tun_attr;
            size_t tun_left;

            flower->set.set = true;
            NL_ATTR_FOR_EACH_UNSAFE(tun_attr, tun_left, tunnel, tunnel_len) {
                switch (nl_attr_type(tun_attr)) {
                case OVS_TUNNEL_KEY_ATTR_ID: {
                    flower->set.id = nl_attr_get_be64(tun_attr);
                }
                break;
                case OVS_TUNNEL_KEY_ATTR_IPV4_SRC: {
                    flower->set.ipv4.ipv4_src = nl_attr_get_be32(tun_attr);
                }
                break;
                case OVS_TUNNEL_KEY_ATTR_IPV4_DST: {
                    flower->set.ipv4.ipv4_dst = nl_attr_get_be32(tun_attr);
                }
                break;
                case OVS_TUNNEL_KEY_ATTR_IPV6_SRC: {
                    flower->set.ipv6.ipv6_src =
                        nl_attr_get_in6_addr(tun_attr);
                }
                break;
                case OVS_TUNNEL_KEY_ATTR_IPV6_DST: {
                    flower->set.ipv6.ipv6_dst =
                        nl_attr_get_in6_addr(tun_attr);
                }
                break;
                case OVS_TUNNEL_KEY_ATTR_TP_SRC: {
                    flower->set.tp_src = nl_attr_get_be16(tun_attr);
                }
                break;
                case OVS_TUNNEL_KEY_ATTR_TP_DST: {
                    flower->set.tp_dst = nl_attr_get_be16(tun_attr);
                }
                break;
                }
            }
        } else {
            VLOG_DBG_RL(&rl, "unsupported set action type: %d",
                        nl_attr_type(set_attr));
            return EOPNOTSUPP;
        }
    }
    return 0;
}

static int
test_key_and_mask(struct match *match)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    const struct flow *key = &match->flow;
    struct flow *mask = &match->wc.masks;

    if (mask->pkt_mark) {
        VLOG_DBG_RL(&rl, "offloading attribute pkt_mark isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->recirc_id && key->recirc_id) {
        VLOG_DBG_RL(&rl, "offloading attribute recirc_id isn't supported");
        return EOPNOTSUPP;
    }
    mask->recirc_id = 0;

    if (mask->dp_hash) {
        VLOG_DBG_RL(&rl, "offloading attribute dp_hash isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->conj_id) {
        VLOG_DBG_RL(&rl, "offloading attribute conj_id isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->skb_priority) {
        VLOG_DBG_RL(&rl, "offloading attribute skb_priority isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->actset_output) {
        VLOG_DBG_RL(&rl,
                    "offloading attribute actset_output isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->ct_state) {
        VLOG_DBG_RL(&rl, "offloading attribute ct_state isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->ct_zone) {
        VLOG_DBG_RL(&rl, "offloading attribute ct_zone isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->ct_mark) {
        VLOG_DBG_RL(&rl, "offloading attribute ct_mark isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->packet_type && key->packet_type) {
        VLOG_DBG_RL(&rl, "offloading attribute packet_type isn't supported");
        return EOPNOTSUPP;
    }
    mask->packet_type = 0;

    if (!ovs_u128_is_zero(mask->ct_label)) {
        VLOG_DBG_RL(&rl, "offloading attribute ct_label isn't supported");
        return EOPNOTSUPP;
    }

    for (int i = 0; i < FLOW_N_REGS; i++) {
        if (mask->regs[i]) {
            VLOG_DBG_RL(&rl,
                        "offloading attribute regs[%d] isn't supported", i);
            return EOPNOTSUPP;
        }
    }

    if (mask->metadata) {
        VLOG_DBG_RL(&rl, "offloading attribute metadata isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->nw_tos) {
        VLOG_DBG_RL(&rl, "offloading attribute nw_tos isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->nw_ttl) {
        VLOG_DBG_RL(&rl, "offloading attribute nw_ttl isn't supported");
        return EOPNOTSUPP;
    }

    if (mask->nw_frag) {
        VLOG_DBG_RL(&rl, "offloading attribute nw_frag isn't supported");
        return EOPNOTSUPP;
    }

    for (int i = 0; i < FLOW_MAX_MPLS_LABELS; i++) {
        if (mask->mpls_lse[i]) {
            VLOG_DBG_RL(&rl, "offloading attribute mpls_lse isn't supported");
            return EOPNOTSUPP;
        }
    }

    if (key->dl_type == htons(ETH_TYPE_IP) &&
        key->nw_proto == IPPROTO_ICMP) {
        if (mask->tp_src) {
            VLOG_DBG_RL(&rl,
                        "offloading attribute icmp_type isn't supported");
            return EOPNOTSUPP;
        }
        if (mask->tp_dst) {
            VLOG_DBG_RL(&rl,
                        "offloading attribute icmp_code isn't supported");
            return EOPNOTSUPP;
        }
    } else if (key->dl_type == htons(ETH_TYPE_IP) &&
               key->nw_proto == IPPROTO_IGMP) {
        if (mask->tp_src) {
            VLOG_DBG_RL(&rl,
                        "offloading attribute igmp_type isn't supported");
            return EOPNOTSUPP;
        }
        if (mask->tp_dst) {
            VLOG_DBG_RL(&rl,
                        "offloading attribute igmp_code isn't supported");
            return EOPNOTSUPP;
        }
    } else if (key->dl_type == htons(ETH_TYPE_IPV6) &&
               key->nw_proto == IPPROTO_ICMPV6) {
        if (mask->tp_src) {
            VLOG_DBG_RL(&rl,
                        "offloading attribute icmp_type isn't supported");
            return EOPNOTSUPP;
        }
        if (mask->tp_dst) {
            VLOG_DBG_RL(&rl,
                        "offloading attribute icmp_code isn't supported");
            return EOPNOTSUPP;
        }
    }
    if (is_ip_any(key) && key->nw_proto == IPPROTO_TCP && mask->tcp_flags) {
        if (mask->tcp_flags) {
            VLOG_DBG_RL(&rl,
                        "offloading attribute tcp_flags isn't supported");
            return EOPNOTSUPP;
        }
    }

    if (!is_all_zeros(mask, sizeof *mask)) {
        VLOG_DBG_RL(&rl, "offloading isn't supported, unknown attribute");
        return EOPNOTSUPP;
    }

    return 0;
}

int
netdev_tc_flow_put(struct netdev *netdev, struct match *match,
                   struct nlattr *actions, size_t actions_len,
                   const ovs_u128 *ufid, struct offload_info *info,
                   struct dpif_flow_stats *stats OVS_UNUSED)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct tc_flower flower;
    const struct flow *key = &match->flow;
    struct flow *mask = &match->wc.masks;
    const struct flow_tnl *tnl = &match->flow.tunnel;
    struct nlattr *nla;
    size_t left;
    int prio = 0;
    int handle;
    int ifindex;
    int err;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    memset(&flower, 0, sizeof flower);

    if (tnl->tun_id) {
        VLOG_DBG_RL(&rl,
                    "tunnel: id %#" PRIx64 " src " IP_FMT
                    " dst " IP_FMT " tp_src %d tp_dst %d",
                    ntohll(tnl->tun_id),
                    IP_ARGS(tnl->ip_src), IP_ARGS(tnl->ip_dst),
                    ntohs(tnl->tp_src), ntohs(tnl->tp_dst));
        flower.tunnel.id = tnl->tun_id;
        flower.tunnel.ipv4.ipv4_src = tnl->ip_src;
        flower.tunnel.ipv4.ipv4_dst = tnl->ip_dst;
        flower.tunnel.ipv6.ipv6_src = tnl->ipv6_src;
        flower.tunnel.ipv6.ipv6_dst = tnl->ipv6_dst;
        flower.tunnel.tp_src = tnl->tp_src;
        flower.tunnel.tp_dst = tnl->tp_dst;
        flower.tunnel.tunnel = true;

        memset(&mask->tunnel, 0, sizeof mask->tunnel);
    }

    flower.key.eth_type = key->dl_type;
    flower.mask.eth_type = mask->dl_type;

    if (mask->vlans[0].tci) {
        ovs_be16 vid_mask = mask->vlans[0].tci & htons(VLAN_VID_MASK);
        ovs_be16 pcp_mask = mask->vlans[0].tci & htons(VLAN_PCP_MASK);
        ovs_be16 cfi = mask->vlans[0].tci & htons(VLAN_CFI);

        if (cfi && key->vlans[0].tci & htons(VLAN_CFI)
            && (!vid_mask || vid_mask == htons(VLAN_VID_MASK))
            && (!pcp_mask || pcp_mask == htons(VLAN_PCP_MASK))
            && (vid_mask || pcp_mask)) {
            if (vid_mask) {
                flower.key.vlan_id = vlan_tci_to_vid(key->vlans[0].tci);
                VLOG_DBG_RL(&rl, "vlan_id: %d\n", flower.key.vlan_id);
            }
            if (pcp_mask) {
                flower.key.vlan_prio = vlan_tci_to_pcp(key->vlans[0].tci);
                VLOG_DBG_RL(&rl, "vlan_prio: %d\n", flower.key.vlan_prio);
            }
            flower.key.encap_eth_type = flower.key.eth_type;
            flower.key.eth_type = htons(ETH_TYPE_VLAN);
        } else if (mask->vlans[0].tci == htons(0xffff) &&
                   ntohs(key->vlans[0].tci) == 0) {
            /* exact && no vlan */
        } else {
            /* partial mask */
            return EOPNOTSUPP;
        }
    } else if (mask->vlans[1].tci) {
        return EOPNOTSUPP;
    }
    memset(mask->vlans, 0, sizeof mask->vlans);

    flower.key.dst_mac = key->dl_dst;
    flower.mask.dst_mac = mask->dl_dst;
    flower.key.src_mac = key->dl_src;
    flower.mask.src_mac = mask->dl_src;
    memset(&mask->dl_dst, 0, sizeof mask->dl_dst);
    memset(&mask->dl_src, 0, sizeof mask->dl_src);
    mask->dl_type = 0;
    mask->in_port.odp_port = 0;

    if (is_ip_any(key)) {
        flower.key.ip_proto = key->nw_proto;
        flower.mask.ip_proto = mask->nw_proto;

        if (key->nw_proto == IPPROTO_TCP) {
            flower.key.tcp_dst = key->tp_dst;
            flower.mask.tcp_dst = mask->tp_dst;
            flower.key.tcp_src = key->tp_src;
            flower.mask.tcp_src = mask->tp_src;
            mask->tp_src = 0;
            mask->tp_dst = 0;
        } else if (key->nw_proto == IPPROTO_UDP) {
            flower.key.udp_dst = key->tp_dst;
            flower.mask.udp_dst = mask->tp_dst;
            flower.key.udp_src = key->tp_src;
            flower.mask.udp_src = mask->tp_src;
            mask->tp_src = 0;
            mask->tp_dst = 0;
        } else if (key->nw_proto == IPPROTO_SCTP) {
            flower.key.sctp_dst = key->tp_dst;
            flower.mask.sctp_dst = mask->tp_dst;
            flower.key.sctp_src = key->tp_src;
            flower.mask.sctp_src = mask->tp_src;
            mask->tp_src = 0;
            mask->tp_dst = 0;
        }

        mask->nw_frag = 0;
        mask->nw_tos = 0;
        mask->nw_proto = 0;

        if (key->dl_type == htons(ETH_P_IP)) {
            flower.key.ipv4.ipv4_src = key->nw_src;
            flower.mask.ipv4.ipv4_src = mask->nw_src;
            flower.key.ipv4.ipv4_dst = key->nw_dst;
            flower.mask.ipv4.ipv4_dst = mask->nw_dst;
            mask->nw_src = 0;
            mask->nw_dst = 0;
        } else if (key->dl_type == htons(ETH_P_IPV6)) {
            flower.key.ipv6.ipv6_src = key->ipv6_src;
            flower.mask.ipv6.ipv6_src = mask->ipv6_src;
            flower.key.ipv6.ipv6_dst = key->ipv6_dst;
            flower.mask.ipv6.ipv6_dst = mask->ipv6_dst;
            memset(&mask->ipv6_src, 0, sizeof mask->ipv6_src);
            memset(&mask->ipv6_dst, 0, sizeof mask->ipv6_dst);
        }
    }

    err = test_key_and_mask(match);
    if (err) {
        return err;
    }

    NL_ATTR_FOR_EACH(nla, left, actions, actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            odp_port_t port = nl_attr_get_odp_port(nla);
            struct netdev *outdev = netdev_ports_get(port, info->dpif_class);

            flower.ifindex_out = netdev_get_ifindex(outdev);
            flower.set.tp_dst = info->tp_dst_port;
            netdev_close(outdev);
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_PUSH_VLAN) {
            const struct ovs_action_push_vlan *vlan_push = nl_attr_get(nla);

            flower.vlan_push_id = vlan_tci_to_vid(vlan_push->vlan_tci);
            flower.vlan_push_prio = vlan_tci_to_pcp(vlan_push->vlan_tci);
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_POP_VLAN) {
            flower.vlan_pop = 1;
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SET) {
            const struct nlattr *set = nl_attr_get(nla);
            const size_t set_len = nl_attr_get_size(nla);

            err = parse_put_flow_set_action(&flower, set, set_len);
            if (err) {
                return err;
            }
        } else {
            VLOG_DBG_RL(&rl, "unsupported put action type: %d",
                        nl_attr_type(nla));
            return EOPNOTSUPP;
        }
    }

    handle = get_ufid_tc_mapping(ufid, &prio, NULL);
    if (handle && prio) {
        VLOG_DBG_RL(&rl, "updating old handle: %d prio: %d", handle, prio);
        tc_del_filter(ifindex, prio, handle);
    }

    if (!prio) {
        prio = get_prio_for_tc_flower(&flower);
        if (prio == 0) {
            VLOG_ERR_RL(&rl, "couldn't get tc prio: %s", ovs_strerror(ENOSPC));
            return ENOSPC;
        }
    }

    flower.act_cookie.data = ufid;
    flower.act_cookie.len = sizeof *ufid;

    err = tc_replace_flower(ifindex, prio, handle, &flower);
    if (!err) {
        add_ufid_tc_mapping(ufid, flower.prio, flower.handle, netdev, ifindex);
    }

    return err;
}

int
netdev_tc_flow_get(struct netdev *netdev OVS_UNUSED,
                   struct match *match,
                   struct nlattr **actions,
                   const ovs_u128 *ufid,
                   struct dpif_flow_stats *stats,
                   struct ofpbuf *buf)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct netdev *dev;
    struct tc_flower flower;
    odp_port_t in_port;
    int prio = 0;
    int ifindex;
    int handle;
    int err;

    handle = get_ufid_tc_mapping(ufid, &prio, &dev);
    if (!handle) {
        return ENOENT;
    }

    ifindex = netdev_get_ifindex(dev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "failed to get ifindex for %s: %s",
                    netdev_get_name(dev), ovs_strerror(-ifindex));
        netdev_close(dev);
        return -ifindex;
    }

    VLOG_DBG_RL(&rl, "flow get (dev %s prio %d handle %d)",
                netdev_get_name(dev), prio, handle);
    err = tc_get_flower(ifindex, prio, handle, &flower);
    netdev_close(dev);
    if (err) {
        VLOG_ERR_RL(&error_rl, "flow get failed (dev %s prio %d handle %d): %s",
                    netdev_get_name(dev), prio, handle, ovs_strerror(err));
        return err;
    }

    in_port = netdev_ifindex_to_odp_port(ifindex);
    parse_tc_flower_to_match(&flower, match, actions, stats, buf);

    match->wc.masks.in_port.odp_port = u32_to_odp(UINT32_MAX);
    match->flow.in_port.odp_port = in_port;

    return 0;
}

int
netdev_tc_flow_del(struct netdev *netdev OVS_UNUSED,
                   const ovs_u128 *ufid,
                   struct dpif_flow_stats *stats)
{
    struct netdev *dev;
    int prio = 0;
    int ifindex;
    int handle;
    int error;

    handle = get_ufid_tc_mapping(ufid, &prio, &dev);
    if (!handle) {
        return ENOENT;
    }

    ifindex = netdev_get_ifindex(dev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "failed to get ifindex for %s: %s",
                    netdev_get_name(dev), ovs_strerror(-ifindex));
        netdev_close(dev);
        return -ifindex;
    }

    error = tc_del_filter(ifindex, prio, handle);
    del_ufid_tc_mapping(ufid);

    netdev_close(dev);

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return error;
}

int
netdev_tc_init_flow_api(struct netdev *netdev)
{
    int ifindex;
    int error;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    error = tc_add_del_ingress_qdisc(ifindex, true);

    if (error && error != EEXIST) {
        VLOG_ERR("failed adding ingress qdisc required for offloading: %s",
                 ovs_strerror(error));
        return error;
    }

    VLOG_INFO("added ingress qdisc to %s", netdev_get_name(netdev));

    return 0;
}
