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
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "openvswitch/vlog.h"
#include "netdev-provider.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "odp-netlink.h"
#include "unaligned.h"
#include "util.h"
#include "hash.h"
#include "dpif.h"
#include "tc.h"

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
static void OVS_UNUSED
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
static int OVS_UNUSED
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
static uint16_t OVS_UNUSED
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

    if (key->ip_proto && is_ip_any(&match->flow)) {
        match_set_nw_proto(match, key->ip_proto);
    }

    match_set_nw_src_masked(match, key->ipv4.ipv4_src, mask->ipv4.ipv4_src);
    match_set_nw_dst_masked(match, key->ipv4.ipv4_dst, mask->ipv4.ipv4_dst);

    match_set_ipv6_src_masked(match,
                              &key->ipv6.ipv6_src, &mask->ipv6.ipv6_src);
    match_set_ipv6_dst_masked(match,
                              &key->ipv6.ipv6_dst, &mask->ipv6.ipv6_dst);

    match_set_tp_dst_masked(match, key->dst_port, mask->dst_port);
    match_set_tp_src_masked(match, key->src_port, mask->src_port);

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

int
netdev_tc_flow_put(struct netdev *netdev OVS_UNUSED,
                   struct match *match OVS_UNUSED,
                   struct nlattr *actions OVS_UNUSED,
                   size_t actions_len OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct offload_info *info OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_get(struct netdev *netdev OVS_UNUSED,
                   struct match *match OVS_UNUSED,
                   struct nlattr **actions OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED,
                   struct ofpbuf *buf OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_del(struct netdev *netdev OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_init_flow_api(struct netdev *netdev OVS_UNUSED)
{
    return 0;
}
