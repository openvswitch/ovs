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
#include "openvswitch/util.h"
#include "openvswitch/vlog.h"
#include "netdev-linux.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "odp-netlink.h"
#include "odp-util.h"
#include "tc.h"
#include "unaligned.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netdev_tc_offloads);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static struct hmap ufid_tc = HMAP_INITIALIZER(&ufid_tc);
static bool multi_mask_per_prio = false;
static bool block_support = false;

struct netlink_field {
    int offset;
    int flower_offset;
    int size;
};

static struct netlink_field set_flower_map[][3] = {
    [OVS_KEY_ATTR_IPV4] = {
        { offsetof(struct ovs_key_ipv4, ipv4_src),
          offsetof(struct tc_flower_key, ipv4.ipv4_src),
          MEMBER_SIZEOF(struct tc_flower_key, ipv4.ipv4_src)
        },
        { offsetof(struct ovs_key_ipv4, ipv4_dst),
          offsetof(struct tc_flower_key, ipv4.ipv4_dst),
          MEMBER_SIZEOF(struct tc_flower_key, ipv4.ipv4_dst)
        },
        { offsetof(struct ovs_key_ipv4, ipv4_ttl),
          offsetof(struct tc_flower_key, ipv4.rewrite_ttl),
          MEMBER_SIZEOF(struct tc_flower_key, ipv4.rewrite_ttl)
        },
    },
    [OVS_KEY_ATTR_IPV6] = {
        { offsetof(struct ovs_key_ipv6, ipv6_src),
          offsetof(struct tc_flower_key, ipv6.ipv6_src),
          MEMBER_SIZEOF(struct tc_flower_key, ipv6.ipv6_src)
        },
        { offsetof(struct ovs_key_ipv6, ipv6_dst),
          offsetof(struct tc_flower_key, ipv6.ipv6_dst),
          MEMBER_SIZEOF(struct tc_flower_key, ipv6.ipv6_dst)
        },
    },
    [OVS_KEY_ATTR_ETHERNET] = {
        { offsetof(struct ovs_key_ethernet, eth_src),
          offsetof(struct tc_flower_key, src_mac),
          MEMBER_SIZEOF(struct tc_flower_key, src_mac)
        },
        { offsetof(struct ovs_key_ethernet, eth_dst),
          offsetof(struct tc_flower_key, dst_mac),
          MEMBER_SIZEOF(struct tc_flower_key, dst_mac)
        },
    },
    [OVS_KEY_ATTR_ETHERTYPE] = {
        { 0,
          offsetof(struct tc_flower_key, eth_type),
          MEMBER_SIZEOF(struct tc_flower_key, eth_type)
        },
    },
    [OVS_KEY_ATTR_TCP] = {
        { offsetof(struct ovs_key_tcp, tcp_src),
          offsetof(struct tc_flower_key, tcp_src),
          MEMBER_SIZEOF(struct tc_flower_key, tcp_src)
        },
        { offsetof(struct ovs_key_tcp, tcp_dst),
          offsetof(struct tc_flower_key, tcp_dst),
          MEMBER_SIZEOF(struct tc_flower_key, tcp_dst)
        },
    },
    [OVS_KEY_ATTR_UDP] = {
        { offsetof(struct ovs_key_udp, udp_src),
          offsetof(struct tc_flower_key, udp_src),
          MEMBER_SIZEOF(struct tc_flower_key, udp_src)
        },
        { offsetof(struct ovs_key_udp, udp_dst),
          offsetof(struct tc_flower_key, udp_dst),
          MEMBER_SIZEOF(struct tc_flower_key, udp_dst)
        },
    },
};

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
    size_t hash = hash_int((OVS_FORCE uint32_t) flower->key.eth_type, 0);
    struct prio_map_data *data;
    struct prio_map_data *new_data;

    if (!multi_mask_per_prio) {
        hash = hash_bytes(&flower->mask, key_len, hash);
    }

    /* We can use the same prio for same mask/eth combination but must have
     * different prio if not. Flower classifier will reject same prio for
     * different mask combination unless multi mask per prio is supported. */
    ovs_mutex_lock(&prios_lock);
    HMAP_FOR_EACH_WITH_HASH(data, node, hash, &prios) {
        if ((multi_mask_per_prio
             || !memcmp(&flower->mask, &data->mask, key_len))
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

static uint32_t
get_block_id_from_netdev(struct netdev *netdev)
{
    if (block_support) {
        return netdev_get_block_id(netdev);
    }

    return 0;
}

int
netdev_tc_flow_flush(struct netdev *netdev)
{
    int ifindex = netdev_get_ifindex(netdev);
    uint32_t block_id = 0;

    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "flow_flush: failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    block_id = get_block_id_from_netdev(netdev);

    return tc_flush(ifindex, block_id);
}

int
netdev_tc_flow_dump_create(struct netdev *netdev,
                           struct netdev_flow_dump **dump_out)
{
    struct netdev_flow_dump *dump;
    uint32_t block_id = 0;
    int ifindex;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "dump_create: failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    block_id = get_block_id_from_netdev(netdev);
    dump = xzalloc(sizeof *dump);
    dump->nl_dump = xzalloc(sizeof *dump->nl_dump);
    dump->netdev = netdev_ref(netdev);
    tc_dump_flower_start(ifindex, dump->nl_dump, block_id);

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

static void
parse_flower_rewrite_to_netlink_action(struct ofpbuf *buf,
                                       struct tc_flower *flower)
{
    char *mask = (char *) &flower->rewrite.mask;
    char *data = (char *) &flower->rewrite.key;

    for (int type = 0; type < ARRAY_SIZE(set_flower_map); type++) {
        char *put = NULL;
        size_t nested = 0;
        int len = ovs_flow_key_attr_lens[type].len;

        if (len <= 0) {
            continue;
        }

        for (int j = 0; j < ARRAY_SIZE(set_flower_map[type]); j++) {
            struct netlink_field *f = &set_flower_map[type][j];

            if (!f->size) {
                break;
            }

            if (!is_all_zeros(mask + f->flower_offset, f->size)) {
                if (!put) {
                    nested = nl_msg_start_nested(buf,
                                                 OVS_ACTION_ATTR_SET_MASKED);
                    put = nl_msg_put_unspec_zero(buf, type, len * 2);
                }

                memcpy(put + f->offset, data + f->flower_offset, f->size);
                memcpy(put + len + f->offset,
                       mask + f->flower_offset, f->size);
            }
        }

        if (put) {
            nl_msg_end_nested(buf, nested);
        }
    }
}

static int
parse_tc_flower_to_match(struct tc_flower *flower,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         struct dpif_flow_attrs *attrs,
                         struct ofpbuf *buf)
{
    size_t act_off;
    struct tc_flower_key *key = &flower->key;
    struct tc_flower_key *mask = &flower->mask;
    odp_port_t outport = 0;
    struct tc_action *action;
    int i;

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

        match_set_nw_ttl_masked(match, key->ip_ttl, mask->ip_ttl);

        if (mask->flags) {
            uint8_t flags = 0;
            uint8_t flags_mask = 0;

            if (mask->flags & TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT) {
                if (key->flags & TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT) {
                    flags |= FLOW_NW_FRAG_ANY;
                }
                flags_mask |= FLOW_NW_FRAG_ANY;
            }

            if (mask->flags & TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST) {
                if (!(key->flags & TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST)) {
                    flags |= FLOW_NW_FRAG_LATER;
                }
                flags_mask |= FLOW_NW_FRAG_LATER;
            }

            match_set_nw_frag_masked(match, flags, flags_mask);
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
            match_set_tcp_flags_masked(match, key->tcp_flags, mask->tcp_flags);
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
        action = flower->actions;
        for (i = 0; i < flower->action_count; i++, action++) {
            switch (action->type) {
            case TC_ACT_VLAN_POP: {
                nl_msg_put_flag(buf, OVS_ACTION_ATTR_POP_VLAN);
            }
            break;
            case TC_ACT_VLAN_PUSH: {
                struct ovs_action_push_vlan *push;

                push = nl_msg_put_unspec_zero(buf, OVS_ACTION_ATTR_PUSH_VLAN,
                                              sizeof *push);
                push->vlan_tpid = htons(ETH_TYPE_VLAN);
                push->vlan_tci = htons(action->vlan.vlan_push_id
                                       | (action->vlan.vlan_push_prio << 13)
                                       | VLAN_CFI);
            }
            break;
            case TC_ACT_PEDIT: {
                parse_flower_rewrite_to_netlink_action(buf, flower);
            }
            break;
            case TC_ACT_ENCAP: {
                size_t set_offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_SET);
                size_t tunnel_offset =
                    nl_msg_start_nested(buf, OVS_KEY_ATTR_TUNNEL);

                nl_msg_put_be64(buf, OVS_TUNNEL_KEY_ATTR_ID, action->encap.id);
                if (action->encap.ipv4.ipv4_src) {
                    nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
                                    action->encap.ipv4.ipv4_src);
                }
                if (action->encap.ipv4.ipv4_dst) {
                    nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                                    action->encap.ipv4.ipv4_dst);
                }
                if (!is_all_zeros(&action->encap.ipv6.ipv6_src,
                                  sizeof action->encap.ipv6.ipv6_src)) {
                    nl_msg_put_in6_addr(buf, OVS_TUNNEL_KEY_ATTR_IPV6_SRC,
                                        &action->encap.ipv6.ipv6_src);
                }
                if (!is_all_zeros(&action->encap.ipv6.ipv6_dst,
                                  sizeof action->encap.ipv6.ipv6_dst)) {
                    nl_msg_put_in6_addr(buf, OVS_TUNNEL_KEY_ATTR_IPV6_DST,
                                        &action->encap.ipv6.ipv6_dst);
                }
                nl_msg_put_be16(buf, OVS_TUNNEL_KEY_ATTR_TP_DST,
                                action->encap.tp_dst);

                nl_msg_end_nested(buf, tunnel_offset);
                nl_msg_end_nested(buf, set_offset);
            }
            break;
            case TC_ACT_OUTPUT: {
                if (action->ifindex_out) {
                    outport = netdev_ifindex_to_odp_port(action->ifindex_out);
                    if (!outport) {
                        return ENOENT;
                    }
                }
                nl_msg_put_u32(buf, OVS_ACTION_ATTR_OUTPUT, odp_to_u32(outport));
            }
            break;
            }
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

    attrs->offloaded = (flower->offloaded_state == TC_OFFLOADED_STATE_IN_HW)
                       || (flower->offloaded_state == TC_OFFLOADED_STATE_UNDEFINED);
    attrs->dp_layer = "tc";

    return 0;
}

bool
netdev_tc_flow_dump_next(struct netdev_flow_dump *dump,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         struct dpif_flow_attrs *attrs,
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

        if (parse_tc_flower_to_match(&flower, match, actions, stats, attrs,
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
parse_put_flow_set_masked_action(struct tc_flower *flower,
                                 struct tc_action *action,
                                 const struct nlattr *set,
                                 size_t set_len,
                                 bool hasmask)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    uint64_t set_stub[1024 / 8];
    struct ofpbuf set_buf = OFPBUF_STUB_INITIALIZER(set_stub);
    char *set_data, *set_mask;
    char *key = (char *) &flower->rewrite.key;
    char *mask = (char *) &flower->rewrite.mask;
    const struct nlattr *attr;
    int i, j, type;
    size_t size;

    /* copy so we can set attr mask to 0 for used ovs key struct members  */
    attr = ofpbuf_put(&set_buf, set, set_len);

    type = nl_attr_type(attr);
    size = nl_attr_get_size(attr) / 2;
    set_data = CONST_CAST(char *, nl_attr_get(attr));
    set_mask = set_data + size;

    if (type >= ARRAY_SIZE(set_flower_map)
        || !set_flower_map[type][0].size) {
        VLOG_DBG_RL(&rl, "unsupported set action type: %d", type);
        ofpbuf_uninit(&set_buf);
        return EOPNOTSUPP;
    }

    for (i = 0; i < ARRAY_SIZE(set_flower_map[type]); i++) {
        struct netlink_field *f = &set_flower_map[type][i];

        if (!f->size) {
            break;
        }

        /* copy masked value */
        for (j = 0; j < f->size; j++) {
            char maskval = hasmask ? set_mask[f->offset + j] : 0xFF;

            key[f->flower_offset + j] = maskval & set_data[f->offset + j];
            mask[f->flower_offset + j] = maskval;

        }

        /* set its mask to 0 to show it's been used. */
        if (hasmask) {
            memset(set_mask + f->offset, 0, f->size);
        }
    }

    if (!is_all_zeros(&flower->rewrite, sizeof flower->rewrite)) {
        if (flower->rewrite.rewrite == false) {
            flower->rewrite.rewrite = true;
            action->type = TC_ACT_PEDIT;
            flower->action_count++;
        }
    }

    if (hasmask && !is_all_zeros(set_mask, size)) {
        VLOG_DBG_RL(&rl, "unsupported sub attribute of set action type %d",
                    type);
        ofpbuf_uninit(&set_buf);
        return EOPNOTSUPP;
    }

    ofpbuf_uninit(&set_buf);
    return 0;
}

static int
parse_put_flow_set_action(struct tc_flower *flower, struct tc_action *action,
                          const struct nlattr *set, size_t set_len)
{
    const struct nlattr *tunnel;
    const struct nlattr *tun_attr;
    size_t tun_left, tunnel_len;

    if (nl_attr_type(set) != OVS_KEY_ATTR_TUNNEL) {
            return parse_put_flow_set_masked_action(flower, action, set,
                                                    set_len, false);
    }

    tunnel = nl_attr_get(set);
    tunnel_len = nl_attr_get_size(set);

    action->type = TC_ACT_ENCAP;
    flower->action_count++;
    NL_ATTR_FOR_EACH_UNSAFE(tun_attr, tun_left, tunnel, tunnel_len) {
        switch (nl_attr_type(tun_attr)) {
        case OVS_TUNNEL_KEY_ATTR_ID: {
            action->encap.id = nl_attr_get_be64(tun_attr);
        }
        break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_SRC: {
            action->encap.ipv4.ipv4_src = nl_attr_get_be32(tun_attr);
        }
        break;
        case OVS_TUNNEL_KEY_ATTR_IPV4_DST: {
            action->encap.ipv4.ipv4_dst = nl_attr_get_be32(tun_attr);
        }
        break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_SRC: {
            action->encap.ipv6.ipv6_src =
                nl_attr_get_in6_addr(tun_attr);
        }
        break;
        case OVS_TUNNEL_KEY_ATTR_IPV6_DST: {
            action->encap.ipv6.ipv6_dst =
                nl_attr_get_in6_addr(tun_attr);
        }
        break;
        case OVS_TUNNEL_KEY_ATTR_TP_SRC: {
            action->encap.tp_src = nl_attr_get_be16(tun_attr);
        }
        break;
        case OVS_TUNNEL_KEY_ATTR_TP_DST: {
            action->encap.tp_dst = nl_attr_get_be16(tun_attr);
        }
        break;
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
    struct tc_action *action;
    uint32_t block_id = 0;
    struct nlattr *nla;
    size_t left;
    int prio = 0;
    int handle;
    int ifindex;
    int err;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "flow_put: failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    memset(&flower, 0, sizeof flower);

    if (flow_tnl_dst_is_set(&key->tunnel)) {
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
    }
    memset(&mask->tunnel, 0, sizeof mask->tunnel);

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
        flower.key.ip_ttl = key->nw_ttl;
        flower.mask.ip_ttl = mask->nw_ttl;

        if (mask->nw_frag & FLOW_NW_FRAG_ANY) {
            flower.mask.flags |= TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT;

            if (key->nw_frag & FLOW_NW_FRAG_ANY) {
                flower.key.flags |= TCA_FLOWER_KEY_FLAGS_IS_FRAGMENT;

                if (mask->nw_frag & FLOW_NW_FRAG_LATER) {
                    flower.mask.flags |= TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST;

                    if (!(key->nw_frag & FLOW_NW_FRAG_LATER)) {
                        flower.key.flags |= TCA_FLOWER_KEY_FLAGS_FRAG_IS_FIRST;
                    }
                }
            }

            mask->nw_frag = 0;
        }

        if (key->nw_proto == IPPROTO_TCP) {
            flower.key.tcp_dst = key->tp_dst;
            flower.mask.tcp_dst = mask->tp_dst;
            flower.key.tcp_src = key->tp_src;
            flower.mask.tcp_src = mask->tp_src;
            flower.key.tcp_flags = key->tcp_flags;
            flower.mask.tcp_flags = mask->tcp_flags;
            mask->tp_src = 0;
            mask->tp_dst = 0;
            mask->tcp_flags = 0;
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

        mask->nw_tos = 0;
        mask->nw_proto = 0;
        mask->nw_ttl = 0;

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
        if (flower.action_count >= TCA_ACT_MAX_PRIO) {
            VLOG_DBG_RL(&rl, "Can only support %d actions", flower.action_count);
            return EOPNOTSUPP;
        }
        action = &flower.actions[flower.action_count];
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            odp_port_t port = nl_attr_get_odp_port(nla);
            struct netdev *outdev = netdev_ports_get(port, info->dpif_class);

            action->ifindex_out = netdev_get_ifindex(outdev);
            action->type = TC_ACT_OUTPUT;
            flower.action_count++;
            netdev_close(outdev);
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_PUSH_VLAN) {
            const struct ovs_action_push_vlan *vlan_push = nl_attr_get(nla);

            action->vlan.vlan_push_id = vlan_tci_to_vid(vlan_push->vlan_tci);
            action->vlan.vlan_push_prio = vlan_tci_to_pcp(vlan_push->vlan_tci);
            action->type = TC_ACT_VLAN_PUSH;
            flower.action_count++;
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_POP_VLAN) {
            action->type = TC_ACT_VLAN_POP;
            flower.action_count++;
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SET) {
            const struct nlattr *set = nl_attr_get(nla);
            const size_t set_len = nl_attr_get_size(nla);

            err = parse_put_flow_set_action(&flower, action, set, set_len);
            if (err) {
                return err;
            }
            if (action->type == TC_ACT_ENCAP) {
                action->encap.tp_dst = info->tp_dst_port;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED) {
            const struct nlattr *set = nl_attr_get(nla);
            const size_t set_len = nl_attr_get_size(nla);

            err = parse_put_flow_set_masked_action(&flower, action, set,
                                                   set_len, true);
            if (err) {
                return err;
            }
        } else {
            VLOG_DBG_RL(&rl, "unsupported put action type: %d",
                        nl_attr_type(nla));
            return EOPNOTSUPP;
        }
    }

    block_id = get_block_id_from_netdev(netdev);
    handle = get_ufid_tc_mapping(ufid, &prio, NULL);
    if (handle && prio) {
        VLOG_DBG_RL(&rl, "updating old handle: %d prio: %d", handle, prio);
        tc_del_filter(ifindex, prio, handle, block_id);
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

    err = tc_replace_flower(ifindex, prio, handle, &flower, block_id);
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
                   struct dpif_flow_attrs *attrs,
                   struct ofpbuf *buf)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct netdev *dev;
    struct tc_flower flower;
    uint32_t block_id = 0;
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
        VLOG_ERR_RL(&error_rl, "flow_get: failed to get ifindex for %s: %s",
                    netdev_get_name(dev), ovs_strerror(-ifindex));
        netdev_close(dev);
        return -ifindex;
    }

    VLOG_DBG_RL(&rl, "flow get (dev %s prio %d handle %d)",
                netdev_get_name(dev), prio, handle);
    block_id = get_block_id_from_netdev(netdev);
    err = tc_get_flower(ifindex, prio, handle, &flower, block_id);
    netdev_close(dev);
    if (err) {
        VLOG_ERR_RL(&error_rl, "flow get failed (dev %s prio %d handle %d): %s",
                    netdev_get_name(dev), prio, handle, ovs_strerror(err));
        return err;
    }

    in_port = netdev_ifindex_to_odp_port(ifindex);
    parse_tc_flower_to_match(&flower, match, actions, stats, attrs, buf);

    match->wc.masks.in_port.odp_port = u32_to_odp(UINT32_MAX);
    match->flow.in_port.odp_port = in_port;

    return 0;
}

int
netdev_tc_flow_del(struct netdev *netdev OVS_UNUSED,
                   const ovs_u128 *ufid,
                   struct dpif_flow_stats *stats)
{
    struct tc_flower flower;
    uint32_t block_id = 0;
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
        VLOG_ERR_RL(&error_rl, "flow_del: failed to get ifindex for %s: %s",
                    netdev_get_name(dev), ovs_strerror(-ifindex));
        netdev_close(dev);
        return -ifindex;
    }

    block_id = get_block_id_from_netdev(netdev);

    if (stats) {
        memset(stats, 0, sizeof *stats);
        if (!tc_get_flower(ifindex, prio, handle, &flower, block_id)) {
            stats->n_packets = get_32aligned_u64(&flower.stats.n_packets);
            stats->n_bytes = get_32aligned_u64(&flower.stats.n_bytes);
            stats->used = flower.lastused;
        }
    }

    error = tc_del_filter(ifindex, prio, handle, block_id);
    del_ufid_tc_mapping(ufid);

    netdev_close(dev);

    return error;
}

static void
probe_multi_mask_per_prio(int ifindex)
{
    struct tc_flower flower;
    int block_id = 0;
    int error;

    error = tc_add_del_ingress_qdisc(ifindex, true, block_id);
    if (error) {
        return;
    }

    memset(&flower, 0, sizeof flower);

    flower.key.eth_type = htons(ETH_P_IP);
    flower.mask.eth_type = OVS_BE16_MAX;
    memset(&flower.key.dst_mac, 0x11, sizeof flower.key.dst_mac);
    memset(&flower.mask.dst_mac, 0xff, sizeof flower.mask.dst_mac);

    error = tc_replace_flower(ifindex, 1, 1, &flower, block_id);
    if (error) {
        goto out;
    }

    memset(&flower.key.src_mac, 0x11, sizeof flower.key.src_mac);
    memset(&flower.mask.src_mac, 0xff, sizeof flower.mask.src_mac);

    error = tc_replace_flower(ifindex, 1, 2, &flower, block_id);
    tc_del_filter(ifindex, 1, 1, block_id);

    if (error) {
        goto out;
    }

    tc_del_filter(ifindex, 1, 2, block_id);

    multi_mask_per_prio = true;
    VLOG_INFO("probe tc: multiple masks on single tc prio is supported.");

out:
    tc_add_del_ingress_qdisc(ifindex, false, block_id);
}

static void
probe_tc_block_support(int ifindex)
{
    uint32_t block_id = 1;
    int error;

    error = tc_add_del_ingress_qdisc(ifindex, true, block_id);
    if (error) {
        return;
    }

    tc_add_del_ingress_qdisc(ifindex, false, block_id);

    block_support = true;
    VLOG_INFO("probe tc: block offload is supported.");
}

int
netdev_tc_init_flow_api(struct netdev *netdev)
{
    static struct ovsthread_once multi_mask_once = OVSTHREAD_ONCE_INITIALIZER;
    static struct ovsthread_once block_once = OVSTHREAD_ONCE_INITIALIZER;
    uint32_t block_id = 0;
    int ifindex;
    int error;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "init: failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    if (ovsthread_once_start(&block_once)) {
        probe_tc_block_support(ifindex);
        ovsthread_once_done(&block_once);
    }

    if (ovsthread_once_start(&multi_mask_once)) {
        probe_multi_mask_per_prio(ifindex);
        ovsthread_once_done(&multi_mask_once);
    }

    block_id = get_block_id_from_netdev(netdev);
    error = tc_add_del_ingress_qdisc(ifindex, true, block_id);

    if (error && error != EEXIST) {
        VLOG_ERR("failed adding ingress qdisc required for offloading: %s",
                 ovs_strerror(error));
        return error;
    }

    VLOG_INFO("added ingress qdisc to %s", netdev_get_name(netdev));

    return 0;
}
