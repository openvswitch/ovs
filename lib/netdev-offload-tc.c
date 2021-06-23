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
#include "netdev-offload-provider.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "odp-netlink.h"
#include "odp-util.h"
#include "tc.h"
#include "unaligned.h"
#include "util.h"
#include "dpif-provider.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_tc);

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static struct hmap ufid_to_tc = HMAP_INITIALIZER(&ufid_to_tc);
static struct hmap tc_to_ufid = HMAP_INITIALIZER(&tc_to_ufid);
static bool multi_mask_per_prio = false;
static bool block_support = false;
static uint16_t ct_state_support;

struct netlink_field {
    int offset;
    int flower_offset;
    int size;
};

struct chain_node {
    struct hmap_node node;
    uint32_t chain;
};

static bool
is_internal_port(const char *type)
{
    return !strcmp(type, "internal");
}

static enum tc_qdisc_hook
get_tc_qdisc_hook(struct netdev *netdev)
{
    return is_internal_port(netdev_get_type(netdev)) ? TC_EGRESS : TC_INGRESS;
}

static struct netlink_field set_flower_map[][4] = {
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
        { offsetof(struct ovs_key_ipv4, ipv4_tos),
          offsetof(struct tc_flower_key, ipv4.rewrite_tos),
          MEMBER_SIZEOF(struct tc_flower_key, ipv4.rewrite_tos)
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
        { offsetof(struct ovs_key_ipv6, ipv6_hlimit),
          offsetof(struct tc_flower_key, ipv6.rewrite_hlimit),
          MEMBER_SIZEOF(struct tc_flower_key, ipv6.rewrite_hlimit)
        },
        { offsetof(struct ovs_key_ipv6, ipv6_tclass),
          offsetof(struct tc_flower_key, ipv6.rewrite_tclass),
          MEMBER_SIZEOF(struct tc_flower_key, ipv6.rewrite_tclass)
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
 * struct ufid_tc_data - data entry for ufid-tc hashmaps.
 * @ufid_to_tc_node: Element in @ufid_to_tc hash table by ufid key.
 * @tc_to_ufid_node: Element in @tc_to_ufid hash table by tcf_id key.
 * @ufid: ufid assigned to the flow
 * @id: tc filter id (tcf_id)
 * @netdev: netdev associated with the tc rule
 */
struct ufid_tc_data {
    struct hmap_node ufid_to_tc_node;
    struct hmap_node tc_to_ufid_node;
    ovs_u128 ufid;
    struct tcf_id id;
    struct netdev *netdev;
};

static void
del_ufid_tc_mapping_unlocked(const ovs_u128 *ufid)
{
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_tc_data *data;

    HMAP_FOR_EACH_WITH_HASH (data, ufid_to_tc_node, ufid_hash, &ufid_to_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            break;
        }
    }

    if (!data) {
        return;
    }

    hmap_remove(&ufid_to_tc, &data->ufid_to_tc_node);
    hmap_remove(&tc_to_ufid, &data->tc_to_ufid_node);
    netdev_close(data->netdev);
    free(data);
}

/* Remove matching ufid entry from ufid-tc hashmaps. */
static void
del_ufid_tc_mapping(const ovs_u128 *ufid)
{
    ovs_mutex_lock(&ufid_lock);
    del_ufid_tc_mapping_unlocked(ufid);
    ovs_mutex_unlock(&ufid_lock);
}

/* Wrapper function to delete filter and ufid tc mapping */
static int
del_filter_and_ufid_mapping(struct tcf_id *id, const ovs_u128 *ufid)
{
    int err;

    err = tc_del_filter(id);
    if (!err) {
        del_ufid_tc_mapping(ufid);
    }
    return err;
}

/* Add ufid entry to ufid_to_tc hashmap. */
static void
add_ufid_tc_mapping(struct netdev *netdev, const ovs_u128 *ufid,
                    struct tcf_id *id)
{
    struct ufid_tc_data *new_data = xzalloc(sizeof *new_data);
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    size_t tc_hash;

    tc_hash = hash_int(hash_int(id->prio, id->handle), id->ifindex);
    tc_hash = hash_int(id->chain, tc_hash);

    new_data->ufid = *ufid;
    new_data->id = *id;
    new_data->netdev = netdev_ref(netdev);

    ovs_mutex_lock(&ufid_lock);
    hmap_insert(&ufid_to_tc, &new_data->ufid_to_tc_node, ufid_hash);
    hmap_insert(&tc_to_ufid, &new_data->tc_to_ufid_node, tc_hash);
    ovs_mutex_unlock(&ufid_lock);
}

/* Get tc id from ufid_to_tc hashmap.
 *
 * Returns 0 if successful and fills id.
 * Otherwise returns the error.
 */
static int
get_ufid_tc_mapping(const ovs_u128 *ufid, struct tcf_id *id)
{
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_tc_data *data;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH (data, ufid_to_tc_node, ufid_hash, &ufid_to_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            *id = data->id;
            ovs_mutex_unlock(&ufid_lock);
            return 0;
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    return ENOENT;
}

/* Find ufid entry in ufid_to_tc hashmap using tcf_id id.
 * The result is saved in ufid.
 *
 * Returns true on success.
 */
static bool
find_ufid(struct netdev *netdev, struct tcf_id *id, ovs_u128 *ufid)
{
    struct ufid_tc_data *data;
    size_t tc_hash;

    tc_hash = hash_int(hash_int(id->prio, id->handle), id->ifindex);
    tc_hash = hash_int(id->chain, tc_hash);

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH (data, tc_to_ufid_node, tc_hash,  &tc_to_ufid) {
        if (netdev == data->netdev && is_tcf_id_eq(&data->id, id)) {
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
    static uint16_t last_prio = TC_RESERVED_PRIORITY_MAX;
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
    HMAP_FOR_EACH_WITH_HASH (data, node, hash, &prios) {
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

static int
get_chains_from_netdev(struct netdev *netdev, struct tcf_id *id,
                       struct hmap *map)
{
    struct netdev_flow_dump *dump;
    struct chain_node *chain_node;
    struct ofpbuf rbuffer, reply;
    uint32_t chain;
    size_t hash;
    int err;

    dump = xzalloc(sizeof *dump);
    dump->nl_dump = xzalloc(sizeof *dump->nl_dump);
    dump->netdev = netdev_ref(netdev);

    ofpbuf_init(&rbuffer, NL_DUMP_BUFSIZE);
    tc_dump_tc_chain_start(id, dump->nl_dump);

    while (nl_dump_next(dump->nl_dump, &reply, &rbuffer)) {
        if (parse_netlink_to_tc_chain(&reply, &chain)) {
            continue;
        }

        chain_node = xzalloc(sizeof *chain_node);
        chain_node->chain = chain;
        hash = hash_int(chain, 0);
        hmap_insert(map, &chain_node->node, hash);
    }

    err = nl_dump_done(dump->nl_dump);
    ofpbuf_uninit(&rbuffer);
    netdev_close(netdev);
    free(dump->nl_dump);
    free(dump);

    return err;
}

static int
delete_chains_from_netdev(struct netdev *netdev, struct tcf_id *id)
{
    struct chain_node *chain_node;
    struct hmap map;
    int error;

    hmap_init(&map);
    error = get_chains_from_netdev(netdev, id, &map);

    if (!error) {
        /* Flush rules explicitly needed when we work with ingress_block,
         * so we will not fail with reattaching block to bond iface, for ex.
         */
        HMAP_FOR_EACH_POP (chain_node, node, &map) {
            id->chain = chain_node->chain;
            tc_del_filter(id);
            free(chain_node);
        }
    }

    hmap_destroy(&map);
    return error;
}

static int
netdev_tc_flow_flush(struct netdev *netdev)
{
    struct ufid_tc_data *data, *next;
    int err;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_SAFE (data, next, tc_to_ufid_node, &tc_to_ufid) {
        if (data->netdev != netdev) {
            continue;
        }

        err = tc_del_filter(&data->id);
        if (!err) {
            del_ufid_tc_mapping_unlocked(&data->ufid);
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    return 0;
}

static int
netdev_tc_flow_dump_create(struct netdev *netdev,
                           struct netdev_flow_dump **dump_out,
                           bool terse)
{
    enum tc_qdisc_hook hook = get_tc_qdisc_hook(netdev);
    struct netdev_flow_dump *dump;
    uint32_t block_id = 0;
    struct tcf_id id;
    int prio = 0;
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
    dump->terse = terse;

    id = tc_make_tcf_id(ifindex, block_id, prio, hook);
    tc_dump_flower_start(&id, dump->nl_dump, terse);

    *dump_out = dump;

    return 0;
}

static int
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

static void parse_tc_flower_geneve_opts(struct tc_action *action,
                                        struct ofpbuf *buf)
{
    int tun_opt_len = action->encap.data.present.len;
    size_t geneve_off;
    int idx = 0;

    if (!tun_opt_len) {
        return;
    }

    geneve_off = nl_msg_start_nested(buf, OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS);
    while (tun_opt_len) {
        struct geneve_opt *opt;

        opt = &action->encap.data.opts.gnv[idx];
        nl_msg_put(buf, opt, sizeof(struct geneve_opt) + opt->length * 4);
        idx += sizeof(struct geneve_opt) / 4 + opt->length;
        tun_opt_len -= sizeof(struct geneve_opt) + opt->length * 4;
    }
    nl_msg_end_nested(buf, geneve_off);
}

static void
flower_tun_opt_to_match(struct match *match, struct tc_flower *flower)
{
    struct geneve_opt *opt, *opt_mask;
    int len, cnt = 0;

    memcpy(match->flow.tunnel.metadata.opts.gnv,
           flower->key.tunnel.metadata.opts.gnv,
           flower->key.tunnel.metadata.present.len);
    match->flow.tunnel.metadata.present.len =
           flower->key.tunnel.metadata.present.len;
    match->flow.tunnel.flags |= FLOW_TNL_F_UDPIF;
    memcpy(match->wc.masks.tunnel.metadata.opts.gnv,
           flower->mask.tunnel.metadata.opts.gnv,
           flower->mask.tunnel.metadata.present.len);

    len = flower->key.tunnel.metadata.present.len;
    while (len) {
        opt = &match->flow.tunnel.metadata.opts.gnv[cnt];
        opt_mask = &match->wc.masks.tunnel.metadata.opts.gnv[cnt];

        opt_mask->length = 0x1f;

        cnt += sizeof(struct geneve_opt) / 4 + opt->length;
        len -= sizeof(struct geneve_opt) + opt->length * 4;
    }

    match->wc.masks.tunnel.metadata.present.len =
           flower->mask.tunnel.metadata.present.len;
    match->wc.masks.tunnel.flags |= FLOW_TNL_F_UDPIF;
}

static void
parse_tc_flower_to_stats(struct tc_flower *flower,
                         struct dpif_flow_stats *stats)
{
    if (!stats) {
        return;
    }

    memset(stats, 0, sizeof *stats);
    stats->n_packets = get_32aligned_u64(&flower->stats.n_packets);
    stats->n_bytes = get_32aligned_u64(&flower->stats.n_bytes);
    stats->used = flower->lastused;
}

static void
parse_tc_flower_to_attrs(struct tc_flower *flower,
                         struct dpif_flow_attrs *attrs)
{
    attrs->offloaded = (flower->offloaded_state == TC_OFFLOADED_STATE_IN_HW ||
                        flower->offloaded_state ==
                        TC_OFFLOADED_STATE_UNDEFINED);
    attrs->dp_layer = "tc";
    attrs->dp_extra_info = NULL;
}

static int
parse_tc_flower_terse_to_match(struct tc_flower *flower,
                               struct match *match,
                               struct dpif_flow_stats *stats,
                               struct dpif_flow_attrs *attrs)
{
    match_init_catchall(match);

    parse_tc_flower_to_stats(flower, stats);
    parse_tc_flower_to_attrs(flower, attrs);

    return 0;
}

static int
parse_tc_flower_to_match(struct tc_flower *flower,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         struct dpif_flow_attrs *attrs,
                         struct ofpbuf *buf,
                         bool terse)
{
    size_t act_off;
    struct tc_flower_key *key = &flower->key;
    struct tc_flower_key *mask = &flower->mask;
    odp_port_t outport = 0;
    struct tc_action *action;
    int i;

    if (terse) {
        return parse_tc_flower_terse_to_match(flower, match, stats, attrs);
    }

    ofpbuf_clear(buf);

    match_init_catchall(match);
    match_set_dl_src_masked(match, key->src_mac, mask->src_mac);
    match_set_dl_dst_masked(match, key->dst_mac, mask->dst_mac);

    if (eth_type_vlan(key->eth_type)) {
        match->flow.vlans[0].tpid = key->eth_type;
        match->wc.masks.vlans[0].tpid = OVS_BE16_MAX;
        match_set_dl_vlan(match, htons(key->vlan_id[0]), 0);
        match_set_dl_vlan_pcp(match, key->vlan_prio[0], 0);

        if (eth_type_vlan(key->encap_eth_type[0])) {
            match_set_dl_vlan(match, htons(key->vlan_id[1]), 1);
            match_set_dl_vlan_pcp(match, key->vlan_prio[1], 1);
            match_set_dl_type(match, key->encap_eth_type[1]);
            match->flow.vlans[1].tpid = key->encap_eth_type[0];
            match->wc.masks.vlans[1].tpid = OVS_BE16_MAX;
        } else {
            match_set_dl_type(match, key->encap_eth_type[0]);
        }
        flow_fix_vlan_tpid(&match->flow);
    } else if (eth_type_mpls(key->eth_type)) {
        match->flow.mpls_lse[0] = key->mpls_lse & mask->mpls_lse;
        match->wc.masks.mpls_lse[0] = mask->mpls_lse;
        match_set_dl_type(match, key->encap_eth_type[0]);
    } else if (key->eth_type == htons(ETH_TYPE_ARP)) {
        match_set_arp_sha_masked(match, key->arp.sha, mask->arp.sha);
        match_set_arp_tha_masked(match, key->arp.tha, mask->arp.tha);
        match_set_arp_spa_masked(match, key->arp.spa, mask->arp.spa);
        match_set_arp_tpa_masked(match, key->arp.tpa, mask->arp.tpa);
        match_set_arp_opcode_masked(match, key->arp.opcode,
                                    mask->arp.opcode);
        match_set_dl_type(match, key->eth_type);
    } else {
        match_set_dl_type(match, key->eth_type);
    }

    if (is_ip_any(&match->flow)) {
        if (key->ip_proto) {
            match_set_nw_proto(match, key->ip_proto);
        }

        match_set_nw_tos_masked(match, key->ip_tos, mask->ip_tos);
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
        } else if (key->ip_proto == IPPROTO_ICMP ||
                   key->ip_proto == IPPROTO_ICMPV6) {
            match_set_tp_dst_masked(match, htons(key->icmp_code),
                                    htons(mask->icmp_code));
            match_set_tp_src_masked(match, htons(key->icmp_type),
                                    htons(mask->icmp_type));
        }

        if (mask->ct_state) {
            uint8_t ct_statev = 0, ct_statem = 0;

            if (mask->ct_state & TCA_FLOWER_KEY_CT_FLAGS_NEW) {
                if (key->ct_state & TCA_FLOWER_KEY_CT_FLAGS_NEW) {
                    ct_statev |= OVS_CS_F_NEW;
                }
                ct_statem |= OVS_CS_F_NEW;
            }

            if (mask->ct_state & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED) {
                if (key->ct_state & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED) {
                    ct_statev |= OVS_CS_F_ESTABLISHED;
                }
                ct_statem |= OVS_CS_F_ESTABLISHED;
            }

            if (mask->ct_state & TCA_FLOWER_KEY_CT_FLAGS_TRACKED) {
                if (key->ct_state & TCA_FLOWER_KEY_CT_FLAGS_TRACKED) {
                    ct_statev |= OVS_CS_F_TRACKED;
                }
                ct_statem |= OVS_CS_F_TRACKED;
            }

            if (mask->ct_state & TCA_FLOWER_KEY_CT_FLAGS_REPLY) {
                if (key->ct_state & TCA_FLOWER_KEY_CT_FLAGS_REPLY) {
                    ct_statev |= OVS_CS_F_REPLY_DIR;
                }
                ct_statem |= OVS_CS_F_REPLY_DIR;
            }

            if (mask->ct_state & TCA_FLOWER_KEY_CT_FLAGS_INVALID) {
                if (key->ct_state & TCA_FLOWER_KEY_CT_FLAGS_INVALID) {
                    ct_statev |= OVS_CS_F_INVALID;
                }
                ct_statem |= OVS_CS_F_INVALID;
            }

            if (mask->ct_state & TCA_FLOWER_KEY_CT_FLAGS_RELATED) {
                if (key->ct_state & TCA_FLOWER_KEY_CT_FLAGS_RELATED) {
                    ct_statev |= OVS_CS_F_RELATED;
                }
                ct_statem |= OVS_CS_F_RELATED;
            }

            match_set_ct_state_masked(match, ct_statev, ct_statem);
        }

        match_set_ct_zone_masked(match, key->ct_zone, mask->ct_zone);
        match_set_ct_mark_masked(match, key->ct_mark, mask->ct_mark);
        match_set_ct_label_masked(match, key->ct_label, mask->ct_label);
    }

    if (flower->tunnel) {
        if (flower->mask.tunnel.id) {
            match_set_tun_id(match, flower->key.tunnel.id);
            match->flow.tunnel.flags |= FLOW_TNL_F_KEY;
        }
        if (flower->mask.tunnel.ipv4.ipv4_dst ||
            flower->mask.tunnel.ipv4.ipv4_src) {
            match_set_tun_dst_masked(match,
                                     flower->key.tunnel.ipv4.ipv4_dst,
                                     flower->mask.tunnel.ipv4.ipv4_dst);
            match_set_tun_src_masked(match,
                                     flower->key.tunnel.ipv4.ipv4_src,
                                     flower->mask.tunnel.ipv4.ipv4_src);
        } else if (ipv6_addr_is_set(&flower->mask.tunnel.ipv6.ipv6_dst) ||
                   ipv6_addr_is_set(&flower->mask.tunnel.ipv6.ipv6_src)) {
            match_set_tun_ipv6_dst_masked(match,
                                          &flower->key.tunnel.ipv6.ipv6_dst,
                                          &flower->mask.tunnel.ipv6.ipv6_dst);
            match_set_tun_ipv6_src_masked(match,
                                          &flower->key.tunnel.ipv6.ipv6_src,
                                          &flower->mask.tunnel.ipv6.ipv6_src);
        }
        if (flower->key.tunnel.tos) {
            match_set_tun_tos_masked(match, flower->key.tunnel.tos,
                                     flower->mask.tunnel.tos);
        }
        if (flower->key.tunnel.ttl) {
            match_set_tun_ttl_masked(match, flower->key.tunnel.ttl,
                                     flower->mask.tunnel.ttl);
        }
        if (flower->key.tunnel.tp_dst) {
            match_set_tun_tp_dst(match, flower->key.tunnel.tp_dst);
        }
        if (flower->key.tunnel.metadata.present.len) {
            flower_tun_opt_to_match(match, flower);
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
                push->vlan_tpid = action->vlan.vlan_push_tpid;
                push->vlan_tci = htons(action->vlan.vlan_push_id
                                       | (action->vlan.vlan_push_prio << 13)
                                       | VLAN_CFI);
            }
            break;
            case TC_ACT_MPLS_POP: {
                nl_msg_put_be16(buf, OVS_ACTION_ATTR_POP_MPLS,
                                action->mpls.proto);
            }
            break;
            case TC_ACT_MPLS_PUSH: {
                struct ovs_action_push_mpls *push;
                ovs_be32 mpls_lse = 0;

                flow_set_mpls_lse_label(&mpls_lse, action->mpls.label);
                flow_set_mpls_lse_tc(&mpls_lse, action->mpls.tc);
                flow_set_mpls_lse_ttl(&mpls_lse, action->mpls.ttl);
                flow_set_mpls_lse_bos(&mpls_lse, action->mpls.bos);

                push = nl_msg_put_unspec_zero(buf, OVS_ACTION_ATTR_PUSH_MPLS,
                                              sizeof *push);
                push->mpls_ethertype = action->mpls.proto;
                push->mpls_lse = mpls_lse;
            }
            break;
            case TC_ACT_MPLS_SET: {
                size_t set_offset = nl_msg_start_nested(buf,
                                                        OVS_ACTION_ATTR_SET);
                struct ovs_key_mpls *set_mpls;
                ovs_be32 mpls_lse = 0;

                flow_set_mpls_lse_label(&mpls_lse, action->mpls.label);
                flow_set_mpls_lse_tc(&mpls_lse, action->mpls.tc);
                flow_set_mpls_lse_ttl(&mpls_lse, action->mpls.ttl);
                flow_set_mpls_lse_bos(&mpls_lse, action->mpls.bos);

                set_mpls = nl_msg_put_unspec_zero(buf, OVS_KEY_ATTR_MPLS,
                                                  sizeof *set_mpls);
                set_mpls->mpls_lse = mpls_lse;
                nl_msg_end_nested(buf, set_offset);
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

                if (action->encap.id_present) {
                    nl_msg_put_be64(buf, OVS_TUNNEL_KEY_ATTR_ID, action->encap.id);
                }
                if (action->encap.ipv4.ipv4_src) {
                    nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_SRC,
                                    action->encap.ipv4.ipv4_src);
                }
                if (action->encap.ipv4.ipv4_dst) {
                    nl_msg_put_be32(buf, OVS_TUNNEL_KEY_ATTR_IPV4_DST,
                                    action->encap.ipv4.ipv4_dst);
                }
                if (ipv6_addr_is_set(&action->encap.ipv6.ipv6_src)) {
                    nl_msg_put_in6_addr(buf, OVS_TUNNEL_KEY_ATTR_IPV6_SRC,
                                        &action->encap.ipv6.ipv6_src);
                }
                if (ipv6_addr_is_set(&action->encap.ipv6.ipv6_dst)) {
                    nl_msg_put_in6_addr(buf, OVS_TUNNEL_KEY_ATTR_IPV6_DST,
                                        &action->encap.ipv6.ipv6_dst);
                }
                if (action->encap.tos) {
                    nl_msg_put_u8(buf, OVS_TUNNEL_KEY_ATTR_TOS,
                                  action->encap.tos);
                }
                if (action->encap.ttl) {
                    nl_msg_put_u8(buf, OVS_TUNNEL_KEY_ATTR_TTL,
                                  action->encap.ttl);
                }
                if (action->encap.tp_dst) {
                    nl_msg_put_be16(buf, OVS_TUNNEL_KEY_ATTR_TP_DST,
                                    action->encap.tp_dst);
                }
                if (!action->encap.no_csum) {
                    nl_msg_put_u8(buf, OVS_TUNNEL_KEY_ATTR_CSUM,
                                  !action->encap.no_csum);
                }

                parse_tc_flower_geneve_opts(action, buf);
                nl_msg_end_nested(buf, tunnel_offset);
                nl_msg_end_nested(buf, set_offset);
            }
            break;
            case TC_ACT_OUTPUT: {
                if (action->out.ifindex_out) {
                    outport =
                        netdev_ifindex_to_odp_port(action->out.ifindex_out);
                    if (!outport) {
                        return ENOENT;
                    }
                }
                nl_msg_put_u32(buf, OVS_ACTION_ATTR_OUTPUT, odp_to_u32(outport));
            }
            break;
            case TC_ACT_CT: {
                size_t ct_offset;

                if (action->ct.clear) {
                    nl_msg_put_flag(buf, OVS_ACTION_ATTR_CT_CLEAR);
                    break;
                }

                ct_offset = nl_msg_start_nested(buf, OVS_ACTION_ATTR_CT);

                if (action->ct.commit) {
                    nl_msg_put_flag(buf, OVS_CT_ATTR_COMMIT);
                }

                if (action->ct.zone) {
                    nl_msg_put_u16(buf, OVS_CT_ATTR_ZONE, action->ct.zone);
                }

                if (action->ct.mark_mask) {
                    uint32_t mark_and_mask[2] = { action->ct.mark,
                                                  action->ct.mark_mask };
                    nl_msg_put_unspec(buf, OVS_CT_ATTR_MARK, &mark_and_mask,
                                      sizeof mark_and_mask);
                }

                if (!ovs_u128_is_zero(action->ct.label_mask)) {
                    struct {
                        ovs_u128 key;
                        ovs_u128 mask;
                    } *ct_label;

                    ct_label = nl_msg_put_unspec_uninit(buf,
                                                        OVS_CT_ATTR_LABELS,
                                                        sizeof *ct_label);
                    ct_label->key = action->ct.label;
                    ct_label->mask = action->ct.label_mask;
                }

                if (action->ct.nat_type) {
                    size_t nat_offset = nl_msg_start_nested(buf,
                                                            OVS_CT_ATTR_NAT);

                    if (action->ct.nat_type == TC_NAT_SRC) {
                        nl_msg_put_flag(buf, OVS_NAT_ATTR_SRC);
                    } else if (action->ct.nat_type == TC_NAT_DST) {
                        nl_msg_put_flag(buf, OVS_NAT_ATTR_DST);
                    }

                    if (action->ct.range.ip_family == AF_INET) {
                        nl_msg_put_be32(buf, OVS_NAT_ATTR_IP_MIN,
                                        action->ct.range.ipv4.min);
                        nl_msg_put_be32(buf, OVS_NAT_ATTR_IP_MAX,
                                        action->ct.range.ipv4.max);
                    } else if (action->ct.range.ip_family == AF_INET6) {
                        nl_msg_put_in6_addr(buf, OVS_NAT_ATTR_IP_MIN,
                                            &action->ct.range.ipv6.min);
                        nl_msg_put_in6_addr(buf, OVS_NAT_ATTR_IP_MAX,
                                            &action->ct.range.ipv6.max);
                    }

                    if (action->ct.range.port.min) {
                        nl_msg_put_u16(buf, OVS_NAT_ATTR_PROTO_MIN,
                                       ntohs(action->ct.range.port.min));
                        if (action->ct.range.port.max) {
                            nl_msg_put_u16(buf, OVS_NAT_ATTR_PROTO_MAX,
                                           ntohs(action->ct.range.port.max));
                        }
                    }

                    nl_msg_end_nested(buf, nat_offset);
                }

                nl_msg_end_nested(buf, ct_offset);
            }
            break;
            case TC_ACT_GOTO: {
                nl_msg_put_u32(buf, OVS_ACTION_ATTR_RECIRC, action->chain);
            }
            break;
            }
        }
    }
    nl_msg_end_nested(buf, act_off);

    *actions = ofpbuf_at_assert(buf, act_off, sizeof(struct nlattr));

    parse_tc_flower_to_stats(flower, stats);
    parse_tc_flower_to_attrs(flower, attrs);

    return 0;
}

static bool
netdev_tc_flow_dump_next(struct netdev_flow_dump *dump,
                         struct match *match,
                         struct nlattr **actions,
                         struct dpif_flow_stats *stats,
                         struct dpif_flow_attrs *attrs,
                         ovs_u128 *ufid,
                         struct ofpbuf *rbuffer,
                         struct ofpbuf *wbuffer)
{
    struct netdev *netdev = dump->netdev;
    struct ofpbuf nl_flow;
    struct tcf_id id;

    id = tc_make_tcf_id(netdev_get_ifindex(netdev),
                        get_block_id_from_netdev(netdev),
                        0, /* prio */
                        get_tc_qdisc_hook(netdev));

    while (nl_dump_next(dump->nl_dump, &nl_flow, rbuffer)) {
        struct tc_flower flower;

        if (parse_netlink_to_tc_flower(&nl_flow, &id, &flower, dump->terse)) {
            continue;
        }

        if (parse_tc_flower_to_match(&flower, match, actions, stats, attrs,
                                     wbuffer, dump->terse)) {
            continue;
        }

        if (flower.act_cookie.len) {
            *ufid = *((ovs_u128 *) flower.act_cookie.data);
        } else if (!find_ufid(netdev, &id, ufid)) {
            continue;
        }

        match->wc.masks.in_port.odp_port = u32_to_odp(UINT32_MAX);
        match->flow.in_port.odp_port = dump->port;
        match_set_recirc_id(match, id.chain);

        return true;
    }

    return false;
}

static int
parse_mpls_set_action(struct tc_flower *flower, struct tc_action *action,
                      const struct nlattr *set)
{
        const struct ovs_key_mpls *mpls_set = nl_attr_get(set);

        action->mpls.label = mpls_lse_to_label(mpls_set->mpls_lse);
        action->mpls.tc = mpls_lse_to_tc(mpls_set->mpls_lse);
        action->mpls.ttl = mpls_lse_to_ttl(mpls_set->mpls_lse);
        action->mpls.bos = mpls_lse_to_bos(mpls_set->mpls_lse);
        action->type = TC_ACT_MPLS_SET;
        flower->action_count++;

        return 0;
}

static int
parse_put_flow_nat_action(struct tc_action *action,
                          const struct nlattr *nat,
                          size_t nat_len)
{
    const struct nlattr *nat_attr;
    size_t nat_left;

    action->ct.nat_type = TC_NAT_RESTORE;
    NL_ATTR_FOR_EACH_UNSAFE (nat_attr, nat_left, nat, nat_len) {
        switch (nl_attr_type(nat_attr)) {
            case OVS_NAT_ATTR_SRC: {
                action->ct.nat_type = TC_NAT_SRC;
            };
            break;
            case OVS_NAT_ATTR_DST: {
                action->ct.nat_type = TC_NAT_DST;
            };
            break;
            case OVS_NAT_ATTR_IP_MIN: {
                if (nl_attr_get_size(nat_attr) == sizeof(ovs_be32)) {
                    ovs_be32 addr = nl_attr_get_be32(nat_attr);

                    action->ct.range.ipv4.min = addr;
                    action->ct.range.ip_family = AF_INET;
                } else {
                    struct in6_addr addr = nl_attr_get_in6_addr(nat_attr);

                    action->ct.range.ipv6.min = addr;
                    action->ct.range.ip_family = AF_INET6;
                }
            };
            break;
            case OVS_NAT_ATTR_IP_MAX: {
                if (nl_attr_get_size(nat_attr) == sizeof(ovs_be32)) {
                    ovs_be32 addr = nl_attr_get_be32(nat_attr);

                    action->ct.range.ipv4.max = addr;
                    action->ct.range.ip_family = AF_INET;
                } else {
                    struct in6_addr addr = nl_attr_get_in6_addr(nat_attr);

                    action->ct.range.ipv6.max = addr;
                    action->ct.range.ip_family = AF_INET6;
                }
            };
            break;
            case OVS_NAT_ATTR_PROTO_MIN: {
                action->ct.range.port.min = htons(nl_attr_get_u16(nat_attr));
            };
            break;
            case OVS_NAT_ATTR_PROTO_MAX: {
                action->ct.range.port.max = htons(nl_attr_get_u16(nat_attr));
            };
            break;
        }
    }
    return 0;
}

static int
parse_put_flow_ct_action(struct tc_flower *flower,
                         struct tc_action *action,
                         const struct nlattr *ct,
                         size_t ct_len)
{
        const struct nlattr *ct_attr;
        size_t ct_left;
        int err;

        NL_ATTR_FOR_EACH_UNSAFE (ct_attr, ct_left, ct, ct_len) {
            switch (nl_attr_type(ct_attr)) {
                case OVS_CT_ATTR_COMMIT: {
                        action->ct.commit = true;
                }
                break;
                case OVS_CT_ATTR_ZONE: {
                    action->ct.zone = nl_attr_get_u16(ct_attr);
                }
                break;
                case OVS_CT_ATTR_NAT: {
                    const struct nlattr *nat = nl_attr_get(ct_attr);
                    const size_t nat_len = nl_attr_get_size(ct_attr);

                    err = parse_put_flow_nat_action(action, nat, nat_len);
                    if (err) {
                        return err;
                    }
                }
                break;
                case OVS_CT_ATTR_MARK: {
                    const struct {
                        uint32_t key;
                        uint32_t mask;
                    } *ct_mark;

                    ct_mark = nl_attr_get_unspec(ct_attr, sizeof *ct_mark);
                    action->ct.mark = ct_mark->key;
                    action->ct.mark_mask = ct_mark->mask;
                }
                break;
                case OVS_CT_ATTR_LABELS: {
                    const struct {
                        ovs_u128 key;
                        ovs_u128 mask;
                    } *ct_label;

                    ct_label = nl_attr_get_unspec(ct_attr, sizeof *ct_label);
                    action->ct.label = ct_label->key;
                    action->ct.label_mask = ct_label->mask;
                }
                break;
            }
        }

        action->type = TC_ACT_CT;
        flower->action_count++;
        return 0;
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

    if (nl_attr_type(set) == OVS_KEY_ATTR_MPLS) {
        return parse_mpls_set_action(flower, action, set);
    }

    if (nl_attr_type(set) != OVS_KEY_ATTR_TUNNEL) {
            return parse_put_flow_set_masked_action(flower, action, set,
                                                    set_len, false);
    }

    tunnel = nl_attr_get(set);
    tunnel_len = nl_attr_get_size(set);

    action->type = TC_ACT_ENCAP;
    action->encap.id_present = false;
    flower->action_count++;
    NL_ATTR_FOR_EACH_UNSAFE(tun_attr, tun_left, tunnel, tunnel_len) {
        switch (nl_attr_type(tun_attr)) {
        case OVS_TUNNEL_KEY_ATTR_ID: {
            action->encap.id = nl_attr_get_be64(tun_attr);
            action->encap.id_present = true;
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
        case OVS_TUNNEL_KEY_ATTR_TOS: {
            action->encap.tos = nl_attr_get_u8(tun_attr);
        }
        break;
        case OVS_TUNNEL_KEY_ATTR_TTL: {
            action->encap.ttl = nl_attr_get_u8(tun_attr);
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
        case OVS_TUNNEL_KEY_ATTR_GENEVE_OPTS: {
            memcpy(action->encap.data.opts.gnv, nl_attr_get(tun_attr),
                   nl_attr_get_size(tun_attr));
            action->encap.data.present.len = nl_attr_get_size(tun_attr);
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

    if (mask->packet_type && key->packet_type) {
        VLOG_DBG_RL(&rl, "offloading attribute packet_type isn't supported");
        return EOPNOTSUPP;
    }
    mask->packet_type = 0;

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

    for (int i = 1; i < FLOW_MAX_MPLS_LABELS; i++) {
        if (mask->mpls_lse[i]) {
            VLOG_DBG_RL(&rl, "offloading multiple mpls_lses isn't supported");
            return EOPNOTSUPP;
        }
    }

    if (key->dl_type == htons(ETH_TYPE_IP) &&
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
    } else if (key->dl_type == htons(OFP_DL_TYPE_NOT_ETH_TYPE)) {
        VLOG_DBG_RL(&rl,
                    "offloading of non-ethernet packets isn't supported");
        return EOPNOTSUPP;
    }

    if (!is_all_zeros(mask, sizeof *mask)) {
        VLOG_DBG_RL(&rl, "offloading isn't supported, unknown attribute");
        return EOPNOTSUPP;
    }

    return 0;
}

static void
flower_match_to_tun_opt(struct tc_flower *flower, const struct flow_tnl *tnl,
                        const struct flow_tnl *tnl_mask)
{
    struct geneve_opt *opt, *opt_mask;
    int len, cnt = 0;

    memcpy(flower->key.tunnel.metadata.opts.gnv, tnl->metadata.opts.gnv,
           tnl->metadata.present.len);
    flower->key.tunnel.metadata.present.len = tnl->metadata.present.len;

    memcpy(flower->mask.tunnel.metadata.opts.gnv, tnl_mask->metadata.opts.gnv,
           tnl->metadata.present.len);

    len = flower->key.tunnel.metadata.present.len;
    while (len) {
        opt = &flower->key.tunnel.metadata.opts.gnv[cnt];
        opt_mask = &flower->mask.tunnel.metadata.opts.gnv[cnt];

        opt_mask->length = opt->length;

        cnt += sizeof(struct geneve_opt) / 4 + opt->length;
        len -= sizeof(struct geneve_opt) + opt->length * 4;
    }

    flower->mask.tunnel.metadata.present.len = tnl->metadata.present.len;
}

static void
parse_match_ct_state_to_flower(struct tc_flower *flower, struct match *match)
{
    const struct flow *key = &match->flow;
    struct flow *mask = &match->wc.masks;

    if (!ct_state_support) {
        return;
    }

    if ((ct_state_support & mask->ct_state) == mask->ct_state) {
        if (mask->ct_state & OVS_CS_F_NEW) {
            if (key->ct_state & OVS_CS_F_NEW) {
                flower->key.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_NEW;
            }
            flower->mask.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_NEW;
            mask->ct_state &= ~OVS_CS_F_NEW;
        }

        if (mask->ct_state & OVS_CS_F_ESTABLISHED) {
            if (key->ct_state & OVS_CS_F_ESTABLISHED) {
                flower->key.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;
            }
            flower->mask.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED;
            mask->ct_state &= ~OVS_CS_F_ESTABLISHED;
        }

        if (mask->ct_state & OVS_CS_F_TRACKED) {
            if (key->ct_state & OVS_CS_F_TRACKED) {
                flower->key.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
            }
            flower->mask.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
            mask->ct_state &= ~OVS_CS_F_TRACKED;
        }

        if (mask->ct_state & OVS_CS_F_REPLY_DIR) {
            if (key->ct_state & OVS_CS_F_REPLY_DIR) {
                flower->key.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_REPLY;
            }
            flower->mask.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_REPLY;
            mask->ct_state &= ~OVS_CS_F_REPLY_DIR;
        }

        if (mask->ct_state & OVS_CS_F_INVALID) {
            if (key->ct_state & OVS_CS_F_INVALID) {
                flower->key.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_INVALID;
            }
            flower->mask.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_INVALID;
            mask->ct_state &= ~OVS_CS_F_INVALID;
        }

        if (mask->ct_state & OVS_CS_F_RELATED) {
            if (key->ct_state & OVS_CS_F_RELATED) {
                flower->key.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_RELATED;
            }
            flower->mask.ct_state |= TCA_FLOWER_KEY_CT_FLAGS_RELATED;
            mask->ct_state &= ~OVS_CS_F_RELATED;
        }

        if (flower->key.ct_state & TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED) {
            flower->key.ct_state &= ~(TCA_FLOWER_KEY_CT_FLAGS_NEW);
            flower->mask.ct_state &= ~(TCA_FLOWER_KEY_CT_FLAGS_NEW);
        }
    }

    if (mask->ct_zone) {
        flower->key.ct_zone = key->ct_zone;
        flower->mask.ct_zone = mask->ct_zone;
        mask->ct_zone = 0;
    }

    if (mask->ct_mark) {
        flower->key.ct_mark = key->ct_mark;
        flower->mask.ct_mark = mask->ct_mark;
        mask->ct_mark = 0;
    }

    if (!ovs_u128_is_zero(mask->ct_label)) {
        flower->key.ct_label = key->ct_label;
        flower->mask.ct_label = mask->ct_label;
        mask->ct_label = OVS_U128_ZERO;
    }
}

static int
netdev_tc_flow_put(struct netdev *netdev, struct match *match,
                   struct nlattr *actions, size_t actions_len,
                   const ovs_u128 *ufid, struct offload_info *info,
                   struct dpif_flow_stats *stats)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    enum tc_qdisc_hook hook = get_tc_qdisc_hook(netdev);
    struct tc_flower flower;
    const struct flow *key = &match->flow;
    struct flow *mask = &match->wc.masks;
    const struct flow_tnl *tnl = &match->flow.tunnel;
    const struct flow_tnl *tnl_mask = &mask->tunnel;
    struct tc_action *action;
    bool recirc_act = false;
    uint32_t block_id = 0;
    struct nlattr *nla;
    struct tcf_id id;
    uint32_t chain;
    size_t left;
    int prio = 0;
    int ifindex;
    int err;

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "flow_put: failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    memset(&flower, 0, sizeof flower);

    chain = key->recirc_id;
    mask->recirc_id = 0;

    if (flow_tnl_dst_is_set(&key->tunnel) ||
        flow_tnl_src_is_set(&key->tunnel)) {
        VLOG_DBG_RL(&rl,
                    "tunnel: id %#" PRIx64 " src " IP_FMT
                    " dst " IP_FMT " tp_src %d tp_dst %d",
                    ntohll(tnl->tun_id),
                    IP_ARGS(tnl->ip_src), IP_ARGS(tnl->ip_dst),
                    ntohs(tnl->tp_src), ntohs(tnl->tp_dst));
        flower.key.tunnel.id = tnl->tun_id;
        flower.key.tunnel.ipv4.ipv4_src = tnl->ip_src;
        flower.key.tunnel.ipv4.ipv4_dst = tnl->ip_dst;
        flower.key.tunnel.ipv6.ipv6_src = tnl->ipv6_src;
        flower.key.tunnel.ipv6.ipv6_dst = tnl->ipv6_dst;
        flower.key.tunnel.tos = tnl->ip_tos;
        flower.key.tunnel.ttl = tnl->ip_ttl;
        flower.key.tunnel.tp_src = tnl->tp_src;
        flower.key.tunnel.tp_dst = tnl->tp_dst;
        flower.mask.tunnel.ipv4.ipv4_src = tnl_mask->ip_src;
        flower.mask.tunnel.ipv4.ipv4_dst = tnl_mask->ip_dst;
        flower.mask.tunnel.ipv6.ipv6_src = tnl_mask->ipv6_src;
        flower.mask.tunnel.ipv6.ipv6_dst = tnl_mask->ipv6_dst;
        flower.mask.tunnel.tos = tnl_mask->ip_tos;
        flower.mask.tunnel.ttl = tnl_mask->ip_ttl;
        flower.mask.tunnel.id = (tnl->flags & FLOW_TNL_F_KEY) ? tnl_mask->tun_id : 0;
        flower_match_to_tun_opt(&flower, tnl, tnl_mask);
        flower.tunnel = true;
    }
    memset(&mask->tunnel, 0, sizeof mask->tunnel);

    flower.key.eth_type = key->dl_type;
    flower.mask.eth_type = mask->dl_type;
    if (mask->mpls_lse[0]) {
        flower.key.mpls_lse = key->mpls_lse[0];
        flower.mask.mpls_lse = mask->mpls_lse[0];
        flower.key.encap_eth_type[0] = flower.key.eth_type;
    }
    mask->mpls_lse[0] = 0;

    if (mask->vlans[0].tpid && eth_type_vlan(key->vlans[0].tpid)) {
        flower.key.encap_eth_type[0] = flower.key.eth_type;
        flower.mask.encap_eth_type[0] = flower.mask.eth_type;
        flower.key.eth_type = key->vlans[0].tpid;
        flower.mask.eth_type = mask->vlans[0].tpid;
    }
    if (mask->vlans[0].tci) {
        ovs_be16 vid_mask = mask->vlans[0].tci & htons(VLAN_VID_MASK);
        ovs_be16 pcp_mask = mask->vlans[0].tci & htons(VLAN_PCP_MASK);
        ovs_be16 cfi = mask->vlans[0].tci & htons(VLAN_CFI);

        if (cfi && key->vlans[0].tci & htons(VLAN_CFI)
            && (!vid_mask || vid_mask == htons(VLAN_VID_MASK))
            && (!pcp_mask || pcp_mask == htons(VLAN_PCP_MASK))
            && (vid_mask || pcp_mask)) {
            if (vid_mask) {
                flower.key.vlan_id[0] = vlan_tci_to_vid(key->vlans[0].tci);
                flower.mask.vlan_id[0] = vlan_tci_to_vid(mask->vlans[0].tci);
                VLOG_DBG_RL(&rl, "vlan_id[0]: %d\n", flower.key.vlan_id[0]);
            }
            if (pcp_mask) {
                flower.key.vlan_prio[0] = vlan_tci_to_pcp(key->vlans[0].tci);
                flower.mask.vlan_prio[0] = vlan_tci_to_pcp(mask->vlans[0].tci);
                VLOG_DBG_RL(&rl, "vlan_prio[0]: %d\n",
                            flower.key.vlan_prio[0]);
            }
        } else if (mask->vlans[0].tci == htons(0xffff) &&
                   ntohs(key->vlans[0].tci) == 0) {
            /* exact && no vlan */
        } else {
            /* partial mask */
            return EOPNOTSUPP;
        }
    }

    if (mask->vlans[1].tpid && eth_type_vlan(key->vlans[1].tpid)) {
        flower.key.encap_eth_type[1] = flower.key.encap_eth_type[0];
        flower.mask.encap_eth_type[1] = flower.mask.encap_eth_type[0];
        flower.key.encap_eth_type[0] = key->vlans[1].tpid;
        flower.mask.encap_eth_type[0] = mask->vlans[1].tpid;
    }
    if (mask->vlans[1].tci) {
        ovs_be16 vid_mask = mask->vlans[1].tci & htons(VLAN_VID_MASK);
        ovs_be16 pcp_mask = mask->vlans[1].tci & htons(VLAN_PCP_MASK);
        ovs_be16 cfi = mask->vlans[1].tci & htons(VLAN_CFI);

        if (cfi && key->vlans[1].tci & htons(VLAN_CFI)
            && (!vid_mask || vid_mask == htons(VLAN_VID_MASK))
            && (!pcp_mask || pcp_mask == htons(VLAN_PCP_MASK))
            && (vid_mask || pcp_mask)) {
            if (vid_mask) {
                flower.key.vlan_id[1] = vlan_tci_to_vid(key->vlans[1].tci);
                flower.mask.vlan_id[1] = vlan_tci_to_vid(mask->vlans[1].tci);
                VLOG_DBG_RL(&rl, "vlan_id[1]: %d", flower.key.vlan_id[1]);
            }
            if (pcp_mask) {
                flower.key.vlan_prio[1] = vlan_tci_to_pcp(key->vlans[1].tci);
                flower.mask.vlan_prio[1] = vlan_tci_to_pcp(mask->vlans[1].tci);
                VLOG_DBG_RL(&rl, "vlan_prio[1]: %d", flower.key.vlan_prio[1]);
            }
        } else if (mask->vlans[1].tci == htons(0xffff) &&
                   ntohs(key->vlans[1].tci) == 0) {
            /* exact && no vlan */
        } else {
            /* partial mask */
            return EOPNOTSUPP;
        }
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

    if (key->dl_type == htons(ETH_P_ARP)) {
            flower.key.arp.spa = key->nw_src;
            flower.key.arp.tpa = key->nw_dst;
            flower.key.arp.sha = key->arp_sha;
            flower.key.arp.tha = key->arp_tha;
            flower.key.arp.opcode = key->nw_proto;
            flower.mask.arp.spa = mask->nw_src;
            flower.mask.arp.tpa = mask->nw_dst;
            flower.mask.arp.sha = mask->arp_sha;
            flower.mask.arp.tha = mask->arp_tha;
            flower.mask.arp.opcode = mask->nw_proto;

            mask->nw_src = 0;
            mask->nw_dst = 0;
            mask->nw_proto = 0;
            memset(&mask->arp_sha, 0, sizeof mask->arp_sha);
            memset(&mask->arp_tha, 0, sizeof mask->arp_tha);
    }

    if (is_ip_any(key)) {
        flower.key.ip_proto = key->nw_proto;
        flower.mask.ip_proto = mask->nw_proto;
        mask->nw_proto = 0;
        flower.key.ip_tos = key->nw_tos;
        flower.mask.ip_tos = mask->nw_tos;
        mask->nw_tos = 0;
        flower.key.ip_ttl = key->nw_ttl;
        flower.mask.ip_ttl = mask->nw_ttl;
        mask->nw_ttl = 0;

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
        } else if (key->nw_proto == IPPROTO_ICMP ||
                   key->nw_proto == IPPROTO_ICMPV6) {
            flower.key.icmp_code = (uint8_t) ntohs(key->tp_dst);
            flower.mask.icmp_code = (uint8_t) ntohs (mask->tp_dst);
            flower.key.icmp_type = (uint8_t) ntohs(key->tp_src);
            flower.mask.icmp_type = (uint8_t) ntohs(mask->tp_src);
            mask->tp_src = 0;
            mask->tp_dst = 0;
        }

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

    parse_match_ct_state_to_flower(&flower, match);

    /* ignore exact match on skb_mark of 0. */
    if (mask->pkt_mark == UINT32_MAX && !key->pkt_mark) {
        mask->pkt_mark = 0;
    }

    err = test_key_and_mask(match);
    if (err) {
        return err;
    }

    NL_ATTR_FOR_EACH(nla, left, actions, actions_len) {
        if (flower.action_count >= TCA_ACT_MAX_NUM) {
            VLOG_DBG_RL(&rl, "Can only support %d actions", TCA_ACT_MAX_NUM);
            return EOPNOTSUPP;
        }
        action = &flower.actions[flower.action_count];
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            odp_port_t port = nl_attr_get_odp_port(nla);
            struct netdev *outdev = netdev_ports_get(
                                        port, netdev_get_dpif_type(netdev));

            if (!outdev) {
                VLOG_DBG_RL(&rl, "Can't find netdev for output port %d", port);
                return ENODEV;
            }
            action->out.ifindex_out = netdev_get_ifindex(outdev);
            action->out.ingress = is_internal_port(netdev_get_type(outdev));
            action->type = TC_ACT_OUTPUT;
            flower.action_count++;
            netdev_close(outdev);
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_PUSH_VLAN) {
            const struct ovs_action_push_vlan *vlan_push = nl_attr_get(nla);

            action->vlan.vlan_push_tpid = vlan_push->vlan_tpid;
            action->vlan.vlan_push_id = vlan_tci_to_vid(vlan_push->vlan_tci);
            action->vlan.vlan_push_prio = vlan_tci_to_pcp(vlan_push->vlan_tci);
            action->type = TC_ACT_VLAN_PUSH;
            flower.action_count++;
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_POP_VLAN) {
            action->type = TC_ACT_VLAN_POP;
            flower.action_count++;
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_PUSH_MPLS) {
            const struct ovs_action_push_mpls *mpls_push = nl_attr_get(nla);

            action->mpls.proto = mpls_push->mpls_ethertype;
            action->mpls.label = mpls_lse_to_label(mpls_push->mpls_lse);
            action->mpls.tc = mpls_lse_to_tc(mpls_push->mpls_lse);
            action->mpls.ttl = mpls_lse_to_ttl(mpls_push->mpls_lse);
            action->mpls.bos = mpls_lse_to_bos(mpls_push->mpls_lse);
            action->type = TC_ACT_MPLS_PUSH;
            flower.action_count++;
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_POP_MPLS) {
            action->mpls.proto = nl_attr_get_be16(nla);
            action->type = TC_ACT_MPLS_POP;
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
                action->encap.no_csum = !info->tunnel_csum_on;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED) {
            const struct nlattr *set = nl_attr_get(nla);
            const size_t set_len = nl_attr_get_size(nla);

            err = parse_put_flow_set_masked_action(&flower, action, set,
                                                   set_len, true);
            if (err) {
                return err;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_CT) {
            const struct nlattr *ct = nl_attr_get(nla);
            const size_t ct_len = nl_attr_get_size(nla);

            if (!ct_state_support) {
                return -EOPNOTSUPP;
            }

            err = parse_put_flow_ct_action(&flower, action, ct, ct_len);
            if (err) {
                return err;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_CT_CLEAR) {
            action->type = TC_ACT_CT;
            action->ct.clear = true;
            flower.action_count++;
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_RECIRC) {
            action->type = TC_ACT_GOTO;
            action->chain = nl_attr_get_u32(nla);
            flower.action_count++;
            recirc_act = true;
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_DROP) {
            action->type = TC_ACT_GOTO;
            action->chain = 0;  /* 0 is reserved and not used by recirc. */
            flower.action_count++;
        } else {
            VLOG_DBG_RL(&rl, "unsupported put action type: %d",
                        nl_attr_type(nla));
            return EOPNOTSUPP;
        }
    }

    if ((chain || recirc_act) && !info->recirc_id_shared_with_tc) {
        VLOG_ERR_RL(&error_rl, "flow_put: recirc_id sharing not supported");
        return EOPNOTSUPP;
    }

    if (get_ufid_tc_mapping(ufid, &id) == 0) {
        VLOG_DBG_RL(&rl, "updating old handle: %d prio: %d",
                    id.handle, id.prio);
        info->tc_modify_flow_deleted = !del_filter_and_ufid_mapping(&id, ufid);
    }

    prio = get_prio_for_tc_flower(&flower);
    if (prio == 0) {
        VLOG_ERR_RL(&rl, "couldn't get tc prio: %s", ovs_strerror(ENOSPC));
        return ENOSPC;
    }

    flower.act_cookie.data = ufid;
    flower.act_cookie.len = sizeof *ufid;

    block_id = get_block_id_from_netdev(netdev);
    id = tc_make_tcf_id_chain(ifindex, block_id, chain, prio, hook);
    err = tc_replace_flower(&id, &flower);
    if (!err) {
        if (stats) {
            memset(stats, 0, sizeof *stats);
        }
        add_ufid_tc_mapping(netdev, ufid, &id);
    }

    return err;
}

static int
netdev_tc_flow_get(struct netdev *netdev,
                   struct match *match,
                   struct nlattr **actions,
                   const ovs_u128 *ufid,
                   struct dpif_flow_stats *stats,
                   struct dpif_flow_attrs *attrs,
                   struct ofpbuf *buf)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);
    struct tc_flower flower;
    odp_port_t in_port;
    struct tcf_id id;
    int err;

    err = get_ufid_tc_mapping(ufid, &id);
    if (err) {
        return err;
    }

    VLOG_DBG_RL(&rl, "flow get (dev %s prio %d handle %d block_id %d)",
                netdev_get_name(netdev), id.prio, id.handle, id.block_id);

    err = tc_get_flower(&id, &flower);
    if (err) {
        VLOG_ERR_RL(&error_rl, "flow get failed (dev %s prio %d handle %d): %s",
                    netdev_get_name(netdev), id.prio, id.handle,
                    ovs_strerror(err));
        return err;
    }

    in_port = netdev_ifindex_to_odp_port(id.ifindex);
    parse_tc_flower_to_match(&flower, match, actions, stats, attrs, buf, false);

    match->wc.masks.in_port.odp_port = u32_to_odp(UINT32_MAX);
    match->flow.in_port.odp_port = in_port;
    match_set_recirc_id(match, id.chain);

    return 0;
}

static int
netdev_tc_flow_del(struct netdev *netdev OVS_UNUSED,
                   const ovs_u128 *ufid,
                   struct dpif_flow_stats *stats)
{
    struct tc_flower flower;
    struct tcf_id id;
    int error;

    error = get_ufid_tc_mapping(ufid, &id);
    if (error) {
        return error;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
        if (!tc_get_flower(&id, &flower)) {
            stats->n_packets = get_32aligned_u64(&flower.stats.n_packets);
            stats->n_bytes = get_32aligned_u64(&flower.stats.n_bytes);
            stats->used = flower.lastused;
        }
    }

    error = del_filter_and_ufid_mapping(&id, ufid);

    return error;
}

static int
netdev_tc_get_n_flows(struct netdev *netdev, uint64_t *n_flows)
{
    struct ufid_tc_data *data;
    uint64_t total = 0;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH (data, tc_to_ufid_node, &tc_to_ufid) {
        if (data->netdev == netdev) {
            total++;
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    *n_flows = total;
    return 0;
}

static void
probe_multi_mask_per_prio(int ifindex)
{
    struct tc_flower flower;
    struct tcf_id id1, id2;
    int block_id = 0;
    int prio = 1;
    int error;

    error = tc_add_del_qdisc(ifindex, true, block_id, TC_INGRESS);
    if (error) {
        return;
    }

    memset(&flower, 0, sizeof flower);

    flower.tc_policy = TC_POLICY_SKIP_HW;
    flower.key.eth_type = htons(ETH_P_IP);
    flower.mask.eth_type = OVS_BE16_MAX;
    memset(&flower.key.dst_mac, 0x11, sizeof flower.key.dst_mac);
    memset(&flower.mask.dst_mac, 0xff, sizeof flower.mask.dst_mac);

    id1 = tc_make_tcf_id(ifindex, block_id, prio, TC_INGRESS);
    error = tc_replace_flower(&id1, &flower);
    if (error) {
        goto out;
    }

    memset(&flower.key.src_mac, 0x11, sizeof flower.key.src_mac);
    memset(&flower.mask.src_mac, 0xff, sizeof flower.mask.src_mac);

    id2 = tc_make_tcf_id(ifindex, block_id, prio, TC_INGRESS);
    error = tc_replace_flower(&id2, &flower);
    tc_del_filter(&id1);

    if (error) {
        goto out;
    }

    tc_del_filter(&id2);

    multi_mask_per_prio = true;
    VLOG_INFO("probe tc: multiple masks on single tc prio is supported.");

out:
    tc_add_del_qdisc(ifindex, false, block_id, TC_INGRESS);
}


static int
probe_insert_ct_state_rule(int ifindex, uint16_t ct_state, struct tcf_id *id)
{
    int prio = TC_RESERVED_PRIORITY_MAX + 1;
    struct tc_flower flower;

    memset(&flower, 0, sizeof flower);
    flower.key.ct_state = ct_state;
    flower.mask.ct_state = ct_state;
    flower.tc_policy = TC_POLICY_SKIP_HW;
    flower.key.eth_type = htons(ETH_P_IP);
    flower.mask.eth_type = OVS_BE16_MAX;

    *id = tc_make_tcf_id(ifindex, 0, prio, TC_INGRESS);
    return tc_replace_flower(id, &flower);
}

static void
probe_ct_state_support(int ifindex)
{
    struct tc_flower flower;
    uint16_t ct_state;
    struct tcf_id id;
    int error;

    error = tc_add_del_qdisc(ifindex, true, 0, TC_INGRESS);
    if (error) {
        return;
    }

    /* Test for base ct_state match support */
    ct_state = TCA_FLOWER_KEY_CT_FLAGS_NEW | TCA_FLOWER_KEY_CT_FLAGS_TRACKED;
    error = probe_insert_ct_state_rule(ifindex, ct_state, &id);
    if (error) {
        goto out;
    }

    error = tc_get_flower(&id, &flower);
    if (error || flower.mask.ct_state != ct_state) {
        goto out_del;
    }

    tc_del_filter(&id);
    ct_state_support = OVS_CS_F_NEW |
                       OVS_CS_F_ESTABLISHED |
                       OVS_CS_F_TRACKED |
                       OVS_CS_F_RELATED;

    /* Test for reject, ct_state >= MAX */
    ct_state = ~0;
    error = probe_insert_ct_state_rule(ifindex, ct_state, &id);
    if (!error) {
        /* No reject, can't continue probing other flags */
        goto out_del;
    }

    tc_del_filter(&id);

    /* Test for ct_state INVALID support */
    memset(&flower, 0, sizeof flower);
    ct_state = TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
               TCA_FLOWER_KEY_CT_FLAGS_INVALID;
    error = probe_insert_ct_state_rule(ifindex, ct_state, &id);
    if (error) {
        goto out;
    }

    tc_del_filter(&id);
    ct_state_support |= OVS_CS_F_INVALID;

    /* Test for ct_state REPLY support */
    memset(&flower, 0, sizeof flower);
    ct_state = TCA_FLOWER_KEY_CT_FLAGS_TRACKED |
               TCA_FLOWER_KEY_CT_FLAGS_ESTABLISHED |
               TCA_FLOWER_KEY_CT_FLAGS_REPLY;
    error = probe_insert_ct_state_rule(ifindex, ct_state, &id);
    if (error) {
        goto out;
    }

    ct_state_support |= OVS_CS_F_REPLY_DIR;

out_del:
    tc_del_filter(&id);
out:
    tc_add_del_qdisc(ifindex, false, 0, TC_INGRESS);
    VLOG_INFO("probe tc: supported ovs ct_state bits: 0x%x", ct_state_support);
}

static void
probe_tc_block_support(int ifindex)
{
    struct tc_flower flower;
    uint32_t block_id = 1;
    struct tcf_id id;
    int prio = 0;
    int error;

    error = tc_add_del_qdisc(ifindex, true, block_id, TC_INGRESS);
    if (error) {
        return;
    }

    memset(&flower, 0, sizeof flower);

    flower.tc_policy = TC_POLICY_SKIP_HW;
    flower.key.eth_type = htons(ETH_P_IP);
    flower.mask.eth_type = OVS_BE16_MAX;
    memset(&flower.key.dst_mac, 0x11, sizeof flower.key.dst_mac);
    memset(&flower.mask.dst_mac, 0xff, sizeof flower.mask.dst_mac);

    id = tc_make_tcf_id(ifindex, block_id, prio, TC_INGRESS);
    error = tc_replace_flower(&id, &flower);

    tc_add_del_qdisc(ifindex, false, block_id, TC_INGRESS);

    if (!error) {
        block_support = true;
        VLOG_INFO("probe tc: block offload is supported.");
    }
}

static int
netdev_tc_init_flow_api(struct netdev *netdev)
{
    static struct ovsthread_once once = OVSTHREAD_ONCE_INITIALIZER;
    enum tc_qdisc_hook hook = get_tc_qdisc_hook(netdev);
    static bool get_chain_supported = true;
    uint32_t block_id = 0;
    struct tcf_id id;
    int ifindex;
    int error;

    if (netdev_vport_is_vport_class(netdev->netdev_class)
        && strcmp(netdev_get_dpif_type(netdev), "system")) {
        VLOG_DBG("%s: vport doesn't belong to the system datapath. Skipping.",
                 netdev_get_name(netdev));
        return EOPNOTSUPP;
    }

    ifindex = netdev_get_ifindex(netdev);
    if (ifindex < 0) {
        VLOG_INFO("init: failed to get ifindex for %s: %s",
                  netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    block_id = get_block_id_from_netdev(netdev);
    id = tc_make_tcf_id(ifindex, block_id, 0, hook);

    if (get_chain_supported) {
        if (delete_chains_from_netdev(netdev, &id)) {
            get_chain_supported = false;
        }
    }

    /* fallback here if delete chains fail */
    if (!get_chain_supported) {
        tc_del_filter(&id);
    }

    /* make sure there is no ingress/egress qdisc */
    tc_add_del_qdisc(ifindex, false, 0, hook);

    if (ovsthread_once_start(&once)) {
        probe_tc_block_support(ifindex);
        /* Need to re-fetch block id as it depends on feature availability. */
        block_id = get_block_id_from_netdev(netdev);

        probe_multi_mask_per_prio(ifindex);
        probe_ct_state_support(ifindex);
        ovsthread_once_done(&once);
    }

    error = tc_add_del_qdisc(ifindex, true, block_id, hook);

    if (error && error != EEXIST) {
        VLOG_INFO("failed adding ingress qdisc required for offloading: %s",
                  ovs_strerror(error));
        return error;
    }

    VLOG_INFO("added ingress qdisc to %s", netdev_get_name(netdev));

    return 0;
}

const struct netdev_flow_api netdev_offload_tc = {
   .type = "linux_tc",
   .flow_flush = netdev_tc_flow_flush,
   .flow_dump_create = netdev_tc_flow_dump_create,
   .flow_dump_destroy = netdev_tc_flow_dump_destroy,
   .flow_dump_next = netdev_tc_flow_dump_next,
   .flow_put = netdev_tc_flow_put,
   .flow_get = netdev_tc_flow_get,
   .flow_del = netdev_tc_flow_del,
   .flow_get_n_flows = netdev_tc_get_n_flows,
   .init_flow_api = netdev_tc_init_flow_api,
};
