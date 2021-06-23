/*
 * Copyright (c) 2014, 2015, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2019 Mellanox Technologies, Ltd.
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

#include <sys/types.h>
#include <netinet/ip6.h>
#include <rte_flow.h>

#include "cmap.h"
#include "dpif-netdev.h"
#include "netdev-offload-provider.h"
#include "netdev-provider.h"
#include "netdev-vport.h"
#include "odp-util.h"
#include "openvswitch/match.h"
#include "openvswitch/vlog.h"
#include "packets.h"
#include "uuid.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload_dpdk);
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

/* Thread-safety
 * =============
 *
 * Below API is NOT thread safe in following terms:
 *
 *  - The caller must be sure that none of these functions will be called
 *    simultaneously.  Even for different 'netdev's.
 *
 *  - The caller must be sure that 'netdev' will not be destructed/deallocated.
 *
 *  - The caller must be sure that 'netdev' configuration will not be changed.
 *    For example, simultaneous call of 'netdev_reconfigure()' for the same
 *    'netdev' is forbidden.
 *
 * For current implementation all above restrictions could be fulfilled by
 * taking the datapath 'port_mutex' in lib/dpif-netdev.c.  */

/*
 * A mapping from ufid to dpdk rte_flow.
 */
static struct cmap ufid_to_rte_flow = CMAP_INITIALIZER;

struct ufid_to_rte_flow_data {
    struct cmap_node node;
    ovs_u128 ufid;
    struct netdev *netdev;
    struct rte_flow *rte_flow;
    bool actions_offloaded;
    struct dpif_flow_stats stats;
    struct netdev *physdev;
};

/* Find rte_flow with @ufid. */
static struct ufid_to_rte_flow_data *
ufid_to_rte_flow_data_find(const ovs_u128 *ufid, bool warn)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH_WITH_HASH (data, node, hash, &ufid_to_rte_flow) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            return data;
        }
    }

    if (warn) {
        VLOG_WARN("ufid "UUID_FMT" is not associated with an rte flow",
                  UUID_ARGS((struct uuid *) ufid));
    }

    return NULL;
}

static inline struct ufid_to_rte_flow_data *
ufid_to_rte_flow_associate(const ovs_u128 *ufid, struct netdev *netdev,
                           struct netdev *physdev, struct rte_flow *rte_flow,
                           bool actions_offloaded)
{
    size_t hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_to_rte_flow_data *data = xzalloc(sizeof *data);
    struct ufid_to_rte_flow_data *data_prev;

    /*
     * We should not simply overwrite an existing rte flow.
     * We should have deleted it first before re-adding it.
     * Thus, if following assert triggers, something is wrong:
     * the rte_flow is not destroyed.
     */
    data_prev = ufid_to_rte_flow_data_find(ufid, false);
    if (data_prev) {
        ovs_assert(data_prev->rte_flow == NULL);
    }

    data->ufid = *ufid;
    data->netdev = netdev_ref(netdev);
    data->physdev = netdev != physdev ? netdev_ref(physdev) : physdev;
    data->rte_flow = rte_flow;
    data->actions_offloaded = actions_offloaded;

    cmap_insert(&ufid_to_rte_flow,
                CONST_CAST(struct cmap_node *, &data->node), hash);
    return data;
}

static inline void
ufid_to_rte_flow_disassociate(struct ufid_to_rte_flow_data *data)
{
    size_t hash = hash_bytes(&data->ufid, sizeof data->ufid, 0);

    cmap_remove(&ufid_to_rte_flow,
                CONST_CAST(struct cmap_node *, &data->node), hash);
    if (data->netdev != data->physdev) {
        netdev_close(data->netdev);
    }
    netdev_close(data->physdev);
    ovsrcu_postpone(free, data);
}

/*
 * To avoid individual xrealloc calls for each new element, a 'curent_max'
 * is used to keep track of current allocated number of elements. Starts
 * by 8 and doubles on each xrealloc call.
 */
struct flow_patterns {
    struct rte_flow_item *items;
    int cnt;
    int current_max;
    struct netdev *physdev;
    /* tnl_pmd_items is the opaque array of items returned by the PMD. */
    struct rte_flow_item *tnl_pmd_items;
    uint32_t tnl_pmd_items_cnt;
    struct ds s_tnl;
};

struct flow_actions {
    struct rte_flow_action *actions;
    int cnt;
    int current_max;
    struct netdev *tnl_netdev;
    /* tnl_pmd_actions is the opaque array of actions returned by the PMD. */
    struct rte_flow_action *tnl_pmd_actions;
    uint32_t tnl_pmd_actions_cnt;
    /* tnl_pmd_actions_pos is where the tunnel actions starts within the
     * 'actions' field.
     */
    int tnl_pmd_actions_pos;
    struct ds s_tnl;
};

static void
dump_flow_attr(struct ds *s, struct ds *s_extra,
               const struct rte_flow_attr *attr,
               struct flow_patterns *flow_patterns,
               struct flow_actions *flow_actions)
{
    if (flow_actions->tnl_pmd_actions_cnt) {
        ds_clone(s_extra, &flow_actions->s_tnl);
    } else if (flow_patterns->tnl_pmd_items_cnt) {
        ds_clone(s_extra, &flow_patterns->s_tnl);
    }
    ds_put_format(s, "%s%spriority %"PRIu32" group %"PRIu32" %s%s%s",
                  attr->ingress  ? "ingress " : "",
                  attr->egress   ? "egress " : "", attr->priority, attr->group,
                  attr->transfer ? "transfer " : "",
                  flow_actions->tnl_pmd_actions_cnt ? "tunnel_set 1 " : "",
                  flow_patterns->tnl_pmd_items_cnt ? "tunnel_match 1 " : "");
}

/* Adds one pattern item 'field' with the 'mask' to dynamic string 's' using
 * 'testpmd command'-like format. */
#define DUMP_PATTERN_ITEM(mask, field, fmt, spec_pri, mask_pri) \
    if (is_all_ones(&mask, sizeof mask)) { \
        ds_put_format(s, field " is " fmt " ", spec_pri); \
    } else if (!is_all_zeros(&mask, sizeof mask)) { \
        ds_put_format(s, field " spec " fmt " " field " mask " fmt " ", \
                      spec_pri, mask_pri); \
    }

static void
dump_flow_pattern(struct ds *s,
                  struct flow_patterns *flow_patterns,
                  int pattern_index)
{
    const struct rte_flow_item *item = &flow_patterns->items[pattern_index];

    if (item->type == RTE_FLOW_ITEM_TYPE_END) {
        ds_put_cstr(s, "end ");
    } else if (flow_patterns->tnl_pmd_items_cnt &&
               pattern_index < flow_patterns->tnl_pmd_items_cnt) {
        return;
    } else if (item->type == RTE_FLOW_ITEM_TYPE_ETH) {
        const struct rte_flow_item_eth *eth_spec = item->spec;
        const struct rte_flow_item_eth *eth_mask = item->mask;

        ds_put_cstr(s, "eth ");
        if (eth_spec) {
            if (!eth_mask) {
                eth_mask = &rte_flow_item_eth_mask;
            }
            DUMP_PATTERN_ITEM(eth_mask->src, "src", ETH_ADDR_FMT,
                              ETH_ADDR_BYTES_ARGS(eth_spec->src.addr_bytes),
                              ETH_ADDR_BYTES_ARGS(eth_mask->src.addr_bytes));
            DUMP_PATTERN_ITEM(eth_mask->dst, "dst", ETH_ADDR_FMT,
                              ETH_ADDR_BYTES_ARGS(eth_spec->dst.addr_bytes),
                              ETH_ADDR_BYTES_ARGS(eth_mask->dst.addr_bytes));
            DUMP_PATTERN_ITEM(eth_mask->type, "type", "0x%04"PRIx16,
                              ntohs(eth_spec->type),
                              ntohs(eth_mask->type));
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_VLAN) {
        const struct rte_flow_item_vlan *vlan_spec = item->spec;
        const struct rte_flow_item_vlan *vlan_mask = item->mask;

        ds_put_cstr(s, "vlan ");
        if (vlan_spec) {
            if (!vlan_mask) {
                vlan_mask = &rte_flow_item_vlan_mask;
            }
            DUMP_PATTERN_ITEM(vlan_mask->inner_type, "inner_type", "0x%"PRIx16,
                              ntohs(vlan_spec->inner_type),
                              ntohs(vlan_mask->inner_type));
            DUMP_PATTERN_ITEM(vlan_mask->tci, "tci", "0x%"PRIx16,
                              ntohs(vlan_spec->tci), ntohs(vlan_mask->tci));
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_IPV4) {
        const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
        const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

        ds_put_cstr(s, "ipv4 ");
        if (ipv4_spec) {
            if (!ipv4_mask) {
                ipv4_mask = &rte_flow_item_ipv4_mask;
            }
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.src_addr, "src", IP_FMT,
                              IP_ARGS(ipv4_spec->hdr.src_addr),
                              IP_ARGS(ipv4_mask->hdr.src_addr));
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.dst_addr, "dst", IP_FMT,
                              IP_ARGS(ipv4_spec->hdr.dst_addr),
                              IP_ARGS(ipv4_mask->hdr.dst_addr));
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.next_proto_id, "proto",
                              "0x%"PRIx8, ipv4_spec->hdr.next_proto_id,
                              ipv4_mask->hdr.next_proto_id);
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.type_of_service, "tos",
                              "0x%"PRIx8, ipv4_spec->hdr.type_of_service,
                              ipv4_mask->hdr.type_of_service);
            DUMP_PATTERN_ITEM(ipv4_mask->hdr.time_to_live, "ttl",
                              "0x%"PRIx8, ipv4_spec->hdr.time_to_live,
                              ipv4_mask->hdr.time_to_live);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_UDP) {
        const struct rte_flow_item_udp *udp_spec = item->spec;
        const struct rte_flow_item_udp *udp_mask = item->mask;

        ds_put_cstr(s, "udp ");
        if (udp_spec) {
            if (!udp_mask) {
                udp_mask = &rte_flow_item_udp_mask;
            }
            DUMP_PATTERN_ITEM(udp_mask->hdr.src_port, "src", "%"PRIu16,
                              ntohs(udp_spec->hdr.src_port),
                              ntohs(udp_mask->hdr.src_port));
            DUMP_PATTERN_ITEM(udp_mask->hdr.dst_port, "dst", "%"PRIu16,
                              ntohs(udp_spec->hdr.dst_port),
                              ntohs(udp_mask->hdr.dst_port));
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_SCTP) {
        const struct rte_flow_item_sctp *sctp_spec = item->spec;
        const struct rte_flow_item_sctp *sctp_mask = item->mask;

        ds_put_cstr(s, "sctp ");
        if (sctp_spec) {
            if (!sctp_mask) {
                sctp_mask = &rte_flow_item_sctp_mask;
            }
            DUMP_PATTERN_ITEM(sctp_mask->hdr.src_port, "src", "%"PRIu16,
                              ntohs(sctp_spec->hdr.src_port),
                              ntohs(sctp_mask->hdr.src_port));
            DUMP_PATTERN_ITEM(sctp_mask->hdr.dst_port, "dst", "%"PRIu16,
                              ntohs(sctp_spec->hdr.dst_port),
                              ntohs(sctp_mask->hdr.dst_port));
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_ICMP) {
        const struct rte_flow_item_icmp *icmp_spec = item->spec;
        const struct rte_flow_item_icmp *icmp_mask = item->mask;

        ds_put_cstr(s, "icmp ");
        if (icmp_spec) {
            if (!icmp_mask) {
                icmp_mask = &rte_flow_item_icmp_mask;
            }
            DUMP_PATTERN_ITEM(icmp_mask->hdr.icmp_type, "icmp_type", "%"PRIu8,
                              icmp_spec->hdr.icmp_type,
                              icmp_mask->hdr.icmp_type);
            DUMP_PATTERN_ITEM(icmp_mask->hdr.icmp_code, "icmp_code", "%"PRIu8,
                              icmp_spec->hdr.icmp_code,
                              icmp_mask->hdr.icmp_code);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_TCP) {
        const struct rte_flow_item_tcp *tcp_spec = item->spec;
        const struct rte_flow_item_tcp *tcp_mask = item->mask;

        ds_put_cstr(s, "tcp ");
        if (tcp_spec) {
            if (!tcp_mask) {
                tcp_mask = &rte_flow_item_tcp_mask;
            }
            DUMP_PATTERN_ITEM(tcp_mask->hdr.src_port, "src", "%"PRIu16,
                              ntohs(tcp_spec->hdr.src_port),
                              ntohs(tcp_mask->hdr.src_port));
            DUMP_PATTERN_ITEM(tcp_mask->hdr.dst_port, "dst", "%"PRIu16,
                              ntohs(tcp_spec->hdr.dst_port),
                              ntohs(tcp_mask->hdr.dst_port));
            DUMP_PATTERN_ITEM(tcp_mask->hdr.tcp_flags, "flags", "0x%"PRIx8,
                              tcp_spec->hdr.tcp_flags,
                              tcp_mask->hdr.tcp_flags);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_IPV6) {
        const struct rte_flow_item_ipv6 *ipv6_spec = item->spec;
        const struct rte_flow_item_ipv6 *ipv6_mask = item->mask;

        char addr_str[INET6_ADDRSTRLEN];
        char mask_str[INET6_ADDRSTRLEN];
        struct in6_addr addr, mask;

        ds_put_cstr(s, "ipv6 ");
        if (ipv6_spec) {
            if (!ipv6_mask) {
                ipv6_mask = &rte_flow_item_ipv6_mask;
            }
            memcpy(&addr, ipv6_spec->hdr.src_addr, sizeof addr);
            memcpy(&mask, ipv6_mask->hdr.src_addr, sizeof mask);
            ipv6_string_mapped(addr_str, &addr);
            ipv6_string_mapped(mask_str, &mask);
            DUMP_PATTERN_ITEM(mask, "src", "%s", addr_str, mask_str);

            memcpy(&addr, ipv6_spec->hdr.dst_addr, sizeof addr);
            memcpy(&mask, ipv6_mask->hdr.dst_addr, sizeof mask);
            ipv6_string_mapped(addr_str, &addr);
            ipv6_string_mapped(mask_str, &mask);
            DUMP_PATTERN_ITEM(mask, "dst", "%s", addr_str, mask_str);

            DUMP_PATTERN_ITEM(ipv6_mask->hdr.proto, "proto", "%"PRIu8,
                              ipv6_spec->hdr.proto, ipv6_mask->hdr.proto);
            DUMP_PATTERN_ITEM(ipv6_mask->hdr.vtc_flow, "tc", "0x%"PRIx32,
                              ntohl(ipv6_spec->hdr.vtc_flow),
                              ntohl(ipv6_mask->hdr.vtc_flow));
            DUMP_PATTERN_ITEM(ipv6_mask->hdr.hop_limits, "hop", "%"PRIu8,
                              ipv6_spec->hdr.hop_limits,
                              ipv6_mask->hdr.hop_limits);
        }
        ds_put_cstr(s, "/ ");
    } else if (item->type == RTE_FLOW_ITEM_TYPE_VXLAN) {
        const struct rte_flow_item_vxlan *vxlan_spec = item->spec;
        const struct rte_flow_item_vxlan *vxlan_mask = item->mask;

        ds_put_cstr(s, "vxlan ");
        if (vxlan_spec) {
            if (!vxlan_mask) {
                vxlan_mask = &rte_flow_item_vxlan_mask;
            }
            DUMP_PATTERN_ITEM(vxlan_mask->vni, "vni", "%"PRIu32,
                              ntohl(*(ovs_be32 *) vxlan_spec->vni) >> 8,
                              ntohl(*(ovs_be32 *) vxlan_mask->vni) >> 8);
        }
        ds_put_cstr(s, "/ ");
    } else {
        ds_put_format(s, "unknown rte flow pattern (%d)\n", item->type);
    }
}

static void
dump_vxlan_encap(struct ds *s, const struct rte_flow_item *items)
{
    const struct rte_flow_item_eth *eth = NULL;
    const struct rte_flow_item_ipv4 *ipv4 = NULL;
    const struct rte_flow_item_ipv6 *ipv6 = NULL;
    const struct rte_flow_item_udp *udp = NULL;
    const struct rte_flow_item_vxlan *vxlan = NULL;

    for (; items && items->type != RTE_FLOW_ITEM_TYPE_END; items++) {
        if (items->type == RTE_FLOW_ITEM_TYPE_ETH) {
            eth = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_IPV4) {
            ipv4 = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_IPV6) {
            ipv6 = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_UDP) {
            udp = items->spec;
        } else if (items->type == RTE_FLOW_ITEM_TYPE_VXLAN) {
            vxlan = items->spec;
        }
    }

    ds_put_format(s, "set vxlan ip-version %s ",
                  ipv4 ? "ipv4" : ipv6 ? "ipv6" : "ERR");
    if (vxlan) {
        ds_put_format(s, "vni %"PRIu32" ",
                      ntohl(*(ovs_be32 *) vxlan->vni) >> 8);
    }
    if (udp) {
        ds_put_format(s, "udp-src %"PRIu16" udp-dst %"PRIu16" ",
                      ntohs(udp->hdr.src_port), ntohs(udp->hdr.dst_port));
    }
    if (ipv4) {
        ds_put_format(s, "ip-src "IP_FMT" ip-dst "IP_FMT" ",
                      IP_ARGS(ipv4->hdr.src_addr),
                      IP_ARGS(ipv4->hdr.dst_addr));
    }
    if (ipv6) {
        struct in6_addr addr;

        ds_put_cstr(s, "ip-src ");
        memcpy(&addr, ipv6->hdr.src_addr, sizeof addr);
        ipv6_format_mapped(&addr, s);
        ds_put_cstr(s, " ip-dst ");
        memcpy(&addr, ipv6->hdr.dst_addr, sizeof addr);
        ipv6_format_mapped(&addr, s);
        ds_put_cstr(s, " ");
    }
    if (eth) {
        ds_put_format(s, "eth-src "ETH_ADDR_FMT" eth-dst "ETH_ADDR_FMT,
                      ETH_ADDR_BYTES_ARGS(eth->src.addr_bytes),
                      ETH_ADDR_BYTES_ARGS(eth->dst.addr_bytes));
    }
}

static void
dump_flow_action(struct ds *s, struct ds *s_extra,
                 struct flow_actions *flow_actions, int act_index)
{
    const struct rte_flow_action *actions = &flow_actions->actions[act_index];

    if (actions->type == RTE_FLOW_ACTION_TYPE_END) {
        ds_put_cstr(s, "end");
    } else if (flow_actions->tnl_pmd_actions_cnt &&
               act_index >= flow_actions->tnl_pmd_actions_pos &&
               act_index < flow_actions->tnl_pmd_actions_pos +
                           flow_actions->tnl_pmd_actions_cnt) {
        /* Opaque PMD tunnel actions are skipped. */
        return;
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_MARK) {
        const struct rte_flow_action_mark *mark = actions->conf;

        ds_put_cstr(s, "mark ");
        if (mark) {
            ds_put_format(s, "id %d ", mark->id);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RSS) {
        ds_put_cstr(s, "rss / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_COUNT) {
        ds_put_cstr(s, "count / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_PORT_ID) {
        const struct rte_flow_action_port_id *port_id = actions->conf;

        ds_put_cstr(s, "port_id ");
        if (port_id) {
            ds_put_format(s, "original %d id %d ",
                          port_id->original, port_id->id);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_DROP) {
        ds_put_cstr(s, "drop / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST) {
        const struct rte_flow_action_set_mac *set_mac = actions->conf;

        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_MAC_DST
                       ? "dst" : "src";

        ds_put_format(s, "set_mac_%s ", dirstr);
        if (set_mac) {
            ds_put_format(s, "mac_addr "ETH_ADDR_FMT" ",
                          ETH_ADDR_BYTES_ARGS(set_mac->mac_addr));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST) {
        const struct rte_flow_action_set_ipv4 *set_ipv4 = actions->conf;
        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV4_DST
                       ? "dst" : "src";

        ds_put_format(s, "set_ipv4_%s ", dirstr);
        if (set_ipv4) {
            ds_put_format(s, "ipv4_addr "IP_FMT" ",
                          IP_ARGS(set_ipv4->ipv4_addr));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TTL) {
        const struct rte_flow_action_set_ttl *set_ttl = actions->conf;

        ds_put_cstr(s, "set_ttl ");
        if (set_ttl) {
            ds_put_format(s, "ttl_value %d ", set_ttl->ttl_value);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_DST) {
        const struct rte_flow_action_set_tp *set_tp = actions->conf;
        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_TP_DST
                       ? "dst" : "src";

        ds_put_format(s, "set_tp_%s ", dirstr);
        if (set_tp) {
            ds_put_format(s, "port %"PRIu16" ", ntohs(set_tp->port));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN) {
        const struct rte_flow_action_of_push_vlan *of_push_vlan =
            actions->conf;

        ds_put_cstr(s, "of_push_vlan ");
        if (of_push_vlan) {
            ds_put_format(s, "ethertype 0x%"PRIx16" ",
                          ntohs(of_push_vlan->ethertype));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP) {
        const struct rte_flow_action_of_set_vlan_pcp *of_set_vlan_pcp =
            actions->conf;

        ds_put_cstr(s, "of_set_vlan_pcp ");
        if (of_set_vlan_pcp) {
            ds_put_format(s, "vlan_pcp %"PRIu8" ", of_set_vlan_pcp->vlan_pcp);
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID) {
        const struct rte_flow_action_of_set_vlan_vid *of_set_vlan_vid =
            actions->conf;

        ds_put_cstr(s, "of_set_vlan_vid ");
        if (of_set_vlan_vid) {
            ds_put_format(s, "vlan_vid %"PRIu16" ",
                          ntohs(of_set_vlan_vid->vlan_vid));
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_OF_POP_VLAN) {
        ds_put_cstr(s, "of_pop_vlan / ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC ||
               actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST) {
        const struct rte_flow_action_set_ipv6 *set_ipv6 = actions->conf;

        char *dirstr = actions->type == RTE_FLOW_ACTION_TYPE_SET_IPV6_DST
                       ? "dst" : "src";

        ds_put_format(s, "set_ipv6_%s ", dirstr);
        if (set_ipv6) {
            ds_put_cstr(s, "ipv6_addr ");
            ipv6_format_addr((struct in6_addr *) &set_ipv6->ipv6_addr, s);
            ds_put_cstr(s, " ");
        }
        ds_put_cstr(s, "/ ");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_RAW_ENCAP) {
        const struct rte_flow_action_raw_encap *raw_encap = actions->conf;

        ds_put_cstr(s, "raw_encap index 0 / ");
        if (raw_encap) {
            ds_put_format(s_extra, "Raw-encap size=%ld set raw_encap 0 raw "
                          "pattern is ", raw_encap->size);
            for (int i = 0; i < raw_encap->size; i++) {
                ds_put_format(s_extra, "%02x", raw_encap->data[i]);
            }
            ds_put_cstr(s_extra, " / end_set;");
        }
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP) {
        const struct rte_flow_action_vxlan_encap *vxlan_encap = actions->conf;
        const struct rte_flow_item *items = vxlan_encap->definition;

        ds_put_cstr(s, "vxlan_encap / ");
        dump_vxlan_encap(s_extra, items);
        ds_put_cstr(s_extra, ";");
    } else if (actions->type == RTE_FLOW_ACTION_TYPE_JUMP) {
        const struct rte_flow_action_jump *jump = actions->conf;

        ds_put_cstr(s, "jump ");
        if (jump) {
            ds_put_format(s, "group %"PRIu32" ", jump->group);
        }
        ds_put_cstr(s, "/ ");
    } else {
        ds_put_format(s, "unknown rte flow action (%d)\n", actions->type);
    }
}

static struct ds *
dump_flow(struct ds *s, struct ds *s_extra,
          const struct rte_flow_attr *attr,
          struct flow_patterns *flow_patterns,
          struct flow_actions *flow_actions)
{
    int i;

    if (attr) {
        dump_flow_attr(s, s_extra, attr, flow_patterns, flow_actions);
    }
    ds_put_cstr(s, "pattern ");
    for (i = 0; i < flow_patterns->cnt; i++) {
        dump_flow_pattern(s, flow_patterns, i);
    }
    ds_put_cstr(s, "actions ");
    for (i = 0; i < flow_actions->cnt; i++) {
        dump_flow_action(s, s_extra, flow_actions, i);
    }
    return s;
}

static struct rte_flow *
netdev_offload_dpdk_flow_create(struct netdev *netdev,
                                const struct rte_flow_attr *attr,
                                struct flow_patterns *flow_patterns,
                                struct flow_actions *flow_actions,
                                struct rte_flow_error *error)
{
    const struct rte_flow_action *actions = flow_actions->actions;
    const struct rte_flow_item *items = flow_patterns->items;
    struct ds s_extra = DS_EMPTY_INITIALIZER;
    struct ds s = DS_EMPTY_INITIALIZER;
    struct rte_flow *flow;
    char *extra_str;

    flow = netdev_dpdk_rte_flow_create(netdev, attr, items, actions, error);
    if (flow) {
        if (!VLOG_DROP_DBG(&rl)) {
            dump_flow(&s, &s_extra, attr, flow_patterns, flow_actions);
            extra_str = ds_cstr(&s_extra);
            VLOG_DBG_RL(&rl, "%s: rte_flow 0x%"PRIxPTR" %s  flow create %d %s",
                        netdev_get_name(netdev), (intptr_t) flow, extra_str,
                        netdev_dpdk_get_port_id(netdev), ds_cstr(&s));
        }
    } else {
        enum vlog_level level = VLL_WARN;

        if (error->type == RTE_FLOW_ERROR_TYPE_ACTION) {
            level = VLL_DBG;
        }
        VLOG_RL(&rl, level, "%s: rte_flow creation failed: %d (%s).",
                netdev_get_name(netdev), error->type, error->message);
        if (!vlog_should_drop(&this_module, level, &rl)) {
            dump_flow(&s, &s_extra, attr, flow_patterns, flow_actions);
            extra_str = ds_cstr(&s_extra);
            VLOG_RL(&rl, level, "%s: Failed flow: %s  flow create %d %s",
                    netdev_get_name(netdev), extra_str,
                    netdev_dpdk_get_port_id(netdev), ds_cstr(&s));
        }
    }
    ds_destroy(&s);
    ds_destroy(&s_extra);
    return flow;
}

static void
add_flow_pattern(struct flow_patterns *patterns, enum rte_flow_item_type type,
                 const void *spec, const void *mask)
{
    int cnt = patterns->cnt;

    if (cnt == 0) {
        patterns->current_max = 8;
        patterns->items = xcalloc(patterns->current_max,
                                  sizeof *patterns->items);
    } else if (cnt == patterns->current_max) {
        patterns->current_max *= 2;
        patterns->items = xrealloc(patterns->items, patterns->current_max *
                                   sizeof *patterns->items);
    }

    patterns->items[cnt].type = type;
    patterns->items[cnt].spec = spec;
    patterns->items[cnt].mask = mask;
    patterns->items[cnt].last = NULL;
    patterns->cnt++;
}

static void
add_flow_action(struct flow_actions *actions, enum rte_flow_action_type type,
                const void *conf)
{
    int cnt = actions->cnt;

    if (cnt == 0) {
        actions->current_max = 8;
        actions->actions = xcalloc(actions->current_max,
                                   sizeof *actions->actions);
    } else if (cnt == actions->current_max) {
        actions->current_max *= 2;
        actions->actions = xrealloc(actions->actions, actions->current_max *
                                    sizeof *actions->actions);
    }

    actions->actions[cnt].type = type;
    actions->actions[cnt].conf = conf;
    actions->cnt++;
}

static void
add_flow_tnl_actions(struct flow_actions *actions,
                     struct netdev *tnl_netdev,
                     struct rte_flow_action *tnl_pmd_actions,
                     uint32_t tnl_pmd_actions_cnt)
{
    int i;

    actions->tnl_netdev = tnl_netdev;
    actions->tnl_pmd_actions_pos = actions->cnt;
    actions->tnl_pmd_actions = tnl_pmd_actions;
    actions->tnl_pmd_actions_cnt = tnl_pmd_actions_cnt;
    for (i = 0; i < tnl_pmd_actions_cnt; i++) {
        add_flow_action(actions, tnl_pmd_actions[i].type,
                        tnl_pmd_actions[i].conf);
    }
}

static void
add_flow_tnl_items(struct flow_patterns *patterns,
                   struct netdev *physdev,
                   struct rte_flow_item *tnl_pmd_items,
                   uint32_t tnl_pmd_items_cnt)
{
    int i;

    patterns->physdev = physdev;
    patterns->tnl_pmd_items = tnl_pmd_items;
    patterns->tnl_pmd_items_cnt = tnl_pmd_items_cnt;
    for (i = 0; i < tnl_pmd_items_cnt; i++) {
        add_flow_pattern(patterns, tnl_pmd_items[i].type,
                         tnl_pmd_items[i].spec, tnl_pmd_items[i].mask);
    }
}

static void
free_flow_patterns(struct flow_patterns *patterns)
{
    struct rte_flow_error error;
    int i;

    if (patterns->tnl_pmd_items) {
        struct rte_flow_item *tnl_pmd_items = patterns->tnl_pmd_items;
        uint32_t tnl_pmd_items_cnt = patterns->tnl_pmd_items_cnt;
        struct netdev *physdev = patterns->physdev;

        if (netdev_dpdk_rte_flow_tunnel_item_release(physdev, tnl_pmd_items,
                                                     tnl_pmd_items_cnt,
                                                     &error)) {
            VLOG_DBG_RL(&rl, "%s: netdev_dpdk_rte_flow_tunnel_item_release "
                        "failed: %d (%s).", netdev_get_name(physdev),
                        error.type, error.message);
        }
    }

    for (i = patterns->tnl_pmd_items_cnt; i < patterns->cnt; i++) {
        if (patterns->items[i].spec) {
            free(CONST_CAST(void *, patterns->items[i].spec));
        }
        if (patterns->items[i].mask) {
            free(CONST_CAST(void *, patterns->items[i].mask));
        }
    }
    free(patterns->items);
    patterns->items = NULL;
    patterns->cnt = 0;
}

static void
free_flow_actions(struct flow_actions *actions)
{
    struct rte_flow_error error;
    int i;

    for (i = 0; i < actions->cnt; i++) {
        if (actions->tnl_pmd_actions_cnt &&
            i == actions->tnl_pmd_actions_pos) {
            if (netdev_dpdk_rte_flow_tunnel_action_decap_release(
                    actions->tnl_netdev, actions->tnl_pmd_actions,
                    actions->tnl_pmd_actions_cnt, &error)) {
                VLOG_DBG_RL(&rl, "%s: "
                            "netdev_dpdk_rte_flow_tunnel_action_decap_release "
                            "failed: %d (%s).",
                            netdev_get_name(actions->tnl_netdev),
                            error.type, error.message);
            }
            i += actions->tnl_pmd_actions_cnt - 1;
            continue;
        }
        if (actions->actions[i].conf) {
            free(CONST_CAST(void *, actions->actions[i].conf));
        }
    }
    free(actions->actions);
    actions->actions = NULL;
    actions->cnt = 0;
    ds_destroy(&actions->s_tnl);
}

static int
vport_to_rte_tunnel(struct netdev *vport,
                    struct rte_flow_tunnel *tunnel,
                    struct netdev *netdev,
                    struct ds *s_tnl)
{
    const struct netdev_tunnel_config *tnl_cfg;

    memset(tunnel, 0, sizeof *tunnel);
    if (!strcmp(netdev_get_type(vport), "vxlan")) {
        tunnel->type = RTE_FLOW_ITEM_TYPE_VXLAN;
        tnl_cfg = netdev_get_tunnel_config(vport);
        if (!tnl_cfg) {
            return -1;
        }
        tunnel->tp_dst = tnl_cfg->dst_port;
        if (!VLOG_DROP_DBG(&rl)) {
            ds_put_format(s_tnl, "flow tunnel create %d type vxlan; ",
                          netdev_dpdk_get_port_id(netdev));
        }
    } else {
        VLOG_DBG_RL(&rl, "vport type '%s' is not supported",
                    netdev_get_type(vport));
        return -1;
    }

    return 0;
}

static int
add_vport_match(struct flow_patterns *patterns,
                odp_port_t orig_in_port,
                struct netdev *tnldev)
{
    struct rte_flow_item *tnl_pmd_items;
    struct rte_flow_tunnel tunnel;
    struct rte_flow_error error;
    uint32_t tnl_pmd_items_cnt;
    struct netdev *physdev;
    int ret;

    physdev = netdev_ports_get(orig_in_port, tnldev->dpif_type);
    if (physdev == NULL) {
        return -1;
    }

    ret = vport_to_rte_tunnel(tnldev, &tunnel, physdev, &patterns->s_tnl);
    if (ret) {
        goto out;
    }
    ret = netdev_dpdk_rte_flow_tunnel_match(physdev, &tunnel, &tnl_pmd_items,
                                            &tnl_pmd_items_cnt, &error);
    if (ret) {
        VLOG_DBG_RL(&rl, "%s: netdev_dpdk_rte_flow_tunnel_match failed: "
                    "%d (%s).", netdev_get_name(physdev), error.type,
                    error.message);
        goto out;
    }
    add_flow_tnl_items(patterns, physdev, tnl_pmd_items, tnl_pmd_items_cnt);

out:
    netdev_close(physdev);
    return ret;
}

static int
parse_tnl_ip_match(struct flow_patterns *patterns,
                   struct match *match,
                   uint8_t proto)
{
    struct flow *consumed_masks;

    consumed_masks = &match->wc.masks;
    /* IP v4 */
    if (match->wc.masks.tunnel.ip_src || match->wc.masks.tunnel.ip_dst) {
        struct rte_flow_item_ipv4 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.type_of_service = match->flow.tunnel.ip_tos;
        spec->hdr.time_to_live    = match->flow.tunnel.ip_ttl;
        spec->hdr.next_proto_id   = proto;
        spec->hdr.src_addr        = match->flow.tunnel.ip_src;
        spec->hdr.dst_addr        = match->flow.tunnel.ip_dst;

        mask->hdr.type_of_service = match->wc.masks.tunnel.ip_tos;
        mask->hdr.time_to_live    = match->wc.masks.tunnel.ip_ttl;
        mask->hdr.next_proto_id   = UINT8_MAX;
        mask->hdr.src_addr        = match->wc.masks.tunnel.ip_src;
        mask->hdr.dst_addr        = match->wc.masks.tunnel.ip_dst;

        consumed_masks->tunnel.ip_tos = 0;
        consumed_masks->tunnel.ip_ttl = 0;
        consumed_masks->tunnel.ip_src = 0;
        consumed_masks->tunnel.ip_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, spec, mask);
    } else if (!is_all_zeros(&match->wc.masks.tunnel.ipv6_src,
                             sizeof(struct in6_addr)) ||
               !is_all_zeros(&match->wc.masks.tunnel.ipv6_dst,
                             sizeof(struct in6_addr))) {
        /* IP v6 */
        struct rte_flow_item_ipv6 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.proto = proto;
        spec->hdr.hop_limits = match->flow.tunnel.ip_ttl;
        spec->hdr.vtc_flow = htonl((uint32_t) match->flow.tunnel.ip_tos <<
                                   RTE_IPV6_HDR_TC_SHIFT);
        memcpy(spec->hdr.src_addr, &match->flow.tunnel.ipv6_src,
               sizeof spec->hdr.src_addr);
        memcpy(spec->hdr.dst_addr, &match->flow.tunnel.ipv6_dst,
               sizeof spec->hdr.dst_addr);

        mask->hdr.proto = UINT8_MAX;
        mask->hdr.hop_limits = match->wc.masks.tunnel.ip_ttl;
        mask->hdr.vtc_flow = htonl((uint32_t) match->wc.masks.tunnel.ip_tos <<
                                   RTE_IPV6_HDR_TC_SHIFT);
        memcpy(mask->hdr.src_addr, &match->wc.masks.tunnel.ipv6_src,
               sizeof mask->hdr.src_addr);
        memcpy(mask->hdr.dst_addr, &match->wc.masks.tunnel.ipv6_dst,
               sizeof mask->hdr.dst_addr);

        consumed_masks->tunnel.ip_tos = 0;
        consumed_masks->tunnel.ip_ttl = 0;
        memset(&consumed_masks->tunnel.ipv6_src, 0,
               sizeof consumed_masks->tunnel.ipv6_src);
        memset(&consumed_masks->tunnel.ipv6_dst, 0,
               sizeof consumed_masks->tunnel.ipv6_dst);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6, spec, mask);
    } else {
        VLOG_ERR_RL(&rl, "Tunnel L3 protocol is neither IPv4 nor IPv6");
        return -1;
    }

    return 0;
}

static void
parse_tnl_udp_match(struct flow_patterns *patterns,
                    struct match *match)
{
    struct flow *consumed_masks;
    struct rte_flow_item_udp *spec, *mask;

    consumed_masks = &match->wc.masks;

    spec = xzalloc(sizeof *spec);
    mask = xzalloc(sizeof *mask);

    spec->hdr.src_port = match->flow.tunnel.tp_src;
    spec->hdr.dst_port = match->flow.tunnel.tp_dst;

    mask->hdr.src_port = match->wc.masks.tunnel.tp_src;
    mask->hdr.dst_port = match->wc.masks.tunnel.tp_dst;

    consumed_masks->tunnel.tp_src = 0;
    consumed_masks->tunnel.tp_dst = 0;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP, spec, mask);
}

static int
parse_vxlan_match(struct flow_patterns *patterns,
                  struct match *match)
{
    struct rte_flow_item_vxlan *vx_spec, *vx_mask;
    struct flow *consumed_masks;
    int ret;

    ret = parse_tnl_ip_match(patterns, match, IPPROTO_UDP);
    if (ret) {
        return -1;
    }
    parse_tnl_udp_match(patterns, match);

    consumed_masks = &match->wc.masks;
    /* VXLAN */
    vx_spec = xzalloc(sizeof *vx_spec);
    vx_mask = xzalloc(sizeof *vx_mask);

    put_unaligned_be32((ovs_be32 *) vx_spec->vni,
                       htonl(ntohll(match->flow.tunnel.tun_id) << 8));
    put_unaligned_be32((ovs_be32 *) vx_mask->vni,
                       htonl(ntohll(match->wc.masks.tunnel.tun_id) << 8));

    consumed_masks->tunnel.tun_id = 0;
    consumed_masks->tunnel.flags = 0;

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VXLAN, vx_spec, vx_mask);
    return 0;
}

static int OVS_UNUSED
parse_flow_tnl_match(struct netdev *tnldev,
                     struct flow_patterns *patterns,
                     odp_port_t orig_in_port,
                     struct match *match)
{
    int ret;

    ret = add_vport_match(patterns, orig_in_port, tnldev);
    if (ret) {
        return ret;
    }

    if (!strcmp(netdev_get_type(tnldev), "vxlan")) {
        ret = parse_vxlan_match(patterns, match);
    }

    return ret;
}

static int
parse_flow_match(struct netdev *netdev,
                 odp_port_t orig_in_port OVS_UNUSED,
                 struct flow_patterns *patterns,
                 struct match *match)
{
    struct flow *consumed_masks;
    uint8_t proto = 0;

    consumed_masks = &match->wc.masks;

    if (!flow_tnl_dst_is_set(&match->flow.tunnel)) {
        memset(&consumed_masks->tunnel, 0, sizeof consumed_masks->tunnel);
    }

    patterns->physdev = netdev;
#ifdef ALLOW_EXPERIMENTAL_API /* Packet restoration API required. */
    if (netdev_vport_is_vport_class(netdev->netdev_class) &&
        parse_flow_tnl_match(netdev, patterns, orig_in_port, match)) {
        return -1;
    }
#endif
    memset(&consumed_masks->in_port, 0, sizeof consumed_masks->in_port);
    /* recirc id must be zero. */
    if (match->wc.masks.recirc_id & match->flow.recirc_id) {
        return -1;
    }
    consumed_masks->recirc_id = 0;
    consumed_masks->packet_type = 0;

    /* Eth */
    if (match->wc.masks.dl_type ||
        !eth_addr_is_zero(match->wc.masks.dl_src) ||
        !eth_addr_is_zero(match->wc.masks.dl_dst)) {
        struct rte_flow_item_eth *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        memcpy(&spec->dst, &match->flow.dl_dst, sizeof spec->dst);
        memcpy(&spec->src, &match->flow.dl_src, sizeof spec->src);
        spec->type = match->flow.dl_type;

        memcpy(&mask->dst, &match->wc.masks.dl_dst, sizeof mask->dst);
        memcpy(&mask->src, &match->wc.masks.dl_src, sizeof mask->src);
        mask->type = match->wc.masks.dl_type;

        memset(&consumed_masks->dl_dst, 0, sizeof consumed_masks->dl_dst);
        memset(&consumed_masks->dl_src, 0, sizeof consumed_masks->dl_src);
        consumed_masks->dl_type = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ETH, spec, mask);
    }

    /* VLAN */
    if (match->wc.masks.vlans[0].tci && match->flow.vlans[0].tci) {
        struct rte_flow_item_vlan *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->tci = match->flow.vlans[0].tci & ~htons(VLAN_CFI);
        mask->tci = match->wc.masks.vlans[0].tci & ~htons(VLAN_CFI);

        /* Match any protocols. */
        mask->inner_type = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_VLAN, spec, mask);
    }
    /* For untagged matching match->wc.masks.vlans[0].tci is 0xFFFF and
     * match->flow.vlans[0].tci is 0. Consuming is needed outside of the if
     * scope to handle that.
     */
    memset(&consumed_masks->vlans[0], 0, sizeof consumed_masks->vlans[0]);

    /* IP v4 */
    if (match->flow.dl_type == htons(ETH_TYPE_IP)) {
        struct rte_flow_item_ipv4 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.type_of_service = match->flow.nw_tos;
        spec->hdr.time_to_live    = match->flow.nw_ttl;
        spec->hdr.next_proto_id   = match->flow.nw_proto;
        spec->hdr.src_addr        = match->flow.nw_src;
        spec->hdr.dst_addr        = match->flow.nw_dst;

        mask->hdr.type_of_service = match->wc.masks.nw_tos;
        mask->hdr.time_to_live    = match->wc.masks.nw_ttl;
        mask->hdr.next_proto_id   = match->wc.masks.nw_proto;
        mask->hdr.src_addr        = match->wc.masks.nw_src;
        mask->hdr.dst_addr        = match->wc.masks.nw_dst;

        consumed_masks->nw_tos = 0;
        consumed_masks->nw_ttl = 0;
        consumed_masks->nw_proto = 0;
        consumed_masks->nw_src = 0;
        consumed_masks->nw_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV4, spec, mask);

        /* Save proto for L4 protocol setup. */
        proto = spec->hdr.next_proto_id &
                mask->hdr.next_proto_id;
    }
    /* If fragmented, then don't HW accelerate - for now. */
    if (match->wc.masks.nw_frag & match->flow.nw_frag) {
        return -1;
    }
    consumed_masks->nw_frag = 0;

    /* IP v6 */
    if (match->flow.dl_type == htons(ETH_TYPE_IPV6)) {
        struct rte_flow_item_ipv6 *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.proto = match->flow.nw_proto;
        spec->hdr.hop_limits = match->flow.nw_ttl;
        spec->hdr.vtc_flow =
            htonl((uint32_t) match->flow.nw_tos << RTE_IPV6_HDR_TC_SHIFT);
        memcpy(spec->hdr.src_addr, &match->flow.ipv6_src,
               sizeof spec->hdr.src_addr);
        memcpy(spec->hdr.dst_addr, &match->flow.ipv6_dst,
               sizeof spec->hdr.dst_addr);

        mask->hdr.proto = match->wc.masks.nw_proto;
        mask->hdr.hop_limits = match->wc.masks.nw_ttl;
        mask->hdr.vtc_flow =
            htonl((uint32_t) match->wc.masks.nw_tos << RTE_IPV6_HDR_TC_SHIFT);
        memcpy(mask->hdr.src_addr, &match->wc.masks.ipv6_src,
               sizeof mask->hdr.src_addr);
        memcpy(mask->hdr.dst_addr, &match->wc.masks.ipv6_dst,
               sizeof mask->hdr.dst_addr);

        consumed_masks->nw_proto = 0;
        consumed_masks->nw_ttl = 0;
        consumed_masks->nw_tos = 0;
        memset(&consumed_masks->ipv6_src, 0, sizeof consumed_masks->ipv6_src);
        memset(&consumed_masks->ipv6_dst, 0, sizeof consumed_masks->ipv6_dst);

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_IPV6, spec, mask);

        /* Save proto for L4 protocol setup. */
        proto = spec->hdr.proto & mask->hdr.proto;
    }

    if (proto != IPPROTO_ICMP && proto != IPPROTO_UDP  &&
        proto != IPPROTO_SCTP && proto != IPPROTO_TCP  &&
        (match->wc.masks.tp_src ||
         match->wc.masks.tp_dst ||
         match->wc.masks.tcp_flags)) {
        VLOG_DBG("L4 Protocol (%u) not supported", proto);
        return -1;
    }

    if (proto == IPPROTO_TCP) {
        struct rte_flow_item_tcp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port  = match->flow.tp_src;
        spec->hdr.dst_port  = match->flow.tp_dst;
        spec->hdr.data_off  = ntohs(match->flow.tcp_flags) >> 8;
        spec->hdr.tcp_flags = ntohs(match->flow.tcp_flags) & 0xff;

        mask->hdr.src_port  = match->wc.masks.tp_src;
        mask->hdr.dst_port  = match->wc.masks.tp_dst;
        mask->hdr.data_off  = ntohs(match->wc.masks.tcp_flags) >> 8;
        mask->hdr.tcp_flags = ntohs(match->wc.masks.tcp_flags) & 0xff;

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;
        consumed_masks->tcp_flags = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_TCP, spec, mask);
    } else if (proto == IPPROTO_UDP) {
        struct rte_flow_item_udp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_UDP, spec, mask);
    } else if (proto == IPPROTO_SCTP) {
        struct rte_flow_item_sctp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.src_port = match->flow.tp_src;
        spec->hdr.dst_port = match->flow.tp_dst;

        mask->hdr.src_port = match->wc.masks.tp_src;
        mask->hdr.dst_port = match->wc.masks.tp_dst;

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_SCTP, spec, mask);
    } else if (proto == IPPROTO_ICMP) {
        struct rte_flow_item_icmp *spec, *mask;

        spec = xzalloc(sizeof *spec);
        mask = xzalloc(sizeof *mask);

        spec->hdr.icmp_type = (uint8_t) ntohs(match->flow.tp_src);
        spec->hdr.icmp_code = (uint8_t) ntohs(match->flow.tp_dst);

        mask->hdr.icmp_type = (uint8_t) ntohs(match->wc.masks.tp_src);
        mask->hdr.icmp_code = (uint8_t) ntohs(match->wc.masks.tp_dst);

        consumed_masks->tp_src = 0;
        consumed_masks->tp_dst = 0;

        add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_ICMP, spec, mask);
    }

    add_flow_pattern(patterns, RTE_FLOW_ITEM_TYPE_END, NULL, NULL);

    if (!is_all_zeros(consumed_masks, sizeof *consumed_masks)) {
        return -1;
    }
    return 0;
}

static void
add_flow_mark_rss_actions(struct flow_actions *actions,
                          uint32_t flow_mark,
                          const struct netdev *netdev)
{
    struct rte_flow_action_mark *mark;
    struct action_rss_data {
        struct rte_flow_action_rss conf;
        uint16_t queue[0];
    } *rss_data;
    BUILD_ASSERT_DECL(offsetof(struct action_rss_data, conf) == 0);
    int i;

    mark = xzalloc(sizeof *mark);

    mark->id = flow_mark;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_MARK, mark);

    rss_data = xmalloc(sizeof *rss_data +
                       netdev_n_rxq(netdev) * sizeof rss_data->queue[0]);
    *rss_data = (struct action_rss_data) {
        .conf = (struct rte_flow_action_rss) {
            .func = RTE_ETH_HASH_FUNCTION_DEFAULT,
            .level = 0,
            .types = 0,
            .queue_num = netdev_n_rxq(netdev),
            .queue = rss_data->queue,
            .key_len = 0,
            .key  = NULL
        },
    };

    /* Override queue array with default. */
    for (i = 0; i < netdev_n_rxq(netdev); i++) {
       rss_data->queue[i] = i;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RSS, &rss_data->conf);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
}

static struct rte_flow *
netdev_offload_dpdk_mark_rss(struct flow_patterns *patterns,
                             struct netdev *netdev,
                             uint32_t flow_mark)
{
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    const struct rte_flow_attr flow_attr = {
        .group = 0,
        .priority = 0,
        .ingress = 1,
        .egress = 0
    };
    struct rte_flow_error error;
    struct rte_flow *flow;

    add_flow_mark_rss_actions(&actions, flow_mark, netdev);

    flow = netdev_offload_dpdk_flow_create(netdev, &flow_attr, patterns,
                                           &actions, &error);

    free_flow_actions(&actions);
    return flow;
}

static void
add_count_action(struct flow_actions *actions)
{
    struct rte_flow_action_count *count = xzalloc(sizeof *count);

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_COUNT, count);
}

static int
add_port_id_action(struct flow_actions *actions,
                   struct netdev *outdev)
{
    struct rte_flow_action_port_id *port_id;
    int outdev_id;

    outdev_id = netdev_dpdk_get_port_id(outdev);
    if (outdev_id < 0) {
        return -1;
    }
    port_id = xzalloc(sizeof *port_id);
    port_id->id = outdev_id;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_PORT_ID, port_id);
    return 0;
}

static int
add_output_action(struct netdev *netdev,
                  struct flow_actions *actions,
                  const struct nlattr *nla)
{
    struct netdev *outdev;
    odp_port_t port;
    int ret = 0;

    port = nl_attr_get_odp_port(nla);
    outdev = netdev_ports_get(port, netdev->dpif_type);
    if (outdev == NULL) {
        VLOG_DBG_RL(&rl, "Cannot find netdev for odp port %"PRIu32, port);
        return -1;
    }
    if (!netdev_flow_api_equals(netdev, outdev) ||
        add_port_id_action(actions, outdev)) {
        VLOG_DBG_RL(&rl, "%s: Output to port \'%s\' cannot be offloaded.",
                    netdev_get_name(netdev), netdev_get_name(outdev));
        ret = -1;
    }
    netdev_close(outdev);
    return ret;
}

static int
add_set_flow_action__(struct flow_actions *actions,
                      const void *value, void *mask,
                      const size_t size, const int attr)
{
    void *spec;

    if (mask) {
        /* DPDK does not support partially masked set actions. In such
         * case, fail the offload.
         */
        if (is_all_zeros(mask, size)) {
            return 0;
        }
        if (!is_all_ones(mask, size)) {
            VLOG_DBG_RL(&rl, "Partial mask is not supported");
            return -1;
        }
    }

    spec = xzalloc(size);
    memcpy(spec, value, size);
    add_flow_action(actions, attr, spec);

    /* Clear used mask for later checking. */
    if (mask) {
        memset(mask, 0, size);
    }
    return 0;
}

BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_mac) ==
                  MEMBER_SIZEOF(struct ovs_key_ethernet, eth_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_mac) ==
                  MEMBER_SIZEOF(struct ovs_key_ethernet, eth_dst));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ipv4) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ipv4) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_dst));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ttl) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_ttl));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ipv6) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ipv6) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_dst));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_ttl) ==
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_hlimit));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_tp) ==
                  MEMBER_SIZEOF(struct ovs_key_tcp, tcp_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_tp) ==
                  MEMBER_SIZEOF(struct ovs_key_tcp, tcp_dst));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_tp) ==
                  MEMBER_SIZEOF(struct ovs_key_udp, udp_src));
BUILD_ASSERT_DECL(sizeof(struct rte_flow_action_set_tp) ==
                  MEMBER_SIZEOF(struct ovs_key_udp, udp_dst));

static int
parse_set_actions(struct flow_actions *actions,
                  const struct nlattr *set_actions,
                  const size_t set_actions_len,
                  bool masked)
{
    const struct nlattr *sa;
    unsigned int sleft;

#define add_set_flow_action(field, type)                                      \
    if (add_set_flow_action__(actions, &key->field,                           \
                              mask ? CONST_CAST(void *, &mask->field) : NULL, \
                              sizeof key->field, type)) {                     \
        return -1;                                                            \
    }

    NL_ATTR_FOR_EACH_UNSAFE (sa, sleft, set_actions, set_actions_len) {
        if (nl_attr_type(sa) == OVS_KEY_ATTR_ETHERNET) {
            const struct ovs_key_ethernet *key = nl_attr_get(sa);
            const struct ovs_key_ethernet *mask = masked ? key + 1 : NULL;

            add_set_flow_action(eth_src, RTE_FLOW_ACTION_TYPE_SET_MAC_SRC);
            add_set_flow_action(eth_dst, RTE_FLOW_ACTION_TYPE_SET_MAC_DST);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported ETHERNET set action");
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV4) {
            const struct ovs_key_ipv4 *key = nl_attr_get(sa);
            const struct ovs_key_ipv4 *mask = masked ? key + 1 : NULL;

            add_set_flow_action(ipv4_src, RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC);
            add_set_flow_action(ipv4_dst, RTE_FLOW_ACTION_TYPE_SET_IPV4_DST);
            add_set_flow_action(ipv4_ttl, RTE_FLOW_ACTION_TYPE_SET_TTL);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported IPv4 set action");
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_IPV6) {
            const struct ovs_key_ipv6 *key = nl_attr_get(sa);
            const struct ovs_key_ipv6 *mask = masked ? key + 1 : NULL;

            add_set_flow_action(ipv6_src, RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC);
            add_set_flow_action(ipv6_dst, RTE_FLOW_ACTION_TYPE_SET_IPV6_DST);
            add_set_flow_action(ipv6_hlimit, RTE_FLOW_ACTION_TYPE_SET_TTL);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported IPv6 set action");
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_TCP) {
            const struct ovs_key_tcp *key = nl_attr_get(sa);
            const struct ovs_key_tcp *mask = masked ? key + 1 : NULL;

            add_set_flow_action(tcp_src, RTE_FLOW_ACTION_TYPE_SET_TP_SRC);
            add_set_flow_action(tcp_dst, RTE_FLOW_ACTION_TYPE_SET_TP_DST);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported TCP set action");
                return -1;
            }
        } else if (nl_attr_type(sa) == OVS_KEY_ATTR_UDP) {
            const struct ovs_key_udp *key = nl_attr_get(sa);
            const struct ovs_key_udp *mask = masked ? key + 1 : NULL;

            add_set_flow_action(udp_src, RTE_FLOW_ACTION_TYPE_SET_TP_SRC);
            add_set_flow_action(udp_dst, RTE_FLOW_ACTION_TYPE_SET_TP_DST);

            if (mask && !is_all_zeros(mask, sizeof *mask)) {
                VLOG_DBG_RL(&rl, "Unsupported UDP set action");
                return -1;
            }
        } else {
            VLOG_DBG_RL(&rl,
                        "Unsupported set action type %d", nl_attr_type(sa));
            return -1;
        }
    }

    return 0;
}

/* Maximum number of items in struct rte_flow_action_vxlan_encap.
 * ETH / IPv4(6) / UDP / VXLAN / END
 */
#define ACTION_VXLAN_ENCAP_ITEMS_NUM 5

static int
add_vxlan_encap_action(struct flow_actions *actions,
                       const void *header)
{
    const struct eth_header *eth;
    const struct udp_header *udp;
    struct vxlan_data {
        struct rte_flow_action_vxlan_encap conf;
        struct rte_flow_item items[ACTION_VXLAN_ENCAP_ITEMS_NUM];
    } *vxlan_data;
    BUILD_ASSERT_DECL(offsetof(struct vxlan_data, conf) == 0);
    const void *vxlan;
    const void *l3;
    const void *l4;
    int field;

    vxlan_data = xzalloc(sizeof *vxlan_data);
    field = 0;

    eth = header;
    /* Ethernet */
    vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_ETH;
    vxlan_data->items[field].spec = eth;
    vxlan_data->items[field].mask = &rte_flow_item_eth_mask;
    field++;

    l3 = eth + 1;
    /* IP */
    if (eth->eth_type == htons(ETH_TYPE_IP)) {
        /* IPv4 */
        const struct ip_header *ip = l3;

        vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_IPV4;
        vxlan_data->items[field].spec = ip;
        vxlan_data->items[field].mask = &rte_flow_item_ipv4_mask;

        if (ip->ip_proto != IPPROTO_UDP) {
            goto err;
        }
        l4 = (ip + 1);
    } else if (eth->eth_type == htons(ETH_TYPE_IPV6)) {
        const struct ovs_16aligned_ip6_hdr *ip6 = l3;

        vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_IPV6;
        vxlan_data->items[field].spec = ip6;
        vxlan_data->items[field].mask = &rte_flow_item_ipv6_mask;

        if (ip6->ip6_nxt != IPPROTO_UDP) {
            goto err;
        }
        l4 = (ip6 + 1);
    } else {
        goto err;
    }
    field++;

    udp = l4;
    vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_UDP;
    vxlan_data->items[field].spec = udp;
    vxlan_data->items[field].mask = &rte_flow_item_udp_mask;
    field++;

    vxlan = (udp + 1);
    vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_VXLAN;
    vxlan_data->items[field].spec = vxlan;
    vxlan_data->items[field].mask = &rte_flow_item_vxlan_mask;
    field++;

    vxlan_data->items[field].type = RTE_FLOW_ITEM_TYPE_END;

    vxlan_data->conf.definition = vxlan_data->items;

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP, vxlan_data);

    return 0;
err:
    free(vxlan_data);
    return -1;
}

static int
parse_vlan_push_action(struct flow_actions *actions,
                       const struct ovs_action_push_vlan *vlan_push)
{
    struct rte_flow_action_of_push_vlan *rte_push_vlan;
    struct rte_flow_action_of_set_vlan_pcp *rte_vlan_pcp;
    struct rte_flow_action_of_set_vlan_vid *rte_vlan_vid;

    rte_push_vlan = xzalloc(sizeof *rte_push_vlan);
    rte_push_vlan->ethertype = vlan_push->vlan_tpid;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN, rte_push_vlan);

    rte_vlan_pcp = xzalloc(sizeof *rte_vlan_pcp);
    rte_vlan_pcp->vlan_pcp = vlan_tci_to_pcp(vlan_push->vlan_tci);
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP,
                    rte_vlan_pcp);

    rte_vlan_vid = xzalloc(sizeof *rte_vlan_vid);
    rte_vlan_vid->vlan_vid = htons(vlan_tci_to_vid(vlan_push->vlan_tci));
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID,
                    rte_vlan_vid);
    return 0;
}

static int
parse_clone_actions(struct netdev *netdev,
                    struct flow_actions *actions,
                    const struct nlattr *clone_actions,
                    const size_t clone_actions_len)
{
    const struct nlattr *ca;
    unsigned int cleft;

    NL_ATTR_FOR_EACH_UNSAFE (ca, cleft, clone_actions, clone_actions_len) {
        int clone_type = nl_attr_type(ca);

        if (clone_type == OVS_ACTION_ATTR_TUNNEL_PUSH) {
            const struct ovs_action_push_tnl *tnl_push = nl_attr_get(ca);
            struct rte_flow_action_raw_encap *raw_encap;

            if (tnl_push->tnl_type == OVS_VPORT_TYPE_VXLAN &&
                !add_vxlan_encap_action(actions, tnl_push->header)) {
                continue;
            }

            raw_encap = xzalloc(sizeof *raw_encap);
            raw_encap->data = (uint8_t *) tnl_push->header;
            raw_encap->preserve = NULL;
            raw_encap->size = tnl_push->header_len;

            add_flow_action(actions, RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
                            raw_encap);
        } else if (clone_type == OVS_ACTION_ATTR_OUTPUT) {
            if (add_output_action(netdev, actions, ca)) {
                return -1;
            }
        } else {
            VLOG_DBG_RL(&rl,
                        "Unsupported nested action inside clone(), "
                        "action type: %d", clone_type);
            return -1;
        }
    }
    return 0;
}

static void
add_jump_action(struct flow_actions *actions, uint32_t group)
{
    struct rte_flow_action_jump *jump = xzalloc (sizeof *jump);

    jump->group = group;
    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_JUMP, jump);
}

static int OVS_UNUSED
add_tnl_pop_action(struct netdev *netdev,
                   struct flow_actions *actions,
                   const struct nlattr *nla)
{
    struct rte_flow_action *tnl_pmd_actions = NULL;
    uint32_t tnl_pmd_actions_cnt = 0;
    struct rte_flow_tunnel tunnel;
    struct rte_flow_error error;
    struct netdev *vport;
    odp_port_t port;
    int ret;

    port = nl_attr_get_odp_port(nla);
    vport = netdev_ports_get(port, netdev->dpif_type);
    if (vport == NULL) {
        return -1;
    }
    ret = vport_to_rte_tunnel(vport, &tunnel, netdev, &actions->s_tnl);
    netdev_close(vport);
    if (ret) {
        return ret;
    }
    ret = netdev_dpdk_rte_flow_tunnel_decap_set(netdev, &tunnel,
                                                &tnl_pmd_actions,
                                                &tnl_pmd_actions_cnt,
                                                &error);
    if (ret) {
        VLOG_DBG_RL(&rl, "%s: netdev_dpdk_rte_flow_tunnel_decap_set failed: "
                    "%d (%s).", netdev_get_name(netdev), error.type,
                    error.message);
        return ret;
    }
    add_flow_tnl_actions(actions, netdev, tnl_pmd_actions,
                         tnl_pmd_actions_cnt);
    /* After decap_set, the packet processing should continue. In SW, it is
     * done by recirculation (recirc_id = 0). In rte_flow, the group is
     * equivalent to recirc_id, thus jump to group 0 is added to instruct the
     * the HW to proceed processing.
     */
    add_jump_action(actions, 0);
    return 0;
}

static int
parse_flow_actions(struct netdev *netdev,
                   struct flow_actions *actions,
                   struct nlattr *nl_actions,
                   size_t nl_actions_len)
{
    struct nlattr *nla;
    size_t left;

    add_count_action(actions);
    NL_ATTR_FOR_EACH_UNSAFE (nla, left, nl_actions, nl_actions_len) {
        if (nl_attr_type(nla) == OVS_ACTION_ATTR_OUTPUT) {
            if (add_output_action(netdev, actions, nla)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_DROP) {
            add_flow_action(actions, RTE_FLOW_ACTION_TYPE_DROP, NULL);
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_SET ||
                   nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED) {
            const struct nlattr *set_actions = nl_attr_get(nla);
            const size_t set_actions_len = nl_attr_get_size(nla);
            bool masked = nl_attr_type(nla) == OVS_ACTION_ATTR_SET_MASKED;

            if (parse_set_actions(actions, set_actions, set_actions_len,
                                  masked)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_PUSH_VLAN) {
            const struct ovs_action_push_vlan *vlan = nl_attr_get(nla);

            if (parse_vlan_push_action(actions, vlan)) {
                return -1;
            }
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_POP_VLAN) {
            add_flow_action(actions, RTE_FLOW_ACTION_TYPE_OF_POP_VLAN, NULL);
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_CLONE &&
                   left <= NLA_ALIGN(nla->nla_len)) {
            const struct nlattr *clone_actions = nl_attr_get(nla);
            size_t clone_actions_len = nl_attr_get_size(nla);

            if (parse_clone_actions(netdev, actions, clone_actions,
                                    clone_actions_len)) {
                return -1;
            }
#ifdef ALLOW_EXPERIMENTAL_API /* Packet restoration API required. */
        } else if (nl_attr_type(nla) == OVS_ACTION_ATTR_TUNNEL_POP) {
            if (add_tnl_pop_action(netdev, actions, nla)) {
                return -1;
            }
#endif
        } else {
            VLOG_DBG_RL(&rl, "Unsupported action type %d", nl_attr_type(nla));
            return -1;
        }
    }

    if (nl_actions_len == 0) {
        VLOG_DBG_RL(&rl, "No actions provided");
        return -1;
    }

    add_flow_action(actions, RTE_FLOW_ACTION_TYPE_END, NULL);
    return 0;
}

static struct rte_flow *
netdev_offload_dpdk_actions(struct netdev *netdev,
                            struct flow_patterns *patterns,
                            struct nlattr *nl_actions,
                            size_t actions_len)
{
    const struct rte_flow_attr flow_attr = { .ingress = 1, .transfer = 1 };
    struct flow_actions actions = { .actions = NULL, .cnt = 0 };
    struct rte_flow *flow = NULL;
    struct rte_flow_error error;
    int ret;

    ret = parse_flow_actions(netdev, &actions, nl_actions, actions_len);
    if (ret) {
        goto out;
    }
    flow = netdev_offload_dpdk_flow_create(netdev, &flow_attr, patterns,
                                           &actions, &error);
out:
    free_flow_actions(&actions);
    return flow;
}

static struct ufid_to_rte_flow_data *
netdev_offload_dpdk_add_flow(struct netdev *netdev,
                             struct match *match,
                             struct nlattr *nl_actions,
                             size_t actions_len,
                             const ovs_u128 *ufid,
                             struct offload_info *info)
{
    struct flow_patterns patterns = { .items = NULL, .cnt = 0 };
    struct ufid_to_rte_flow_data *flows_data = NULL;
    bool actions_offloaded = true;
    struct rte_flow *flow;

    if (parse_flow_match(netdev, info->orig_in_port, &patterns, match)) {
        VLOG_DBG_RL(&rl, "%s: matches of ufid "UUID_FMT" are not supported",
                    netdev_get_name(netdev), UUID_ARGS((struct uuid *) ufid));
        goto out;
    }

    flow = netdev_offload_dpdk_actions(patterns.physdev, &patterns, nl_actions,
                                       actions_len);
    if (!flow && !netdev_vport_is_vport_class(netdev->netdev_class)) {
        /* If we failed to offload the rule actions fallback to MARK+RSS
         * actions.
         */
        flow = netdev_offload_dpdk_mark_rss(&patterns, netdev,
                                            info->flow_mark);
        actions_offloaded = false;
    }

    if (!flow) {
        goto out;
    }
    flows_data = ufid_to_rte_flow_associate(ufid, netdev, patterns.physdev,
                                            flow, actions_offloaded);
    VLOG_DBG("%s/%s: installed flow %p by ufid "UUID_FMT,
             netdev_get_name(netdev), netdev_get_name(patterns.physdev), flow,
             UUID_ARGS((struct uuid *) ufid));

out:
    free_flow_patterns(&patterns);
    return flows_data;
}

static int
netdev_offload_dpdk_flow_destroy(struct ufid_to_rte_flow_data *rte_flow_data)
{
    struct rte_flow_error error;
    struct rte_flow *rte_flow;
    struct netdev *physdev;
    struct netdev *netdev;
    ovs_u128 *ufid;
    int ret;

    rte_flow = rte_flow_data->rte_flow;
    physdev = rte_flow_data->physdev;
    netdev = rte_flow_data->netdev;
    ufid = &rte_flow_data->ufid;

    ret = netdev_dpdk_rte_flow_destroy(physdev, rte_flow, &error);

    if (ret == 0) {
        ufid_to_rte_flow_disassociate(rte_flow_data);
        VLOG_DBG_RL(&rl, "%s/%s: rte_flow 0x%"PRIxPTR
                    " flow destroy %d ufid " UUID_FMT,
                    netdev_get_name(netdev), netdev_get_name(physdev),
                    (intptr_t) rte_flow,
                    netdev_dpdk_get_port_id(netdev),
                    UUID_ARGS((struct uuid *) ufid));
    } else {
        VLOG_ERR("Failed flow: %s/%s: flow destroy %d ufid " UUID_FMT,
                 netdev_get_name(netdev), netdev_get_name(physdev),
                 netdev_dpdk_get_port_id(netdev),
                 UUID_ARGS((struct uuid *) ufid));
    }

    return ret;
}

struct get_netdev_odp_aux {
    struct netdev *netdev;
    odp_port_t odp_port;
};

static bool
get_netdev_odp_cb(struct netdev *netdev,
                  odp_port_t odp_port,
                  void *aux_)
{
    struct get_netdev_odp_aux *aux = aux_;

    if (netdev == aux->netdev) {
        aux->odp_port = odp_port;
        return true;
    }
    return false;
}

static int
netdev_offload_dpdk_flow_put(struct netdev *netdev, struct match *match,
                             struct nlattr *actions, size_t actions_len,
                             const ovs_u128 *ufid, struct offload_info *info,
                             struct dpif_flow_stats *stats)
{
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct dpif_flow_stats old_stats;
    bool modification = false;
    int ret;

    /*
     * If an old rte_flow exists, it means it's a flow modification.
     * Here destroy the old rte flow first before adding a new one.
     * Keep the stats for the newly created rule.
     */
    rte_flow_data = ufid_to_rte_flow_data_find(ufid, false);
    if (rte_flow_data && rte_flow_data->rte_flow) {
        struct get_netdev_odp_aux aux = {
            .netdev = rte_flow_data->physdev,
            .odp_port = ODPP_NONE,
        };

        /* Extract the orig_in_port from physdev as in case of modify the one
         * provided by upper layer cannot be used.
         */
        netdev_ports_traverse(rte_flow_data->physdev->dpif_type,
                              get_netdev_odp_cb, &aux);
        info->orig_in_port = aux.odp_port;
        old_stats = rte_flow_data->stats;
        modification = true;
        ret = netdev_offload_dpdk_flow_destroy(rte_flow_data);
        if (ret < 0) {
            return ret;
        }
    }

    rte_flow_data = netdev_offload_dpdk_add_flow(netdev, match, actions,
                                                 actions_len, ufid, info);
    if (!rte_flow_data) {
        return -1;
    }
    if (modification) {
        rte_flow_data->stats = old_stats;
    }
    if (stats) {
        *stats = rte_flow_data->stats;
    }
    return 0;
}

static int
netdev_offload_dpdk_flow_del(struct netdev *netdev OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats)
{
    struct ufid_to_rte_flow_data *rte_flow_data;

    rte_flow_data = ufid_to_rte_flow_data_find(ufid, true);
    if (!rte_flow_data || !rte_flow_data->rte_flow) {
        return -1;
    }

    if (stats) {
        memset(stats, 0, sizeof *stats);
    }
    return netdev_offload_dpdk_flow_destroy(rte_flow_data);
}

static int
netdev_offload_dpdk_init_flow_api(struct netdev *netdev)
{
    if (netdev_vport_is_vport_class(netdev->netdev_class)
        && !strcmp(netdev_get_dpif_type(netdev), "system")) {
        VLOG_DBG("%s: vport belongs to the system datapath. Skipping.",
                 netdev_get_name(netdev));
        return EOPNOTSUPP;
    }

    return netdev_dpdk_flow_api_supported(netdev) ? 0 : EOPNOTSUPP;
}

static int
netdev_offload_dpdk_flow_get(struct netdev *netdev,
                             struct match *match OVS_UNUSED,
                             struct nlattr **actions OVS_UNUSED,
                             const ovs_u128 *ufid,
                             struct dpif_flow_stats *stats,
                             struct dpif_flow_attrs *attrs,
                             struct ofpbuf *buf OVS_UNUSED)
{
    struct rte_flow_query_count query = { .reset = 1 };
    struct ufid_to_rte_flow_data *rte_flow_data;
    struct rte_flow_error error;
    int ret = 0;

    rte_flow_data = ufid_to_rte_flow_data_find(ufid, false);
    if (!rte_flow_data || !rte_flow_data->rte_flow) {
        ret = -1;
        goto out;
    }

    attrs->offloaded = true;
    if (!rte_flow_data->actions_offloaded) {
        attrs->dp_layer = "ovs";
        memset(stats, 0, sizeof *stats);
        goto out;
    }
    attrs->dp_layer = "dpdk";
    ret = netdev_dpdk_rte_flow_query_count(rte_flow_data->physdev,
                                           rte_flow_data->rte_flow, &query,
                                           &error);
    if (ret) {
        VLOG_DBG_RL(&rl, "%s: Failed to query ufid "UUID_FMT" flow: %p",
                    netdev_get_name(netdev), UUID_ARGS((struct uuid *) ufid),
                    rte_flow_data->rte_flow);
        goto out;
    }
    rte_flow_data->stats.n_packets += (query.hits_set) ? query.hits : 0;
    rte_flow_data->stats.n_bytes += (query.bytes_set) ? query.bytes : 0;
    if (query.hits_set && query.hits) {
        rte_flow_data->stats.used = time_msec();
    }
    memcpy(stats, &rte_flow_data->stats, sizeof *stats);
out:
    attrs->dp_extra_info = NULL;
    return ret;
}

static int
netdev_offload_dpdk_flow_flush(struct netdev *netdev)
{
    struct ufid_to_rte_flow_data *data;

    CMAP_FOR_EACH (data, node, &ufid_to_rte_flow) {
        if (data->netdev != netdev && data->physdev != netdev) {
            continue;
        }

        netdev_offload_dpdk_flow_destroy(data);
    }

    return 0;
}

struct get_vport_netdev_aux {
    struct rte_flow_tunnel *tunnel;
    odp_port_t *odp_port;
    struct netdev *vport;
};

static bool
get_vxlan_netdev_cb(struct netdev *netdev,
                    odp_port_t odp_port,
                    void *aux_)
{
    const struct netdev_tunnel_config *tnl_cfg;
    struct get_vport_netdev_aux *aux = aux_;

    if (strcmp(netdev_get_type(netdev), "vxlan")) {
        return false;
    }

    tnl_cfg = netdev_get_tunnel_config(netdev);
    if (!tnl_cfg) {
        VLOG_ERR_RL(&rl, "Cannot get a tunnel config for netdev %s",
                    netdev_get_name(netdev));
        return false;
    }

    if (tnl_cfg->dst_port == aux->tunnel->tp_dst) {
        /* Found the netdev. Store the results and stop the traversing. */
        aux->vport = netdev_ref(netdev);
        *aux->odp_port = odp_port;
        return true;
    }

    return false;
}

static struct netdev *
get_vxlan_netdev(const char *dpif_type,
                 struct rte_flow_tunnel *tunnel,
                 odp_port_t *odp_port)
{
    struct get_vport_netdev_aux aux = {
        .tunnel = tunnel,
        .odp_port = odp_port,
        .vport = NULL,
    };

    netdev_ports_traverse(dpif_type, get_vxlan_netdev_cb, &aux);
    return aux.vport;
}

static struct netdev *
get_vport_netdev(const char *dpif_type,
                 struct rte_flow_tunnel *tunnel,
                 odp_port_t *odp_port)
{
    if (tunnel->type == RTE_FLOW_ITEM_TYPE_VXLAN) {
        return get_vxlan_netdev(dpif_type, tunnel, odp_port);
    }

    OVS_NOT_REACHED();
}

static int
netdev_offload_dpdk_hw_miss_packet_recover(struct netdev *netdev,
                                           struct dp_packet *packet)
{
    struct rte_flow_restore_info rte_restore_info;
    struct rte_flow_tunnel *rte_tnl;
    struct netdev *vport_netdev;
    struct pkt_metadata *md;
    struct flow_tnl *md_tnl;
    odp_port_t vport_odp;
    int ret = 0;

    if (netdev_dpdk_rte_flow_get_restore_info(netdev, packet,
                                              &rte_restore_info, NULL)) {
        /* This function is called for every packet, and in most cases there
         * will be no restore info from the HW, thus error is expected.
         */
        return 0;
    }

    if (!(rte_restore_info.flags & RTE_FLOW_RESTORE_INFO_TUNNEL)) {
        return EOPNOTSUPP;
    }

    rte_tnl = &rte_restore_info.tunnel;
    vport_netdev = get_vport_netdev(netdev->dpif_type, rte_tnl,
                                    &vport_odp);
    if (!vport_netdev) {
        VLOG_WARN_RL(&rl, "Could not find vport netdev");
        return EOPNOTSUPP;
    }

    md = &packet->md;
    /* For tunnel recovery (RTE_FLOW_RESTORE_INFO_TUNNEL), it is possible
     * to have the packet to still be encapsulated, or not.  This is reflected
     * by the RTE_FLOW_RESTORE_INFO_ENCAPSULATED flag.
     * In the case it is on, the packet is still encapsulated, and we do
     * the pop in SW.
     * In the case it is off, the packet is already decapsulated by HW, and
     * the tunnel info is provided in the tunnel struct.  For this case we
     * take it to OVS metadata.
     */
    if (rte_restore_info.flags & RTE_FLOW_RESTORE_INFO_ENCAPSULATED) {
        if (!vport_netdev->netdev_class ||
            !vport_netdev->netdev_class->pop_header) {
            VLOG_ERR_RL(&rl, "vport nedtdev=%s with no pop_header method",
                        netdev_get_name(vport_netdev));
            ret = EOPNOTSUPP;
            goto close_vport_netdev;
        }
        parse_tcp_flags(packet);
        if (vport_netdev->netdev_class->pop_header(packet) == NULL) {
            /* If there is an error with popping the header, the packet is
             * freed. In this case it should not continue SW processing.
             */
            ret = EINVAL;
            goto close_vport_netdev;
        }
    } else {
        md_tnl = &md->tunnel;
        if (rte_tnl->is_ipv6) {
            memcpy(&md_tnl->ipv6_src, &rte_tnl->ipv6.src_addr,
                   sizeof md_tnl->ipv6_src);
            memcpy(&md_tnl->ipv6_dst, &rte_tnl->ipv6.dst_addr,
                   sizeof md_tnl->ipv6_dst);
        } else {
            md_tnl->ip_src = rte_tnl->ipv4.src_addr;
            md_tnl->ip_dst = rte_tnl->ipv4.dst_addr;
        }
        md_tnl->tun_id = htonll(rte_tnl->tun_id);
        md_tnl->flags = rte_tnl->tun_flags;
        md_tnl->ip_tos = rte_tnl->tos;
        md_tnl->ip_ttl = rte_tnl->ttl;
        md_tnl->tp_src = rte_tnl->tp_src;
    }
    /* Change the in_port to the vport's one, in order to continue packet
     * processing in SW.
     */
    md->in_port.odp_port = vport_odp;
    dp_packet_reset_offload(packet);

close_vport_netdev:
    netdev_close(vport_netdev);

    return ret;
}

const struct netdev_flow_api netdev_offload_dpdk = {
    .type = "dpdk_flow_api",
    .flow_put = netdev_offload_dpdk_flow_put,
    .flow_del = netdev_offload_dpdk_flow_del,
    .init_flow_api = netdev_offload_dpdk_init_flow_api,
    .flow_get = netdev_offload_dpdk_flow_get,
    .flow_flush = netdev_offload_dpdk_flow_flush,
    .hw_miss_packet_recover = netdev_offload_dpdk_hw_miss_packet_recover,
};
