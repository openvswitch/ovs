/*
 * Copyright (c) 2009, 2010, 2011 Nicira Networks.
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
#include "odp-util.h"
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "byte-order.h"
#include "coverage.h"
#include "dynamic-string.h"
#include "flow.h"
#include "netlink.h"
#include "openvswitch/tunnel.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"

int
odp_action_len(uint16_t type)
{
    if (type > ODPAT_MAX) {
        return -1;
    }

    switch ((enum odp_action_type) type) {
    case ODPAT_OUTPUT: return 4;
    case ODPAT_CONTROLLER: return 8;
    case ODPAT_SET_DL_TCI: return 2;
    case ODPAT_STRIP_VLAN: return 0;
    case ODPAT_SET_DL_SRC: return ETH_ADDR_LEN;
    case ODPAT_SET_DL_DST: return ETH_ADDR_LEN;
    case ODPAT_SET_NW_SRC: return 4;
    case ODPAT_SET_NW_DST: return 4;
    case ODPAT_SET_NW_TOS: return 1;
    case ODPAT_SET_TP_SRC: return 2;
    case ODPAT_SET_TP_DST: return 2;
    case ODPAT_SET_TUNNEL: return 8;
    case ODPAT_SET_PRIORITY: return 4;
    case ODPAT_POP_PRIORITY: return 0;
    case ODPAT_DROP_SPOOFED_ARP: return 0;

    case ODPAT_UNSPEC:
    case __ODPAT_MAX:
        return -1;
    }

    return -1;
}

static void
format_generic_odp_action(struct ds *ds, const struct nlattr *a)
{
    size_t len = nl_attr_get_size(a);

    ds_put_format(ds, "action%"PRId16, nl_attr_type(a));
    if (len) {
        const uint8_t *unspec;
        unsigned int i;

        unspec = nl_attr_get(a);
        for (i = 0; i < len; i++) {
            ds_put_char(ds, i ? ' ': '(');
            ds_put_format(ds, "%02x", unspec[i]);
        }
        ds_put_char(ds, ')');
    }
}

void
format_odp_action(struct ds *ds, const struct nlattr *a)
{
    const uint8_t *eth;
    ovs_be32 ip;

    if (nl_attr_get_size(a) != odp_action_len(nl_attr_type(a))) {
        ds_put_format(ds, "bad length %zu, expected %d for: ",
                      nl_attr_get_size(a), odp_action_len(nl_attr_type(a)));
        format_generic_odp_action(ds, a);
        return;
    }

    switch (nl_attr_type(a)) {
    case ODPAT_OUTPUT:
        ds_put_format(ds, "%"PRIu16, nl_attr_get_u32(a));
        break;
    case ODPAT_CONTROLLER:
        ds_put_format(ds, "ctl(%"PRIu64")", nl_attr_get_u64(a));
        break;
    case ODPAT_SET_TUNNEL:
        ds_put_format(ds, "set_tunnel(%#"PRIx64")",
                      ntohll(nl_attr_get_be64(a)));
        break;
    case ODPAT_SET_DL_TCI:
        ds_put_format(ds, "set_tci(vid=%"PRIu16",pcp=%d)",
                      vlan_tci_to_vid(nl_attr_get_be16(a)),
                      vlan_tci_to_pcp(nl_attr_get_be16(a)));
        break;
    case ODPAT_STRIP_VLAN:
        ds_put_format(ds, "strip_vlan");
        break;
    case ODPAT_SET_DL_SRC:
        eth = nl_attr_get_unspec(a, ETH_ADDR_LEN);
        ds_put_format(ds, "set_dl_src("ETH_ADDR_FMT")", ETH_ADDR_ARGS(eth));
        break;
    case ODPAT_SET_DL_DST:
        eth = nl_attr_get_unspec(a, ETH_ADDR_LEN);
        ds_put_format(ds, "set_dl_dst("ETH_ADDR_FMT")", ETH_ADDR_ARGS(eth));
        break;
    case ODPAT_SET_NW_SRC:
        ip = nl_attr_get_be32(a);
        ds_put_format(ds, "set_nw_src("IP_FMT")", IP_ARGS(&ip));
        break;
    case ODPAT_SET_NW_DST:
        ip = nl_attr_get_be32(a);
        ds_put_format(ds, "set_nw_dst("IP_FMT")", IP_ARGS(&ip));
        break;
    case ODPAT_SET_NW_TOS:
        ds_put_format(ds, "set_nw_tos(%"PRIu8")", nl_attr_get_u8(a));
        break;
    case ODPAT_SET_TP_SRC:
        ds_put_format(ds, "set_tp_src(%"PRIu16")", ntohs(nl_attr_get_be16(a)));
        break;
    case ODPAT_SET_TP_DST:
        ds_put_format(ds, "set_tp_dst(%"PRIu16")", ntohs(nl_attr_get_be16(a)));
        break;
    case ODPAT_SET_PRIORITY:
        ds_put_format(ds, "set_priority(%#"PRIx32")", nl_attr_get_u32(a));
        break;
    case ODPAT_POP_PRIORITY:
        ds_put_cstr(ds, "pop_priority");
        break;
    case ODPAT_DROP_SPOOFED_ARP:
        ds_put_cstr(ds, "drop_spoofed_arp");
        break;
    default:
        format_generic_odp_action(ds, a);
        break;
    }
}

void
format_odp_actions(struct ds *ds, const struct nlattr *actions,
                   size_t actions_len)
{
    if (actions_len) {
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH (a, left, actions, actions_len) {
            if (a != actions) {
                ds_put_char(ds, ',');
            }
            format_odp_action(ds, a);
        }
        if (left) {
            if (left == actions_len) {
                ds_put_cstr(ds, "<empty>");
            }
            ds_put_format(ds, ",***%u leftover bytes***", left);
        }
    } else {
        ds_put_cstr(ds, "drop");
    }
}

void
format_odp_flow_stats(struct ds *ds, const struct odp_flow_stats *s)
{
    ds_put_format(ds, "packets:%llu, bytes:%llu, used:",
                  (unsigned long long int) s->n_packets,
                  (unsigned long long int) s->n_bytes);
    if (s->used_sec) {
        long long int used = s->used_sec * 1000 + s->used_nsec / 1000000;
        ds_put_format(ds, "%.3fs", (time_msec() - used) / 1000.0);
    } else {
        ds_put_format(ds, "never");
    }
}

void
format_odp_flow(struct ds *ds, const struct odp_flow *f)
{
    odp_flow_key_format(f->key, f->key_len, ds);
    ds_put_cstr(ds, ", ");
    format_odp_flow_stats(ds, &f->stats);
    ds_put_cstr(ds, ", actions:");
    format_odp_actions(ds, f->actions, f->actions_len);
}

void
format_odp_port_type(struct ds *ds, const struct odp_port *p)
{
    if (!strcmp(p->type, "gre") 
            || !strcmp(p->type, "ipsec_gre")
            || !strcmp(p->type, "capwap")) {
        const struct tnl_port_config *config;

        config = (struct tnl_port_config *)p->config;

        ds_put_format(ds, " (%s: remote_ip="IP_FMT, 
                p->type, IP_ARGS(&config->daddr));

        if (config->saddr) {
            ds_put_format(ds, ", local_ip="IP_FMT, IP_ARGS(&config->saddr));
        }

        if (config->in_key) {
            ds_put_format(ds, ", in_key=%#"PRIx64, ntohll(config->in_key));
        }

        ds_put_cstr(ds, ")");
    } else if (!strcmp(p->type, "patch")) {
        ds_put_format(ds, " (%s: peer=%s)", p->type, (char *)p->config);
    } else if (strcmp(p->type, "system")) {
        ds_put_format(ds, " (%s)", p->type);
    }
}

/* Returns the correct length of the payload for a flow key attribute of the
 * specified 'type', or -1 if 'type' is unknown. */
static int
odp_flow_key_attr_len(uint16_t type)
{
    if (type > ODP_KEY_ATTR_MAX) {
        return -1;
    }

    switch ((enum odp_key_type) type) {
    case ODP_KEY_ATTR_TUN_ID: return 8;
    case ODP_KEY_ATTR_IN_PORT: return 4;
    case ODP_KEY_ATTR_ETHERNET: return sizeof(struct odp_key_ethernet);
    case ODP_KEY_ATTR_8021Q: return sizeof(struct odp_key_8021q);
    case ODP_KEY_ATTR_ETHERTYPE: return 2;
    case ODP_KEY_ATTR_IPV4: return sizeof(struct odp_key_ipv4);
    case ODP_KEY_ATTR_TCP: return sizeof(struct odp_key_tcp);
    case ODP_KEY_ATTR_UDP: return sizeof(struct odp_key_udp);
    case ODP_KEY_ATTR_ICMP: return sizeof(struct odp_key_icmp);
    case ODP_KEY_ATTR_ARP: return sizeof(struct odp_key_arp);

    case ODP_KEY_ATTR_UNSPEC:
    case __ODP_KEY_ATTR_MAX:
        return -1;
    }

    return -1;
}


static void
format_generic_odp_key(const struct nlattr *a, struct ds *ds)
{
    size_t len = nl_attr_get_size(a);

    ds_put_format(ds, "key%"PRId16, nl_attr_type(a));
    if (len) {
        const uint8_t *unspec;
        unsigned int i;

        unspec = nl_attr_get(a);
        for (i = 0; i < len; i++) {
            ds_put_char(ds, i ? ' ': '(');
            ds_put_format(ds, "%02x", unspec[i]);
        }
        ds_put_char(ds, ')');
    }
}

static void
format_odp_key_attr(const struct nlattr *a, struct ds *ds)
{
    const struct odp_key_ethernet *eth_key;
    const struct odp_key_8021q *q_key;
    const struct odp_key_ipv4 *ipv4_key;
    const struct odp_key_tcp *tcp_key;
    const struct odp_key_udp *udp_key;
    const struct odp_key_icmp *icmp_key;
    const struct odp_key_arp *arp_key;

    if (nl_attr_get_size(a) != odp_flow_key_attr_len(nl_attr_type(a))) {
        ds_put_format(ds, "bad length %zu, expected %d for: ",
                      nl_attr_get_size(a),
                      odp_flow_key_attr_len(nl_attr_type(a)));
        format_generic_odp_key(a, ds);
        return;
    }

    switch (nl_attr_type(a)) {
    case ODP_KEY_ATTR_TUN_ID:
        ds_put_format(ds, "tun_id(%#"PRIx64")", nl_attr_get_be64(a));
        break;

    case ODP_KEY_ATTR_IN_PORT:
        ds_put_format(ds, "in_port(%"PRIu32")", nl_attr_get_u32(a));
        break;

    case ODP_KEY_ATTR_ETHERNET:
        eth_key = nl_attr_get(a);
        ds_put_format(ds, "eth(src="ETH_ADDR_FMT",dst="ETH_ADDR_FMT")",
                      ETH_ADDR_ARGS(eth_key->eth_src),
                      ETH_ADDR_ARGS(eth_key->eth_dst));
        break;

    case ODP_KEY_ATTR_8021Q:
        q_key = nl_attr_get(a);
        ds_put_cstr(ds, "vlan(");
        if (q_key->q_tpid != htons(ETH_TYPE_VLAN)) {
            ds_put_format(ds, "tpid=%#"PRIx16",", ntohs(q_key->q_tpid));
        }
        ds_put_format(ds, "vid%"PRIu16",pcp%d)",
                      vlan_tci_to_vid(q_key->q_tci),
                      vlan_tci_to_pcp(q_key->q_tci));
        break;

    case ODP_KEY_ATTR_ETHERTYPE:
        ds_put_format(ds, "eth_type(%#04"PRIx16")",
                      ntohs(nl_attr_get_be16(a)));
        break;

    case ODP_KEY_ATTR_IPV4:
        ipv4_key = nl_attr_get(a);
        ds_put_format(ds, "ipv4(src="IP_FMT",dst="IP_FMT","
                      "proto=%"PRId8",tos=%"PRIu8")",
                      IP_ARGS(&ipv4_key->ipv4_src),
                      IP_ARGS(&ipv4_key->ipv4_dst),
                      ipv4_key->ipv4_proto, ipv4_key->ipv4_tos);
        break;

    case ODP_KEY_ATTR_TCP:
        tcp_key = nl_attr_get(a);
        ds_put_format(ds, "tcp(src=%"PRIu16",dst=%"PRIu16")",
                      ntohs(tcp_key->tcp_src), ntohs(tcp_key->tcp_dst));
        break;

    case ODP_KEY_ATTR_UDP:
        udp_key = nl_attr_get(a);
        ds_put_format(ds, "udp(src=%"PRIu16",dst=%"PRIu16")",
                      ntohs(udp_key->udp_src), ntohs(udp_key->udp_dst));
        break;

    case ODP_KEY_ATTR_ICMP:
        icmp_key = nl_attr_get(a);
        ds_put_format(ds, "icmp(type=%"PRIu8",code=%"PRIu8")",
                      icmp_key->icmp_type, icmp_key->icmp_code);
        break;

    case ODP_KEY_ATTR_ARP:
        arp_key = nl_attr_get(a);
        ds_put_format(ds, "arp(sip="IP_FMT",tip="IP_FMT",op=%"PRIu16")",
                      IP_ARGS(&arp_key->arp_sip), IP_ARGS(&arp_key->arp_tip),
                      ntohs(arp_key->arp_op));
        break;

    default:
        format_generic_odp_key(a, ds);
        break;
    }
}

/* Appends to 'ds' a string representation of the 'key_len' bytes of
 * ODP_KEY_ATTR_* attributes in 'key'. */
void
odp_flow_key_format(const struct nlattr *key, size_t key_len, struct ds *ds)
{
    if (key_len) {
        const struct nlattr *a;
        unsigned int left;

        NL_ATTR_FOR_EACH (a, left, key, key_len) {
            if (a != key) {
                ds_put_char(ds, ',');
            }
            format_odp_key_attr(a, ds);
        }
        if (left) {
            if (left == key_len) {
                ds_put_cstr(ds, "<empty>");
            }
            ds_put_format(ds, ",***%u leftover bytes***", left);
        }
    } else {
        ds_put_cstr(ds, "<empty>");
    }
}

/* Appends a representation of 'flow' as ODP_KEY_ATTR_* attributes to 'buf'. */
void
odp_flow_key_from_flow(struct ofpbuf *buf, const struct flow *flow)
{
    struct odp_key_ethernet *eth_key;

    if (flow->tun_id != htonll(0)) {
        nl_msg_put_be64(buf, ODP_KEY_ATTR_TUN_ID, flow->tun_id);
    }

    nl_msg_put_u32(buf, ODP_KEY_ATTR_IN_PORT, flow->in_port);

    eth_key = nl_msg_put_unspec_uninit(buf, ODP_KEY_ATTR_ETHERNET,
                                       sizeof *eth_key);
    memcpy(eth_key->eth_src, flow->dl_src, ETH_ADDR_LEN);
    memcpy(eth_key->eth_dst, flow->dl_dst, ETH_ADDR_LEN);

    if (flow->vlan_tci != htons(0)) {
        struct odp_key_8021q *q_key;

        q_key = nl_msg_put_unspec_uninit(buf, ODP_KEY_ATTR_8021Q,
                                         sizeof *q_key);
        q_key->q_tpid = htons(ETH_TYPE_VLAN);
        q_key->q_tci = flow->vlan_tci & ~htons(VLAN_CFI);
    }

    if (ntohs(flow->dl_type) < ETH_TYPE_MIN) {
        return;
    }

    nl_msg_put_be16(buf, ODP_KEY_ATTR_ETHERTYPE, flow->dl_type);

    if (flow->dl_type == htons(ETH_TYPE_IP)) {
        struct odp_key_ipv4 *ipv4_key;

        ipv4_key = nl_msg_put_unspec_uninit(buf, ODP_KEY_ATTR_IPV4,
                                            sizeof *ipv4_key);
        ipv4_key->ipv4_src = flow->nw_src;
        ipv4_key->ipv4_dst = flow->nw_dst;
        ipv4_key->ipv4_proto = flow->nw_proto;
        ipv4_key->ipv4_tos = flow->nw_tos;

        if (flow->nw_proto == IP_TYPE_TCP) {
            struct odp_key_tcp *tcp_key;

            tcp_key = nl_msg_put_unspec_uninit(buf, ODP_KEY_ATTR_TCP,
                                               sizeof *tcp_key);
            tcp_key->tcp_src = flow->tp_src;
            tcp_key->tcp_dst = flow->tp_dst;
        } else if (flow->nw_proto == IP_TYPE_UDP) {
            struct odp_key_udp *udp_key;

            udp_key = nl_msg_put_unspec_uninit(buf, ODP_KEY_ATTR_UDP,
                                               sizeof *udp_key);
            udp_key->udp_src = flow->tp_src;
            udp_key->udp_dst = flow->tp_dst;
        } else if (flow->nw_proto == IP_TYPE_ICMP) {
            struct odp_key_icmp *icmp_key;

            icmp_key = nl_msg_put_unspec_uninit(buf, ODP_KEY_ATTR_ICMP,
                                                sizeof *icmp_key);
            icmp_key->icmp_type = ntohs(flow->tp_src);
            icmp_key->icmp_code = ntohs(flow->tp_dst);
        }
    } else if (flow->dl_type == htons(ETH_TYPE_ARP)) {
        struct odp_key_arp *arp_key;

        arp_key = nl_msg_put_unspec_uninit(buf, ODP_KEY_ATTR_ARP,
                                           sizeof *arp_key);
        arp_key->arp_sip = flow->nw_src;
        arp_key->arp_tip = flow->nw_dst;
        arp_key->arp_op = htons(flow->nw_proto);
    }
}

/* Converts the 'key_len' bytes of ODP_KEY_ATTR_* attributes in 'key' to a flow
 * structure in 'flow'.  Returns 0 if successful, otherwise EINVAL. */
int
odp_flow_key_to_flow(const struct nlattr *key, size_t key_len,
                     struct flow *flow)
{
    const struct nlattr *nla;
    enum odp_key_type prev_type;
    size_t left;

    memset(flow, 0, sizeof *flow);
    flow->dl_type = htons(FLOW_DL_TYPE_NONE);

    prev_type = ODP_KEY_ATTR_UNSPEC;
    NL_ATTR_FOR_EACH (nla, left, key, key_len) {
        const struct odp_key_ethernet *eth_key;
        const struct odp_key_8021q *q_key;
        const struct odp_key_ipv4 *ipv4_key;
        const struct odp_key_tcp *tcp_key;
        const struct odp_key_udp *udp_key;
        const struct odp_key_icmp *icmp_key;
        const struct odp_key_arp *arp_key;

        uint16_t type = nl_attr_type(nla);
        int len = odp_flow_key_attr_len(type);

        if (nl_attr_get_size(nla) != len && len != -1) {
            return EINVAL;
        }

#define TRANSITION(PREV_TYPE, TYPE) (((PREV_TYPE) << 16) | (TYPE))
        switch (TRANSITION(prev_type, type)) {
        case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_TUN_ID):
            flow->tun_id = nl_attr_get_be64(nla);
            break;

        case TRANSITION(ODP_KEY_ATTR_UNSPEC, ODP_KEY_ATTR_IN_PORT):
        case TRANSITION(ODP_KEY_ATTR_TUN_ID, ODP_KEY_ATTR_IN_PORT):
            if (nl_attr_get_u32(nla) >= UINT16_MAX) {
                return EINVAL;
            }
            flow->in_port = nl_attr_get_u32(nla);
            break;

        case TRANSITION(ODP_KEY_ATTR_IN_PORT, ODP_KEY_ATTR_ETHERNET):
            eth_key = nl_attr_get(nla);
            memcpy(flow->dl_src, eth_key->eth_src, ETH_ADDR_LEN);
            memcpy(flow->dl_dst, eth_key->eth_dst, ETH_ADDR_LEN);
            break;

        case TRANSITION(ODP_KEY_ATTR_ETHERNET, ODP_KEY_ATTR_8021Q):
            q_key = nl_attr_get(nla);
            if (q_key->q_tpid != htons(ETH_TYPE_VLAN)) {
                /* Only standard 0x8100 VLANs currently supported. */
                return EINVAL;
            }
            if (q_key->q_tci & htons(VLAN_CFI)) {
                return EINVAL;
            }
            flow->vlan_tci = q_key->q_tci | htons(VLAN_CFI);
            break;

        case TRANSITION(ODP_KEY_ATTR_8021Q, ODP_KEY_ATTR_ETHERTYPE):
        case TRANSITION(ODP_KEY_ATTR_ETHERNET, ODP_KEY_ATTR_ETHERTYPE):
            flow->dl_type = nl_attr_get_be16(nla);
            if (ntohs(flow->dl_type) < 1536) {
                return EINVAL;
            }
            break;

        case TRANSITION(ODP_KEY_ATTR_ETHERTYPE, ODP_KEY_ATTR_IPV4):
            if (flow->dl_type != htons(ETH_TYPE_IP)) {
                return EINVAL;
            }
            ipv4_key = nl_attr_get(nla);
            flow->nw_src = ipv4_key->ipv4_src;
            flow->nw_dst = ipv4_key->ipv4_dst;
            flow->nw_proto = ipv4_key->ipv4_proto;
            flow->nw_tos = ipv4_key->ipv4_tos;
            if (flow->nw_tos & IP_ECN_MASK) {
                return EINVAL;
            }
            break;

        case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_TCP):
            if (flow->nw_proto != IP_TYPE_TCP) {
                return EINVAL;
            }
            tcp_key = nl_attr_get(nla);
            flow->tp_src = tcp_key->tcp_src;
            flow->tp_dst = tcp_key->tcp_dst;
            break;

        case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_UDP):
            if (flow->nw_proto != IP_TYPE_UDP) {
                return EINVAL;
            }
            udp_key = nl_attr_get(nla);
            flow->tp_src = udp_key->udp_src;
            flow->tp_dst = udp_key->udp_dst;
            break;

        case TRANSITION(ODP_KEY_ATTR_IPV4, ODP_KEY_ATTR_ICMP):
            if (flow->nw_proto != IP_TYPE_ICMP) {
                return EINVAL;
            }
            icmp_key = nl_attr_get(nla);
            flow->tp_src = htons(icmp_key->icmp_type);
            flow->tp_dst = htons(icmp_key->icmp_code);
            break;

        case TRANSITION(ODP_KEY_ATTR_ETHERTYPE, ODP_KEY_ATTR_ARP):
            if (flow->dl_type != htons(ETH_TYPE_ARP)) {
                return EINVAL;
            }
            arp_key = nl_attr_get(nla);
            flow->nw_src = arp_key->arp_sip;
            flow->nw_dst = arp_key->arp_tip;
            if (arp_key->arp_op & htons(0xff00)) {
                return EINVAL;
            }
            flow->nw_proto = ntohs(arp_key->arp_op);
            break;

        default:
            if (type == ODP_KEY_ATTR_UNSPEC
                || prev_type == ODP_KEY_ATTR_UNSPEC) {
                return EINVAL;
            }
            return EINVAL;
        }

        prev_type = type;
    }
    if (left) {
        return EINVAL;
    }

    switch (prev_type) {
    case ODP_KEY_ATTR_UNSPEC:
        return EINVAL;

    case ODP_KEY_ATTR_TUN_ID:
    case ODP_KEY_ATTR_IN_PORT:
        return EINVAL;

    case ODP_KEY_ATTR_ETHERNET:
    case ODP_KEY_ATTR_8021Q:
        return 0;

    case ODP_KEY_ATTR_ETHERTYPE:
        if (flow->dl_type == htons(ETH_TYPE_IP)
            || flow->dl_type == htons(ETH_TYPE_ARP)) {
            return EINVAL;
        }
        return 0;

    case ODP_KEY_ATTR_IPV4:
        if (flow->nw_proto == IP_TYPE_TCP
            || flow->nw_proto == IP_TYPE_UDP
            || flow->nw_proto == IP_TYPE_ICMP) {
            return EINVAL;
        }
        return 0;

    case ODP_KEY_ATTR_TCP:
    case ODP_KEY_ATTR_UDP:
    case ODP_KEY_ATTR_ICMP:
    case ODP_KEY_ATTR_ARP:
        return 0;

    case __ODP_KEY_ATTR_MAX:
    default:
        NOT_REACHED();
    }
}
