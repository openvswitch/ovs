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

void
format_odp_flow_key(struct ds *ds, const struct odp_flow_key *key)
{
    ds_put_format(ds, "tun_id%#"PRIx64" in_port%d tci(",
                  ntohll(key->tun_id), key->in_port);
    if (key->dl_tci) {
        ds_put_format(ds, "vlan%"PRIu16",pcp%d",
                      vlan_tci_to_vid(key->dl_tci),
                      vlan_tci_to_pcp(key->dl_tci));
    } else {
        ds_put_char(ds, '0');
    }
    ds_put_format(ds, ") mac"ETH_ADDR_FMT"->"ETH_ADDR_FMT" type%04x "
                  "proto%"PRId8" tos%"PRIu8" ip"IP_FMT"->"IP_FMT" port%d->%d",
                  ETH_ADDR_ARGS(key->dl_src), ETH_ADDR_ARGS(key->dl_dst),
                  ntohs(key->dl_type), key->nw_proto, key->nw_tos,
                  IP_ARGS(&key->nw_src), IP_ARGS(&key->nw_dst),
                  ntohs(key->tp_src), ntohs(key->tp_dst));
}

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
            ds_put_format(ds, " ***%u leftover bytes***", left);
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
    format_odp_flow_key(ds, &f->key);
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

void
odp_flow_key_from_flow(struct odp_flow_key *key, const struct flow *flow)
{
    key->tun_id = flow->tun_id;
    key->nw_src = flow->nw_src;
    key->nw_dst = flow->nw_dst;
    key->in_port = flow->in_port;
    key->dl_tci = flow->vlan_tci;
    key->dl_type = flow->dl_type;
    key->tp_src = flow->tp_src;
    key->tp_dst = flow->tp_dst;
    memcpy(key->dl_src, flow->dl_src, ETH_ADDR_LEN);
    memcpy(key->dl_dst, flow->dl_dst, ETH_ADDR_LEN);
    key->nw_proto = flow->nw_proto;
    key->nw_tos = flow->nw_tos;
}

void
odp_flow_key_to_flow(const struct odp_flow_key *key, struct flow *flow)
{
    memset(flow->regs, 0, sizeof flow->regs);
    flow->tun_id = key->tun_id;
    flow->nw_src = key->nw_src;
    flow->nw_dst = key->nw_dst;
    flow->in_port = key->in_port;
    flow->vlan_tci = key->dl_tci;
    flow->dl_type = key->dl_type;
    flow->tp_src = key->tp_src;
    flow->tp_dst = key->tp_dst;
    memcpy(flow->dl_src, key->dl_src, ETH_ADDR_LEN);
    memcpy(flow->dl_dst, key->dl_dst, ETH_ADDR_LEN);
    flow->nw_proto = key->nw_proto;
    flow->nw_tos = key->nw_tos;
}
