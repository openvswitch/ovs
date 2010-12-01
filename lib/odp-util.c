/*
 * Copyright (c) 2009, 2010 Nicira Networks.
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
#include "coverage.h"
#include "dynamic-string.h"
#include "flow.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"

union odp_action *
odp_actions_add(struct odp_actions *actions, uint16_t type)
{
    union odp_action *a;
    size_t idx;

    idx = actions->n_actions++ & (MAX_ODP_ACTIONS - 1);
    a = &actions->actions[idx];
    memset(a, 0, sizeof *a);
    a->type = type;
    return a;
}

void
format_odp_flow_key(struct ds *ds, const struct odp_flow_key *key)
{
    ds_put_format(ds, "tun_id%#"PRIx32" in_port%d tci(",
                  ntohl(key->tun_id), key->in_port);
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

void
format_odp_action(struct ds *ds, const union odp_action *a)
{
    switch (a->type) {
    case ODPAT_OUTPUT:
        ds_put_format(ds, "%"PRIu16, a->output.port);
        break;
    case ODPAT_CONTROLLER:
        ds_put_format(ds, "ctl(%"PRIu32")", a->controller.arg);
        break;
    case ODPAT_SET_TUNNEL:
        ds_put_format(ds, "set_tunnel(%#"PRIx32")", ntohl(a->tunnel.tun_id));
        break;
    case ODPAT_SET_DL_TCI:
        ds_put_format(ds, "set_tci(vid=%"PRIu16",pcp=%d)",
                      vlan_tci_to_vid(a->dl_tci.tci),
                      vlan_tci_to_pcp(a->dl_tci.tci));
        break;
    case ODPAT_STRIP_VLAN:
        ds_put_format(ds, "strip_vlan");
        break;
    case ODPAT_SET_DL_SRC:
        ds_put_format(ds, "set_dl_src("ETH_ADDR_FMT")",
               ETH_ADDR_ARGS(a->dl_addr.dl_addr));
        break;
    case ODPAT_SET_DL_DST:
        ds_put_format(ds, "set_dl_dst("ETH_ADDR_FMT")",
               ETH_ADDR_ARGS(a->dl_addr.dl_addr));
        break;
    case ODPAT_SET_NW_SRC:
        ds_put_format(ds, "set_nw_src("IP_FMT")",
                      IP_ARGS(&a->nw_addr.nw_addr));
        break;
    case ODPAT_SET_NW_DST:
        ds_put_format(ds, "set_nw_dst("IP_FMT")",
                      IP_ARGS(&a->nw_addr.nw_addr));
        break;
    case ODPAT_SET_NW_TOS:
        ds_put_format(ds, "set_nw_tos(%"PRIu8")", a->nw_tos.nw_tos);
        break;
    case ODPAT_SET_TP_SRC:
        ds_put_format(ds, "set_tp_src(%"PRIu16")", ntohs(a->tp_port.tp_port));
        break;
    case ODPAT_SET_TP_DST:
        ds_put_format(ds, "set_tp_dst(%"PRIu16")", ntohs(a->tp_port.tp_port));
        break;
    case ODPAT_SET_PRIORITY:
        ds_put_format(ds, "set_priority(0x%"PRIx32")", a->priority.priority);
        break;
    case ODPAT_POP_PRIORITY:
        ds_put_cstr(ds, "pop_priority");
        break;
    case ODPAT_DROP_SPOOFED_ARP:
        ds_put_cstr(ds, "drop_spoofed_arp");
        break;
    default:
        ds_put_format(ds, "***bad action 0x%"PRIx16"***", a->type);
        break;
    }
}

void
format_odp_actions(struct ds *ds, const union odp_action *actions,
                   size_t n_actions)
{
    size_t i;
    for (i = 0; i < n_actions; i++) {
        if (i) {
            ds_put_char(ds, ',');
        }
        format_odp_action(ds, &actions[i]);
    }
    if (!n_actions) {
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
    format_odp_actions(ds, f->actions, f->n_actions);
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
