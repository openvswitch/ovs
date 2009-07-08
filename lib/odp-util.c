/*
 * Copyright (c) 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
    if (actions->n_actions < MAX_ODP_ACTIONS) {
        a = &actions->actions[actions->n_actions++];
    } else {
        COVERAGE_INC(odp_overflow);
        actions->n_actions = MAX_ODP_ACTIONS + 1;
        a = &actions->actions[MAX_ODP_ACTIONS - 1];
    }
    memset(a, 0, sizeof *a);
    a->type = type;
    return a;
}

void
format_odp_action(struct ds *ds, const union odp_action *a)
{
    switch (a->type) {
    case ODPAT_OUTPUT:
        ds_put_format(ds, "%"PRIu16, a->output.port);
        break;
    case ODPAT_OUTPUT_GROUP:
        ds_put_format(ds, "g%"PRIu16, a->output_group.group);
        break;
    case ODPAT_CONTROLLER:
        ds_put_format(ds, "ctl(%"PRIu32")", a->controller.arg);
        break;
    case ODPAT_SET_VLAN_VID:
        ds_put_format(ds, "set_vlan(%"PRIu16")", ntohs(a->vlan_vid.vlan_vid));
        break;
    case ODPAT_SET_VLAN_PCP:
        ds_put_format(ds, "set_vlan_pcp(%"PRIu8")", a->vlan_pcp.vlan_pcp);
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
    case ODPAT_SET_TP_SRC:
        ds_put_format(ds, "set_tp_src(%"PRIu16")", ntohs(a->tp_port.tp_port));
        break;
    case ODPAT_SET_TP_DST:
        ds_put_format(ds, "set_tp_dst(%"PRIu16")", ntohs(a->tp_port.tp_port));
        break;
    default:
        ds_put_format(ds, "***bad action %"PRIu16"***", a->type);
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
    ds_put_format(ds, "packets:%"PRIu64", bytes:%"PRIu64", used:",
                  s->n_packets, s->n_bytes);
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
    flow_format(ds, &f->key);
    ds_put_cstr(ds, ", ");
    format_odp_flow_stats(ds, &f->stats);
    ds_put_cstr(ds, ", actions:");
    format_odp_actions(ds, f->actions, f->n_actions);
}

