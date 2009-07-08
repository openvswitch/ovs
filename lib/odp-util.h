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

#ifndef ODP_UTIL_H
#define ODP_UTIL_H 1

#include <stdbool.h>
#include <stdint.h>
#include "openflow/openflow.h"
#include "openvswitch/datapath-protocol.h"

struct ds;

/* The kernel datapaths limits actions to those that fit in a single page of
 * memory, so there is no point in allocating more than that.  */
enum { MAX_ODP_ACTIONS = 4096 / sizeof(union odp_action) };

struct odp_actions {
    size_t n_actions;
    union odp_action actions[MAX_ODP_ACTIONS];
};

static inline void
odp_actions_init(struct odp_actions *actions)
{
    actions->n_actions = 0;
}

union odp_action *odp_actions_add(struct odp_actions *actions, uint16_t type);

static inline bool
odp_actions_overflow(const struct odp_actions *actions)
{
    return actions->n_actions > MAX_ODP_ACTIONS;
}

static inline uint16_t
ofp_port_to_odp_port(uint16_t ofp_port)
{
    switch (ofp_port) {
    case OFPP_LOCAL:
        return ODPP_LOCAL;
    case OFPP_NONE:
        return ODPP_NONE;
    default:
        return ofp_port;
    }
}

static inline uint16_t
odp_port_to_ofp_port(uint16_t odp_port)
{
    switch (odp_port) {
    case ODPP_LOCAL:
        return OFPP_LOCAL;
    case ODPP_NONE:
        return OFPP_NONE;
    default:
        return odp_port;
    }
}

void format_odp_action(struct ds *, const union odp_action *);
void format_odp_actions(struct ds *, const union odp_action *actions,
                        size_t n_actions);
void format_odp_flow_stats(struct ds *, const struct odp_flow_stats *);
void format_odp_flow(struct ds *, const struct odp_flow *);

#endif /* odp-util.h */
