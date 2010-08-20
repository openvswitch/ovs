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

#ifndef XFLOW_UTIL_H
#define XFLOW_UTIL_H 1

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "hash.h"
#include "openflow/openflow.h"
#include "openvswitch/xflow.h"
#include "util.h"

struct ds;
struct flow;

/* The kernel datapaths limits actions to those that fit in a single page of
 * memory, so there is no point in allocating more than that.  */
enum { MAX_XFLOW_ACTIONS = 4096 / sizeof(union xflow_action) };

struct xflow_actions {
    size_t n_actions;
    union xflow_action actions[MAX_XFLOW_ACTIONS];
};

/* xflow_actions_add() assumes that MAX_XFLOW_ACTIONS is a power of 2. */
BUILD_ASSERT_DECL(IS_POW2(MAX_XFLOW_ACTIONS));

static inline void
xflow_actions_init(struct xflow_actions *actions)
{
    actions->n_actions = 0;
}

union xflow_action *xflow_actions_add(struct xflow_actions *actions, uint16_t type);

static inline bool
xflow_actions_overflow(const struct xflow_actions *actions)
{
    return actions->n_actions > MAX_XFLOW_ACTIONS;
}

static inline uint16_t
ofp_port_to_xflow_port(uint16_t ofp_port)
{
    switch (ofp_port) {
    case OFPP_LOCAL:
        return XFLOWP_LOCAL;
    case OFPP_NONE:
        return XFLOWP_NONE;
    default:
        return ofp_port;
    }
}

static inline uint16_t
xflow_port_to_ofp_port(uint16_t xflow_port)
{
    switch (xflow_port) {
    case XFLOWP_LOCAL:
        return OFPP_LOCAL;
    case XFLOWP_NONE:
        return OFPP_NONE;
    default:
        return xflow_port;
    }
}

void format_xflow_key(struct ds *, const struct xflow_key *);
void format_xflow_action(struct ds *, const union xflow_action *);
void format_xflow_actions(struct ds *, const union xflow_action *actions,
                        size_t n_actions);
void format_xflow_flow_stats(struct ds *, const struct xflow_flow_stats *);
void format_xflow_flow(struct ds *, const struct xflow_flow *);

void xflow_key_from_flow(struct xflow_key *, const struct flow *);
void xflow_key_to_flow(const struct xflow_key *, struct flow *);

static inline bool
xflow_key_equal(const struct xflow_key *a, const struct xflow_key *b)
{
    return !memcmp(a, b, sizeof *a);
}

static inline size_t
xflow_key_hash(const struct xflow_key *flow, uint32_t basis)
{
    BUILD_ASSERT_DECL(!(sizeof *flow % sizeof(uint32_t)));
    return hash_words((const uint32_t *) flow,
                      sizeof *flow / sizeof(uint32_t), basis);
}

#endif /* xflow-util.h */
