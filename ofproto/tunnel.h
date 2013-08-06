/* Copyright (c) 2013 Nicira, Inc.
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

#ifndef TUNNEL_H
#define TUNNEL_H 1

#include <stdbool.h>
#include <stdint.h>
#include "flow.h"

/* Tunnel port emulation layer.
 *
 * These functions emulate tunnel virtual ports based on the outer
 * header information from the kernel. */

struct ofport_dpif;
struct netdev;

bool tnl_port_reconfigure(const struct ofport_dpif *, const struct netdev *,
                          odp_port_t);

void tnl_port_add(const struct ofport_dpif *, const struct netdev *,
                  odp_port_t odp_port);
void tnl_port_del(const struct ofport_dpif *);

const struct ofport_dpif *tnl_port_receive(const struct flow *);
bool tnl_xlate_init(const struct flow *base_flow, struct flow *flow,
                    struct flow_wildcards *);
odp_port_t tnl_port_send(const struct ofport_dpif *, struct flow *,
                         struct flow_wildcards *wc);

/* Returns true if 'flow' should be submitted to tnl_port_receive(). */
static inline bool
tnl_port_should_receive(const struct flow *flow)
{
    return flow->tunnel.ip_dst != 0;
}

#endif /* tunnel.h */
