/*
 * Copyright (c) 2014 Nicira, Inc.
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

#ifndef TNL_PORT_H
#define TNL_PORT_H 1

#include <net/if.h>
#include <sys/socket.h>

#include "flow.h"
#include "packets.h"
#include "util.h"

odp_port_t tnl_port_map_lookup(struct flow *flow, struct flow_wildcards *wc);

void tnl_port_map_insert(odp_port_t, ovs_be16 tp_port,
                         const char dev_name[], const char type[]);

void tnl_port_map_delete(odp_port_t, const char type[]);
void tnl_port_map_insert_ipdev(const char dev[]);
void tnl_port_map_delete_ipdev(const char dev[]);
void tnl_port_map_run(void);

void tnl_port_map_init(void);

#endif
