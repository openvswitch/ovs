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

#ifndef TNL_NEIGH_CACHE_H
#define TNL_NEIGH_CACHE_H 1

#include <errno.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <net/if.h>
#include <sys/socket.h>

#include "flow.h"
#include "netdev.h"
#include "packets.h"
#include "util.h"

int tnl_neigh_snoop(const struct flow *flow, struct flow_wildcards *wc,
                    const char dev_name[IFNAMSIZ]);
int tnl_neigh_lookup(const char dev_name[IFNAMSIZ], const struct in6_addr *dst,
                     struct eth_addr *mac);
void tnl_neigh_cache_init(void);
void tnl_neigh_cache_run(void);
void tnl_neigh_flush(const char dev_name[IFNAMSIZ]);

#endif
