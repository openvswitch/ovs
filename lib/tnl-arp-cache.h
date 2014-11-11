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

#ifndef TNL_ARP_CACHE_H
#define TNL_ARP_CACHE_H 1

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

int tnl_arp_snoop(const struct flow *flow, struct flow_wildcards *wc,
                  const char dev_name[]);
int tnl_arp_lookup(const char dev_name[], ovs_be32 dst, uint8_t mac[ETH_ADDR_LEN]);
void tnl_arp_cache_init(void);
void tnl_arp_cache_run(void);

#endif
