/*
 * Copyright (c) 2011, 2012, 2013, 2014 Nicira, Inc.
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

#ifndef ROUTE_TABLE_H
#define ROUTE_TABLE_H 1

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "openvswitch/types.h"

uint64_t route_table_get_change_seq(void);
void route_table_init(void);
void route_table_run(void);
void route_table_wait(void);
bool route_table_fallback_lookup(const struct in6_addr *ip6_dst,
                                 char name[],
                                 struct in6_addr *gw6);
#endif /* route-table.h */
