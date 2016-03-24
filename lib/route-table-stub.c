/* Copyright (c) 2012, 2013, 2014 Nicira, Inc.
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
 * limitations under the License. */

#include <config.h>

#include "compiler.h"
#include "ovs-router.h"
#include "route-table.h"

bool
route_table_fallback_lookup(const struct in6_addr *ip6_dst OVS_UNUSED,
                            char name[] OVS_UNUSED,
                            struct in6_addr *gw6)
{
    *gw6 = in6addr_any;
    return false;
}

uint64_t
route_table_get_change_seq(void)
{
    return 0;
}

void
route_table_init(void)
{
    ovs_router_init();
}

void
route_table_run(void)
{
}

void
route_table_wait(void)
{
}
