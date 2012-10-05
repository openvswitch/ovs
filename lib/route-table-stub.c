/* Copyright (c) 2012 Nicira, Inc.
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
#include "route-table.h"

#include "compiler.h"

bool
route_table_get_name(ovs_be32 ip OVS_UNUSED, char name[IFNAMSIZ] OVS_UNUSED)
{
    name[0] = '\0';
    return false;
}

bool
route_table_get_ifindex(ovs_be32 ip OVS_UNUSED, int *ifindex)
{
    *ifindex = 0;
    return false;
}

void
route_table_register(void)
{
}

void
route_table_unregister(void)
{
}

void
route_table_run(void)
{
}
