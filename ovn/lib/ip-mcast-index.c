/* Copyright (c) 2019, Red Hat, Inc.
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

#include <config.h>

#include "ovn/lib/ip-mcast-index.h"
#include "ovn/lib/ovn-sb-idl.h"

struct ovsdb_idl_index *
ip_mcast_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create1(idl, &sbrec_ip_multicast_col_datapath);
}

const struct sbrec_ip_multicast *
ip_mcast_lookup(struct ovsdb_idl_index *ip_mcast_index,
                const struct sbrec_datapath_binding *datapath)
{
    struct sbrec_ip_multicast *target =
        sbrec_ip_multicast_index_init_row(ip_mcast_index);
    sbrec_ip_multicast_index_set_datapath(target, datapath);

    struct sbrec_ip_multicast *ip_mcast =
        sbrec_ip_multicast_index_find(ip_mcast_index, target);
    sbrec_ip_multicast_index_destroy_row(target);

    return ip_mcast;
}
