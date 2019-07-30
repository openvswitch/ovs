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

#include "ovn/lib/mcast-group-index.h"
#include "ovn/lib/ovn-sb-idl.h"

struct ovsdb_idl_index *
mcast_group_index_create(struct ovsdb_idl *idl)
{
    return ovsdb_idl_index_create2(idl, &sbrec_multicast_group_col_name,
                                   &sbrec_multicast_group_col_datapath);
}

const struct sbrec_multicast_group *
mcast_group_lookup(struct ovsdb_idl_index *mcgroup_index,
                   const char *name,
                   const struct sbrec_datapath_binding *datapath)
{
    struct sbrec_multicast_group *target =
        sbrec_multicast_group_index_init_row(mcgroup_index);
    sbrec_multicast_group_index_set_name(target, name);
    sbrec_multicast_group_index_set_datapath(target, datapath);

    struct sbrec_multicast_group *mcgroup =
        sbrec_multicast_group_index_find(mcgroup_index, target);
    sbrec_multicast_group_index_destroy_row(target);

    return mcgroup;
}
