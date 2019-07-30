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

#ifndef OVN_IP_MCAST_H
#define OVN_IP_MCAST_H 1

#include "mcast-snooping.h"

struct ovsdb_idl;
struct ovsdb_idl_txn;

struct sbrec_chassis;
struct sbrec_datapath_binding;

struct ovsdb_idl_index *igmp_group_index_create(struct ovsdb_idl *);
const struct sbrec_igmp_group *igmp_group_lookup(
    struct ovsdb_idl_index *igmp_groups,
    const struct in6_addr *address,
    const struct sbrec_datapath_binding *datapath,
    const struct sbrec_chassis *chassis);

struct sbrec_igmp_group *igmp_group_create(
    struct ovsdb_idl_txn *idl_txn,
    const struct in6_addr *address,
    const struct sbrec_datapath_binding *datapath,
    const struct sbrec_chassis *chassis);

void igmp_group_update_ports(const struct sbrec_igmp_group *g,
                             struct ovsdb_idl_index *datapaths,
                             struct ovsdb_idl_index *port_bindings,
                             const struct mcast_snooping *ms,
                             const struct mcast_group *mc_group)
    OVS_REQ_RDLOCK(ms->rwlock);

void igmp_group_delete(const struct sbrec_igmp_group *g);

bool igmp_group_cleanup(struct ovsdb_idl_txn *ovnsb_idl_txn,
                        struct ovsdb_idl_index *igmp_groups);

#endif /* ovn/controller/ip-mcast.h */
