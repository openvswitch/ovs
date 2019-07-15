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

#ifndef OVN_MCAST_GROUP_INDEX_H
#define OVN_MCAST_GROUP_INDEX_H 1

struct ovsdb_idl;

struct sbrec_datapath_binding;

#define OVN_MCAST_FLOOD_TUNNEL_KEY   65535
#define OVN_MCAST_UNKNOWN_TUNNEL_KEY (OVN_MCAST_FLOOD_TUNNEL_KEY - 1)

struct ovsdb_idl_index *mcast_group_index_create(struct ovsdb_idl *);
const struct sbrec_multicast_group *
mcast_group_lookup(struct ovsdb_idl_index *mcgroup_index,
                   const char *name,
                   const struct sbrec_datapath_binding *datapath);

#endif /* ovn/lib/mcast-group-index.h */
