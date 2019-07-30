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

#ifndef OVN_IP_MCAST_INDEX_H
#define OVN_IP_MCAST_INDEX_H 1

struct ovsdb_idl;

struct sbrec_datapath_binding;

#define OVN_MCAST_MIN_IDLE_TIMEOUT_S           15
#define OVN_MCAST_MAX_IDLE_TIMEOUT_S           3600
#define OVN_MCAST_DEFAULT_IDLE_TIMEOUT_S       300
#define OVN_MCAST_MIN_QUERY_INTERVAL_S         1
#define OVN_MCAST_MAX_QUERY_INTERVAL_S         OVN_MCAST_MAX_IDLE_TIMEOUT_S
#define OVN_MCAST_DEFAULT_QUERY_MAX_RESPONSE_S 1
#define OVN_MCAST_DEFAULT_MAX_ENTRIES          2048

struct ovsdb_idl_index *ip_mcast_index_create(struct ovsdb_idl *);
const struct sbrec_ip_multicast *ip_mcast_lookup(
    struct ovsdb_idl_index *ip_mcast_index,
    const struct sbrec_datapath_binding *datapath);

#endif /* ovn/lib/ip-mcast-index.h */
