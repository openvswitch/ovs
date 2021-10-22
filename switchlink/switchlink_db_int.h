/*
Copyright 2013-present Barefoot Networks, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef __SWITCHLINK_DB_INT_H__
#define __SWITCHLINK_DB_INT_H__

#define min(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a > _b ? _a : _b;      \
  })

typedef struct switchlink_db_intf_obj_ {
  tommy_trie_inplace_node ifindex_node;
  tommy_trie_inplace_node handle_node;
  uint32_t ifindex;
  switchlink_db_interface_info_t intf_info;
} switchlink_db_intf_obj_t;

typedef struct switchlink_db_tuntap_obj_ {
  tommy_trie_inplace_node ifindex_node;
  tommy_trie_inplace_node handle_node;
  uint32_t ifindex;
  switchlink_db_tuntap_info_t tunp_info;
} switchlink_db_tuntap_obj_t;

typedef struct switchlink_db_bridge_obj_ {
  tommy_trie_inplace_node ifindex_node;
  tommy_trie_inplace_node handle_node;
  uint32_t ifindex;
  switchlink_db_bridge_info_t bridge;
} switchlink_db_bridge_obj_t;

typedef struct switchlink_db_mac_obj_ {
  tommy_node hash_node;
  tommy_node list_node;
  switchlink_mac_addr_t addr;
  switchlink_handle_t bridge_h;
  switchlink_handle_t intf_h;
} switchlink_db_mac_obj_t;

typedef struct switchlink_db_neigh_obj_ {
  tommy_node list_node;
  switchlink_db_neigh_info_t neigh_info;
} switchlink_db_neigh_obj_t;

typedef struct switchlink_db_ecmp_obj_ {
  tommy_node list_node;
  int32_t ref_count;
  tommy_trie_inplace_node handle_node;
  switchlink_db_ecmp_info_t ecmp_info;
} switchlink_db_ecmp_obj_t;

typedef struct switchlink_db_oifl_obj_ {
  tommy_node list_node;
  int32_t ref_count;
  tommy_trie_inplace_node handle_node;
  switchlink_db_oifl_info_t oifl_info;
} switchlink_db_oifl_obj_t;

typedef struct switchlink_db_route_obj_ {
  tommy_node list_node;
  switchlink_db_route_info_t route_info;
} switchlink_db_route_obj_t;

typedef struct switchlink_db_mroute_obj_ {
  tommy_node list_node;
  switchlink_db_mroute_info_t mroute_info;
} switchlink_db_mroute_obj_t;

typedef struct switchlink_db_mdb_obj_ {
  tommy_node list_node;
  switchlink_db_mdb_info_t mdb_info;
} switchlink_db_mdb_obj_t;

#endif /* __SWITCHLINK_DB_INT_H__ */
