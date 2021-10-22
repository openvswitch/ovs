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

#include <config.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include "util.h"
#include "tommytrieinp.h"
#include "tommyhashlin.h"
#include "tommylist.h"
#include "xxhash.h"
#include "switchlink.h"
#include "switchlink_link.h"
#include "switchlink_neigh.h"
#include "switchlink_route.h"
#include "switchlink_db.h"
#include "switchlink_db_int.h"

#define SWITCHLINK_MAC_KEY_LEN 14

#define SWITCHLINK_HANDLE_TYPE_OIFL 0xF800000000

static switchlink_db_port_obj_t switchlink_db_port_map[] = {
    {"swp1", 0},
    {"swp2", 1},
    {"swp3", 2},
    {"swp4", 3},
    {"swp5", 4},
    {"swp6", 5},
    {"swp7", 6},
    {"swp8", 7},
    {"swp9", 8},
    {"swp10", 9},
    {"swp11", 10},
    {"swp12", 11},
    {"swp13", 12},
    {"swp14", 13},
    {"swp15", 14},
    {"swp16", 15},
    {SWITCHLINK_CPU_INTERFACE_NAME, 208},
};

static tommy_trie_inplace switchlink_db_handle_obj_map;
static tommy_trie_inplace switchlink_db_tuntap_obj_map;
static tommy_trie_inplace switchlink_db_interface_obj_map;
static tommy_trie_inplace switchlink_db_bridge_obj_map;
static tommy_hashlin switchlink_db_mac_obj_hash;
static tommy_list switchlink_db_mac_obj_list;
static tommy_list switchlink_db_neigh_obj_list;
static tommy_list switchlink_db_ecmp_obj_list;
static tommy_list switchlink_db_oifl_obj_list;
static tommy_list switchlink_db_route_obj_list;
static tommy_list switchlink_db_mroute_obj_list;
static tommy_list switchlink_db_mdb_obj_list;

static void *switchlink_db_handle_get_obj(switchlink_handle_t h) {
  void *obj;
  obj = tommy_trie_inplace_search(&switchlink_db_handle_obj_map, h);
  return obj;
}

switchlink_db_status_t switchlink_db_port_get_all_ports(
    uint16_t *num_ports, switchlink_db_port_obj_t **port_map) {
  *num_ports =
      sizeof(switchlink_db_port_map) / sizeof(switchlink_db_port_obj_t);
  *port_map = switchlink_malloc(sizeof(switchlink_db_port_obj_t), *num_ports);
  memcpy(*port_map, switchlink_db_port_map, sizeof(switchlink_db_port_map));
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_port_get(char *name, uint16_t *port_id) {
  uint16_t i;
  for (i = 0;
       i < sizeof(switchlink_db_port_map) / sizeof(switchlink_db_port_obj_t);
       i++) {
    switchlink_db_port_obj_t *obj = &switchlink_db_port_map[i];
    if (strcmp(obj->name, name) == 0) {
      *port_id = obj->port_id;
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_interface_add(
    uint32_t ifindex, switchlink_db_interface_info_t *intf_info) {
  switchlink_db_intf_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_intf_obj_t), 1);
  obj->ifindex = ifindex;
  memcpy(&(obj->intf_info), intf_info, sizeof(switchlink_db_interface_info_t));
  tommy_trie_inplace_insert(
      &switchlink_db_interface_obj_map, &obj->ifindex_node, obj, obj->ifindex);
  tommy_trie_inplace_insert(&switchlink_db_handle_obj_map,
                            &obj->handle_node,
                            obj,
                            obj->intf_info.intf_h);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_tuntap_add(
    uint32_t ifindex, switchlink_db_tuntap_info_t *tunp_info) {
  switchlink_db_tuntap_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_tuntap_obj_t), 1);
  obj->ifindex = ifindex;
  memcpy(&(obj->tunp_info), tunp_info, sizeof(switchlink_db_tuntap_info_t));
  tommy_trie_inplace_insert(
      &switchlink_db_tuntap_obj_map, &obj->ifindex_node, obj, obj->ifindex);
  tommy_trie_inplace_insert(&switchlink_db_handle_obj_map,
                            &obj->handle_node,
                            obj,
                            obj->tunp_info.tunp_h);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_tuntap_get_info(
    uint32_t ifindex, switchlink_db_tuntap_info_t *tunp_info) {
  ovs_assert(tunp_info);
  switchlink_db_tuntap_obj_t *obj;
  obj = tommy_trie_inplace_search(&switchlink_db_tuntap_obj_map, ifindex);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  if (tunp_info) {
    memcpy(
        tunp_info, &(obj->tunp_info), sizeof(switchlink_db_tuntap_info_t));
  }
  return SWITCHLINK_DB_STATUS_SUCCESS;
}


switchlink_db_status_t switchlink_db_interface_get_info(
    uint32_t ifindex, switchlink_db_interface_info_t *intf_info) {
  ovs_assert(intf_info);
  switchlink_db_intf_obj_t *obj;
  obj = tommy_trie_inplace_search(&switchlink_db_interface_obj_map, ifindex);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  if (intf_info) {
    memcpy(
        intf_info, &(obj->intf_info), sizeof(switchlink_db_interface_info_t));
  }
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_interface_get_ifindex(
    switchlink_handle_t intf_h, uint32_t *ifindex) {
  switchlink_db_intf_obj_t *obj;
  obj = switchlink_db_handle_get_obj(intf_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }

  *ifindex = obj->ifindex;
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_interface_update(
    uint32_t ifindex, switchlink_db_interface_info_t *intf_info) {
  switchlink_db_intf_obj_t *obj;
  obj = tommy_trie_inplace_search(&switchlink_db_interface_obj_map, ifindex);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  memcpy(&(obj->intf_info), intf_info, sizeof(switchlink_db_interface_info_t));
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_interface_delete(uint32_t ifindex) {
  switchlink_db_intf_obj_t *obj;
  obj = tommy_trie_inplace_remove(&switchlink_db_interface_obj_map, ifindex);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  tommy_trie_inplace_remove_existing(&switchlink_db_handle_obj_map,
                                     &obj->handle_node);
  switchlink_free(obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_bridge_add(
    uint32_t ifindex, switchlink_db_bridge_info_t *bridge) {
  switchlink_db_bridge_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_bridge_obj_t), 1);
  obj->ifindex = ifindex;
  memcpy(&(obj->bridge), bridge, sizeof(switchlink_db_bridge_info_t));
  tommy_trie_inplace_insert(
      &switchlink_db_bridge_obj_map, &obj->ifindex_node, obj, obj->ifindex);
  tommy_trie_inplace_insert(&switchlink_db_handle_obj_map,
                            &obj->handle_node,
                            obj,
                            obj->bridge.bridge_h);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_bridge_update(
    uint32_t ifindex, switchlink_db_bridge_info_t *bridge) {
  switchlink_db_bridge_obj_t *obj;
  obj = tommy_trie_inplace_search(&switchlink_db_bridge_obj_map, ifindex);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  } else {
    memcpy(&(obj->bridge), bridge, sizeof(switchlink_db_bridge_info_t));
  }
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_bridge_get_info(
    uint32_t ifindex, switchlink_db_bridge_info_t *bridge) {
  /*
  switchlink_db_bridge_obj_t *obj;
  obj = tommy_trie_inplace_search(&switchlink_db_bridge_obj_map, ifindex);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  } else {
    if (bridge) {
      memcpy(bridge, &(obj->bridge), sizeof(switchlink_db_bridge_info_t));
    }
  }
  */
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_bridge_get_ifindex(
    switchlink_handle_t bridge_h, uint32_t *ifindex) {
  switchlink_db_bridge_obj_t *obj;
  obj = switchlink_db_handle_get_obj(bridge_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }

  *ifindex = obj->ifindex;
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_bridge_handle_get_info(
    switchlink_handle_t bridge_h, switchlink_db_bridge_info_t *bridge) {
  switchlink_db_bridge_obj_t *obj;
  obj = switchlink_db_handle_get_obj(bridge_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }

  if (bridge) {
    memcpy(bridge, &(obj->bridge), sizeof(switchlink_db_bridge_info_t));
  }
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_bridge_delete(uint32_t ifindex) {
  switchlink_db_bridge_obj_t *obj;
  obj = tommy_trie_inplace_remove(&switchlink_db_bridge_obj_map, ifindex);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  tommy_trie_inplace_remove_existing(&switchlink_db_handle_obj_map,
                                     &obj->handle_node);
  switchlink_free(obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

static inline void switchlink_db_mac_key_hash(switchlink_mac_addr_t mac_addr,
                                              switchlink_handle_t bridge_h,
                                              uint8_t *key,
                                              uint32_t *hash) {
  memset(key, 0, SWITCHLINK_MAC_KEY_LEN);
  memcpy(&key[0], &bridge_h, min(sizeof(bridge_h), (uint32_t)8));
  memcpy(&key[8], mac_addr, 6);
  if (hash) {
    *hash = XXH32(key, SWITCHLINK_MAC_KEY_LEN, 0x98761234);
  }
}

static inline int switchlink_db_mac_cmp(const void *key1, const void *arg) {
  switchlink_db_mac_obj_t *obj = (switchlink_db_mac_obj_t *)arg;
  uint8_t key2[SWITCHLINK_MAC_KEY_LEN];

  switchlink_db_mac_key_hash(obj->addr, obj->bridge_h, key2, NULL);
  return (memcmp(key1, key2, SWITCHLINK_MAC_KEY_LEN));
}

switchlink_db_status_t switchlink_db_mac_add(switchlink_mac_addr_t mac_addr,
                                             switchlink_handle_t bridge_h,
                                             switchlink_handle_t intf_h) {
  switchlink_db_mac_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_mac_obj_t), 1);
  memcpy(obj->addr, mac_addr, sizeof(switchlink_mac_addr_t));
  obj->bridge_h = bridge_h;
  obj->intf_h = intf_h;

  uint32_t hash;
  uint8_t key[SWITCHLINK_MAC_KEY_LEN];
  switchlink_db_mac_key_hash(mac_addr, bridge_h, key, &hash);
  tommy_hashlin_insert(&switchlink_db_mac_obj_hash, &obj->hash_node, obj, hash);
  tommy_list_insert_tail(&switchlink_db_mac_obj_list, &obj->list_node, obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_mac_get_intf(
    switchlink_mac_addr_t mac_addr,
    switchlink_handle_t bridge_h,
    switchlink_handle_t *intf_h) {
  switchlink_db_mac_obj_t *obj;
  uint32_t hash;
  uint8_t key[SWITCHLINK_MAC_KEY_LEN];
  switchlink_db_mac_key_hash(mac_addr, bridge_h, key, &hash);

  obj = tommy_hashlin_search(
      &switchlink_db_mac_obj_hash, switchlink_db_mac_cmp, key, hash);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  *intf_h = obj->intf_h;
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_mac_set_intf(
    switchlink_mac_addr_t mac_addr,
    switchlink_handle_t bridge_h,
    switchlink_handle_t intf_h) {
  switchlink_db_mac_obj_t *obj;
  uint32_t hash;
  uint8_t key[SWITCHLINK_MAC_KEY_LEN];
  switchlink_db_mac_key_hash(mac_addr, bridge_h, key, &hash);

  obj = tommy_hashlin_search(
      &switchlink_db_mac_obj_hash, switchlink_db_mac_cmp, key, hash);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  obj->intf_h = intf_h;
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_mac_delete(switchlink_mac_addr_t mac_addr,
                                                switchlink_handle_t bridge_h) {
  switchlink_db_mac_obj_t *obj;
  uint32_t hash;
  uint8_t key[SWITCHLINK_MAC_KEY_LEN];
  switchlink_db_mac_key_hash(mac_addr, bridge_h, key, &hash);

  obj = tommy_hashlin_search(
      &switchlink_db_mac_obj_hash, switchlink_db_mac_cmp, key, hash);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  tommy_hashlin_remove_existing(&switchlink_db_mac_obj_hash, &obj->hash_node);
  tommy_list_remove_existing(&switchlink_db_mac_obj_list, &obj->list_node);
  switchlink_free(obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_mac_intf_delete(
    switchlink_handle_t intf_h) {
  tommy_node *node = tommy_list_head(&switchlink_db_mac_obj_list);
  while (node) {
    switchlink_db_mac_obj_t *obj = node->data;
    node = node->next;
    if (obj->intf_h == intf_h) {
      tommy_hashlin_remove_existing(&switchlink_db_mac_obj_hash,
                                    &obj->hash_node);
      tommy_list_remove_existing(&switchlink_db_mac_obj_list, &obj->list_node);
      switchlink_free(obj);
    }
  }
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_neighbor_add(
    switchlink_db_neigh_info_t *neigh_info) {
  switchlink_db_neigh_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_neigh_obj_t), 1);
  memcpy(&(obj->neigh_info), neigh_info, sizeof(switchlink_db_neigh_info_t));
  tommy_list_insert_tail(&switchlink_db_neigh_obj_list, &obj->list_node, obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_neighbor_get_info(
    switchlink_db_neigh_info_t *neigh_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_neigh_obj_list);
  while (node) {
    switchlink_db_neigh_obj_t *obj = node->data;
    node = node->next;
    if ((memcmp(&(neigh_info->ip_addr),
                &(obj->neigh_info.ip_addr),
                sizeof(switchlink_ip_addr_t)) == 0) &&
        (neigh_info->vrf_h == obj->neigh_info.vrf_h) &&
        (neigh_info->intf_h == obj->neigh_info.intf_h)) {
      if (neigh_info) {
        memcpy(
            neigh_info, &(obj->neigh_info), sizeof(switchlink_db_neigh_info_t));
      }
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_neighbor_delete(
    switchlink_db_neigh_info_t *neigh_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_neigh_obj_list);
  while (node) {
    switchlink_db_neigh_obj_t *obj = node->data;
    node = node->next;
    if ((memcmp(&(neigh_info->ip_addr),
                &(obj->neigh_info.ip_addr),
                sizeof(switchlink_ip_addr_t)) == 0) &&
        (neigh_info->intf_h == obj->neigh_info.intf_h)) {
      tommy_list_remove_existing(&switchlink_db_neigh_obj_list,
                                 &obj->list_node);
      switchlink_free(obj);
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_ecmp_add(
    switchlink_db_ecmp_info_t *ecmp_info) {
  ovs_assert(ecmp_info->num_nhops < SWITCHLINK_ECMP_NUM_MEMBERS_MAX);
  switchlink_db_ecmp_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_ecmp_obj_t), 1);
  memcpy(&(obj->ecmp_info), ecmp_info, sizeof(switchlink_db_ecmp_info_t));
  obj->ref_count = 0;
  tommy_list_insert_tail(&switchlink_db_ecmp_obj_list, &obj->list_node, obj);
  tommy_trie_inplace_insert(&switchlink_db_handle_obj_map,
                            &obj->handle_node,
                            obj,
                            obj->ecmp_info.ecmp_h);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_ecmp_get_info(
    switchlink_db_ecmp_info_t *ecmp_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_ecmp_obj_list);
  while (node) {
    switchlink_db_ecmp_obj_t *obj = node->data;
    node = node->next;
    if (obj->ecmp_info.num_nhops == ecmp_info->num_nhops) {
      int i, j;
      for (i = 0; i < ecmp_info->num_nhops; i++) {
        bool match_found = false;
        for (j = 0; j < ecmp_info->num_nhops; j++) {
          if (obj->ecmp_info.nhops[i] == ecmp_info->nhops[j]) {
            match_found = true;
            break;
          }
        }
        if (!match_found) {
          return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
        }
      }
      if (ecmp_info) {
        memcpy(ecmp_info, &(obj->ecmp_info), sizeof(switchlink_db_ecmp_info_t));
      }
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_ecmp_handle_get_info(
    switchlink_handle_t ecmp_h, switchlink_db_ecmp_info_t *ecmp_info) {
  switchlink_db_ecmp_obj_t *obj;
  obj = switchlink_db_handle_get_obj(ecmp_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  if (ecmp_info) {
    memcpy(ecmp_info, &(obj->ecmp_info), sizeof(switchlink_db_ecmp_info_t));
  }
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_ecmp_ref_inc(switchlink_handle_t ecmp_h) {
  switchlink_db_ecmp_obj_t *obj;
  obj = switchlink_db_handle_get_obj(ecmp_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  ovs_assert(obj->ref_count >= 0);
  obj->ref_count++;
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_ecmp_ref_dec(switchlink_handle_t ecmp_h,
                                                  int *ref_count) {
  switchlink_db_ecmp_obj_t *obj;
  obj = switchlink_db_handle_get_obj(ecmp_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  ovs_assert(obj->ref_count >= 0);
  if (obj->ref_count != 0) {
    obj->ref_count--;
  }
  *ref_count = obj->ref_count;
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_ecmp_delete(switchlink_handle_t ecmp_h) {
  switchlink_db_ecmp_obj_t *obj;
  obj = switchlink_db_handle_get_obj(ecmp_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  ovs_assert(obj->ref_count == 0);
  tommy_trie_inplace_remove_existing(&switchlink_db_handle_obj_map,
                                     &obj->handle_node);
  tommy_list_remove_existing(&switchlink_db_ecmp_obj_list, &obj->list_node);
  switchlink_free(obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_oifl_add(
    switchlink_db_oifl_info_t *oifl_info) {
  static switchlink_handle_t s_oifl_h = 1;
  ovs_assert(oifl_info->num_intfs < SWITCHLINK_OIFL_NUM_MEMBERS_MAX);
  switchlink_db_oifl_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_oifl_obj_t), 1);
  oifl_info->oifl_h =
      (s_oifl_h++ & ~SWITCHLINK_HANDLE_TYPE_OIFL) | SWITCHLINK_HANDLE_TYPE_OIFL;
  memcpy(&(obj->oifl_info), oifl_info, sizeof(switchlink_db_oifl_info_t));
  obj->ref_count = 0;
  tommy_list_insert_tail(&switchlink_db_oifl_obj_list, &obj->list_node, obj);
  tommy_trie_inplace_insert(&switchlink_db_handle_obj_map,
                            &obj->handle_node,
                            obj,
                            obj->oifl_info.oifl_h);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_oifl_get_info(
    switchlink_db_oifl_info_t *oifl_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_oifl_obj_list);
  while (node) {
    switchlink_db_oifl_obj_t *obj = node->data;
    node = node->next;
    if (obj->oifl_info.num_intfs == oifl_info->num_intfs) {
      int i, j;
      for (i = 0; i < oifl_info->num_intfs; i++) {
        bool match_found = false;
        for (j = 0; j < oifl_info->num_intfs; j++) {
          if (obj->oifl_info.intfs[i] == oifl_info->intfs[j]) {
            match_found = true;
            break;
          }
        }
        if (!match_found) {
          return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
        }
      }
      if (oifl_info) {
        memcpy(oifl_info, &(obj->oifl_info), sizeof(switchlink_db_oifl_info_t));
      }
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_oifl_handle_get_info(
    switchlink_handle_t oifl_h, switchlink_db_oifl_info_t *oifl_info) {
  switchlink_db_oifl_obj_t *obj;
  obj = switchlink_db_handle_get_obj(oifl_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  if (oifl_info) {
    memcpy(oifl_info, &(obj->oifl_info), sizeof(switchlink_db_oifl_info_t));
  }
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_oifl_ref_inc(switchlink_handle_t oifl_h) {
  switchlink_db_oifl_obj_t *obj;
  obj = switchlink_db_handle_get_obj(oifl_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  ovs_assert(obj->ref_count >= 0);
  obj->ref_count++;
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_oifl_ref_dec(switchlink_handle_t oifl_h,
                                                  int *ref_count) {
  switchlink_db_oifl_obj_t *obj;
  obj = switchlink_db_handle_get_obj(oifl_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  ovs_assert(obj->ref_count >= 0);
  if (obj->ref_count != 0) {
    obj->ref_count--;
  }
  *ref_count = obj->ref_count;
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_oifl_delete(switchlink_handle_t oifl_h) {
  switchlink_db_oifl_obj_t *obj;
  obj = switchlink_db_handle_get_obj(oifl_h);
  if (!obj) {
    return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
  }
  ovs_assert(obj->ref_count == 0);
  tommy_trie_inplace_remove_existing(&switchlink_db_handle_obj_map,
                                     &obj->handle_node);
  tommy_list_remove_existing(&switchlink_db_oifl_obj_list, &obj->list_node);
  switchlink_free(obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_route_add(
    switchlink_db_route_info_t *route_info) {
  switchlink_db_route_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_route_obj_t), 1);
  memcpy(&(obj->route_info), route_info, sizeof(switchlink_db_route_info_t));
  tommy_list_insert_tail(&switchlink_db_route_obj_list, &obj->list_node, obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_route_delete(
    switchlink_db_route_info_t *route_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_route_obj_list);
  while (node) {
    switchlink_db_route_obj_t *obj = node->data;
    node = node->next;
    if ((obj->route_info.vrf_h == route_info->vrf_h) &&
        (memcmp(&(obj->route_info.ip_addr),
                &(route_info->ip_addr),
                sizeof(switchlink_ip_addr_t)) == 0)) {
      tommy_list_remove_existing(&switchlink_db_route_obj_list,
                                 &obj->list_node);
      switchlink_free(obj);
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_route_get_info(
    switchlink_db_route_info_t *route_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_route_obj_list);
  while (node) {
    switchlink_db_route_obj_t *obj = node->data;
    node = node->next;
    if ((obj->route_info.vrf_h == route_info->vrf_h) &&
        (memcmp(&(obj->route_info.ip_addr),
                &(route_info->ip_addr),
                sizeof(switchlink_ip_addr_t)) == 0)) {
      if (route_info) {
        memcpy(
            route_info, &(obj->route_info), sizeof(switchlink_db_route_info_t));
      }
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_mroute_add(
    switchlink_db_mroute_info_t *mroute_info) {
  switchlink_db_mroute_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_mroute_obj_t), 1);
  memcpy(&(obj->mroute_info), mroute_info, sizeof(switchlink_db_mroute_info_t));
  tommy_list_insert_tail(&switchlink_db_mroute_obj_list, &obj->list_node, obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_mroute_delete(
    switchlink_db_mroute_info_t *mroute_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_mroute_obj_list);
  while (node) {
    switchlink_db_mroute_obj_t *obj = node->data;
    node = node->next;
    if ((obj->mroute_info.vrf_h == mroute_info->vrf_h) &&
        (memcmp(&(obj->mroute_info.src_ip),
                &(mroute_info->src_ip),
                sizeof(switchlink_ip_addr_t)) == 0) &&
        (memcmp(&(obj->mroute_info.dst_ip),
                &(mroute_info->dst_ip),
                sizeof(switchlink_ip_addr_t)) == 0)) {
      tommy_list_remove_existing(&switchlink_db_mroute_obj_list,
                                 &obj->list_node);
      switchlink_free(obj);
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_mroute_get_info(
    switchlink_db_mroute_info_t *mroute_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_mroute_obj_list);
  while (node) {
    switchlink_db_mroute_obj_t *obj = node->data;
    node = node->next;
    if ((obj->mroute_info.vrf_h == mroute_info->vrf_h) &&
        (memcmp(&(obj->mroute_info.src_ip),
                &(mroute_info->src_ip),
                sizeof(switchlink_ip_addr_t)) == 0) &&
        (memcmp(&(obj->mroute_info.dst_ip),
                &(mroute_info->dst_ip),
                sizeof(switchlink_ip_addr_t)) == 0)) {
      if (mroute_info) {
        memcpy(mroute_info,
               &(obj->mroute_info),
               sizeof(switchlink_db_mroute_info_t));
      }
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

void switchlink_db_mroute_mdb_walk(switchlink_db_mdb_info_t *mdb_info,
                                   switchlink_db_mroute_walk_fn notify) {
  if (!mdb_info || !notify) {
    return;
  }

  switchlink_handle_t mdb_vrf_h;
  switchlink_db_bridge_info_t bridge_info;
  if (switchlink_db_bridge_handle_get_info(mdb_info->bridge_h, &bridge_info) !=
      SWITCHLINK_DB_STATUS_SUCCESS) {
    return;
  }
  mdb_vrf_h = bridge_info.vrf_h;

  tommy_node *node = tommy_list_head(&switchlink_db_mroute_obj_list);
  while (node) {
    switchlink_db_mroute_obj_t *obj = node->data;
    node = node->next;
    if ((obj->mroute_info.vrf_h == mdb_vrf_h) &&
        (memcmp(&(obj->mroute_info.dst_ip),
                &(mdb_info->grp_ip),
                sizeof(switchlink_ip_addr_t)) == 0)) {
      switchlink_db_mroute_info_t mroute_info;
      memcpy(&mroute_info,
             &(obj->mroute_info),
             sizeof(switchlink_db_mroute_info_t));
      (*notify)(&mroute_info);
    }
  }
}

switchlink_db_status_t switchlink_db_mdb_add(
    switchlink_db_mdb_info_t *mdb_info) {
  switchlink_db_mdb_obj_t *obj =
      switchlink_malloc(sizeof(switchlink_db_mdb_obj_t), 1);
  memcpy(&(obj->mdb_info), mdb_info, sizeof(switchlink_db_mdb_info_t));
  tommy_list_insert_tail(&switchlink_db_mdb_obj_list, &obj->list_node, obj);
  return SWITCHLINK_DB_STATUS_SUCCESS;
}

switchlink_db_status_t switchlink_db_mdb_delete(
    switchlink_db_mdb_info_t *mdb_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_mdb_obj_list);
  while (node) {
    switchlink_db_mdb_obj_t *obj = node->data;
    node = node->next;
    if ((obj->mdb_info.bridge_h == mdb_info->bridge_h) &&
        (memcmp(&(obj->mdb_info.grp_ip),
                &(mdb_info->grp_ip),
                sizeof(switchlink_ip_addr_t)) == 0)) {
      tommy_list_remove_existing(&switchlink_db_mdb_obj_list, &obj->list_node);
      switchlink_free(obj);
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_mdb_update(
    switchlink_db_mdb_info_t *mdb_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_mdb_obj_list);
  while (node) {
    switchlink_db_mdb_obj_t *obj = node->data;
    node = node->next;
    if ((obj->mdb_info.bridge_h == mdb_info->bridge_h) &&
        (memcmp(&(obj->mdb_info.grp_ip),
                &(mdb_info->grp_ip),
                sizeof(switchlink_ip_addr_t)) == 0)) {
      memcpy(&(obj->mdb_info), mdb_info, sizeof(switchlink_db_mdb_info_t));
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

switchlink_db_status_t switchlink_db_mdb_get_info(
    switchlink_db_mdb_info_t *mdb_info) {
  tommy_node *node = tommy_list_head(&switchlink_db_mdb_obj_list);
  while (node) {
    switchlink_db_mdb_obj_t *obj = node->data;
    node = node->next;
    if ((obj->mdb_info.bridge_h == mdb_info->bridge_h) &&
        (memcmp(&(obj->mdb_info.grp_ip),
                &(mdb_info->grp_ip),
                sizeof(switchlink_ip_addr_t)) == 0)) {
      if (mdb_info) {
        memcpy(mdb_info, &(obj->mdb_info), sizeof(switchlink_db_mdb_info_t));
      }
      return SWITCHLINK_DB_STATUS_SUCCESS;
    }
  }
  return SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND;
}

void switchlink_db_init() {
  tommy_trie_inplace_init(&switchlink_db_handle_obj_map);
  tommy_trie_inplace_init(&switchlink_db_interface_obj_map);
  tommy_trie_inplace_init(&switchlink_db_tuntap_obj_map);
  tommy_trie_inplace_init(&switchlink_db_bridge_obj_map);
  tommy_hashlin_init(&switchlink_db_mac_obj_hash);
  tommy_list_init(&switchlink_db_mac_obj_list);
  tommy_list_init(&switchlink_db_neigh_obj_list);
  tommy_list_init(&switchlink_db_ecmp_obj_list);
  tommy_list_init(&switchlink_db_oifl_obj_list);
  tommy_list_init(&switchlink_db_route_obj_list);
  tommy_list_init(&switchlink_db_mroute_obj_list);
  tommy_list_init(&switchlink_db_mdb_obj_list);
}
