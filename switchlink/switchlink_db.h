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

#ifndef __SWITCHLINK_DB_H__
#define __SWITCHLINK_DB_H__

#include <stdbool.h>

#define SWITCHLINK_INTERFACE_NAME_LEN_MAX 32
#define SWITCHLINK_ECMP_NUM_MEMBERS_MAX 16
#define SWITCHLINK_OIFL_NUM_MEMBERS_MAX 16
#define SWITCHLINK_CPU_INTERFACE_NAME "veth251"

typedef enum {
  SWITCHLINK_DB_STATUS_SUCCESS,
  SWITCHLINK_DB_STATUS_ITEM_NOT_FOUND,
} switchlink_db_status_t;

typedef struct switchlink_db_port_obj_ {
  char *name;
  uint16_t port_id;
} switchlink_db_port_obj_t;

typedef struct switchlink_db_tuntap_info_ {
  char ifname[SWITCHLINK_INTERFACE_NAME_LEN_MAX];
  uint32_t ifindex;
  switchlink_handle_t tunp_h;
  switchlink_mac_addr_t mac_addr;
  switchlink_link_type_t link_type;
  //struct tuntap_flags {
    //bool <?>_enabled;
    //uint8_t <?>_mode;
  //} flags;
} switchlink_db_tuntap_info_t;

typedef struct switchlink_db_interface_info_ {
  char ifname[SWITCHLINK_INTERFACE_NAME_LEN_MAX];
  uint32_t ifindex;
  uint16_t port_id;
  switchlink_handle_t intf_h;
  switchlink_intf_type_t intf_type;
  switchlink_link_type_t link_type;
  switchlink_handle_t vrf_h;
  switchlink_handle_t bridge_h;
  switchlink_handle_t stp_h;
  switchlink_handle_t lag_h;
  switchlink_handle_t vlan_member_h;
  switchlink_stp_state_t stp_state;
  switchlink_handle_t stp_port_h;
  switchlink_mac_addr_t mac_addr;
  struct interface_flags {
    bool ipv4_unicast_enabled;
    bool ipv6_unicast_enabled;
    bool ipv4_multicast_enabled;
    bool ipv6_multicast_enabled;
    uint8_t ipv4_urpf_mode;
    uint8_t ipv6_urpf_mode;
  } flags;
} switchlink_db_interface_info_t;

typedef struct switchlink_db_bridge_info_ {
  switchlink_handle_t bridge_h;
  switchlink_handle_t vrf_h;
  switchlink_handle_t stp_h;
  switchlink_mac_addr_t mac_addr;
} switchlink_db_bridge_info_t;

typedef struct switchlink_db_neigh_info_ {
  switchlink_handle_t vrf_h;
  switchlink_handle_t nhop_h;
  switchlink_handle_t intf_h;
  switchlink_ip_addr_t ip_addr;
  switchlink_mac_addr_t mac_addr;
} switchlink_db_neigh_info_t;

typedef struct switchlink_db_ecmp_info_ {
  switchlink_handle_t ecmp_h;
  uint8_t num_nhops;
  switchlink_handle_t nhops[SWITCHLINK_ECMP_NUM_MEMBERS_MAX];
  switchlink_handle_t nhop_member_handles[SWITCHLINK_ECMP_NUM_MEMBERS_MAX];
} switchlink_db_ecmp_info_t;

typedef struct switchlink_db_route_info_ {
  switchlink_handle_t vrf_h;
  switchlink_ip_addr_t ip_addr;
  bool ecmp;
  switchlink_handle_t nhop_h;
} switchlink_db_route_info_t;

typedef struct switchlink_db_oifl_info_ {
  switchlink_handle_t oifl_h;
  uint8_t num_intfs;
  switchlink_handle_t intfs[SWITCHLINK_OIFL_NUM_MEMBERS_MAX];
  switchlink_handle_t nhops[SWITCHLINK_OIFL_NUM_MEMBERS_MAX];
} switchlink_db_oifl_info_t;

typedef struct switchlink_db_mroute_info_ {
  switchlink_handle_t vrf_h;
  switchlink_ip_addr_t src_ip;
  switchlink_ip_addr_t dst_ip;
  switchlink_handle_t iif_h;
  switchlink_handle_t oifl_h;
} switchlink_db_mroute_info_t;

typedef struct switchlink_db_mdb_info_ {
  switchlink_handle_t bridge_h;
  switchlink_ip_addr_t grp_ip;
  uint8_t num_intfs;
  switchlink_handle_t intfs[SWITCHLINK_OIFL_NUM_MEMBERS_MAX];
} switchlink_db_mdb_info_t;

/*** port ***/
extern switchlink_db_status_t switchlink_db_port_get(char *name,
                                                     uint16_t *port_id);

extern switchlink_db_status_t switchlink_db_port_get_all_ports(
    uint16_t *num_ports, switchlink_db_port_obj_t **port_map);

/*** interface ***/
extern switchlink_db_status_t switchlink_db_interface_add(
    uint32_t ifindex, switchlink_db_interface_info_t *intf_info);

extern switchlink_db_status_t switchlink_db_interface_get_info(
    uint32_t ifindex, switchlink_db_interface_info_t *intf_info);

extern switchlink_db_status_t switchlink_db_interface_get_ifindex(
    switchlink_handle_t intf_h, uint32_t *ifindex);

extern switchlink_db_status_t switchlink_db_interface_update(
    uint32_t ifindex, switchlink_db_interface_info_t *intf_info);

extern switchlink_db_status_t switchlink_db_interface_delete(uint32_t ifindex);

/*** bridge/vlan ***/
extern switchlink_db_status_t switchlink_db_bridge_add(
    uint32_t ifindex, switchlink_db_bridge_info_t *bridge_info);

extern switchlink_db_status_t switchlink_db_bridge_update(
    uint32_t ifindex, switchlink_db_bridge_info_t *bridge_info);

extern switchlink_db_status_t switchlink_db_bridge_get_info(
    uint32_t ifindex, switchlink_db_bridge_info_t *bridge_info);

extern switchlink_db_status_t switchlink_db_bridge_handle_get_info(
    switchlink_handle_t bridge_h, switchlink_db_bridge_info_t *bridge_info);

extern switchlink_db_status_t switchlink_db_bridge_get_ifindex(
    switchlink_handle_t bridge_h, uint32_t *ifindex);

extern switchlink_db_status_t switchlink_db_bridge_delete(uint32_t ifindex);

/*** mac ***/
extern switchlink_db_status_t switchlink_db_mac_add(
    switchlink_mac_addr_t mac_addr,
    switchlink_handle_t bridge_h,
    switchlink_handle_t intf_h);

extern switchlink_db_status_t switchlink_db_mac_get_intf(
    switchlink_mac_addr_t mac_addr,
    switchlink_handle_t bridge_h,
    switchlink_handle_t *int_h);

extern switchlink_db_status_t switchlink_db_mac_set_intf(
    switchlink_mac_addr_t mac_addr,
    switchlink_handle_t bridge_h,
    switchlink_handle_t int_h);

extern switchlink_db_status_t switchlink_db_mac_delete(
    switchlink_mac_addr_t mac_addr, switchlink_handle_t bridge_h);

extern switchlink_db_status_t switchlink_db_mac_intf_delete(
    switchlink_handle_t intf_h);

/*** neighbor ***/
extern switchlink_db_status_t switchlink_db_neighbor_add(
    switchlink_db_neigh_info_t *neigh_info);

extern switchlink_db_status_t switchlink_db_neighbor_delete(
    switchlink_db_neigh_info_t *neigh_info);

extern switchlink_db_status_t switchlink_db_neighbor_get_info(
    switchlink_db_neigh_info_t *neigh_info);

/*** ecmp ***/
extern switchlink_db_status_t switchlink_db_ecmp_add(
    switchlink_db_ecmp_info_t *ecmp_info);

extern switchlink_db_status_t switchlink_db_ecmp_get_info(
    switchlink_db_ecmp_info_t *ecmp_info);

extern switchlink_db_status_t switchlink_db_ecmp_handle_get_info(
    switchlink_handle_t ecmp_h, switchlink_db_ecmp_info_t *ecmp_info);

extern switchlink_db_status_t switchlink_db_ecmp_ref_inc(
    switchlink_handle_t ecmp_h);

extern switchlink_db_status_t switchlink_db_ecmp_ref_dec(
    switchlink_handle_t ecmp_h, int *ref_count);

extern switchlink_db_status_t switchlink_db_ecmp_delete(
    switchlink_handle_t ecmp_h);

/*** oifl ***/
extern switchlink_db_status_t switchlink_db_oifl_add(
    switchlink_db_oifl_info_t *oifl_info);

extern switchlink_db_status_t switchlink_db_oifl_get_info(
    switchlink_db_oifl_info_t *oifl_info);

extern switchlink_db_status_t switchlink_db_oifl_handle_get_info(
    switchlink_handle_t oifl_h, switchlink_db_oifl_info_t *oifl_info);

extern switchlink_db_status_t switchlink_db_oifl_ref_inc(
    switchlink_handle_t oifl_h);

extern switchlink_db_status_t switchlink_db_oifl_ref_dec(
    switchlink_handle_t oifl_h, int *ref_count);

extern switchlink_db_status_t switchlink_db_oifl_delete(
    switchlink_handle_t oifl_h);

/*** route ***/
extern switchlink_db_status_t switchlink_db_route_add(
    switchlink_db_route_info_t *route_info);

extern switchlink_db_status_t switchlink_db_route_delete(
    switchlink_db_route_info_t *route_info);

extern switchlink_db_status_t switchlink_db_route_get_info(
    switchlink_db_route_info_t *route_info);

/*** multicast route ***/
typedef void (*switchlink_db_mroute_walk_fn)(switchlink_db_mroute_info_t *);

extern switchlink_db_status_t switchlink_db_mroute_add(
    switchlink_db_mroute_info_t *mroute_info);

extern switchlink_db_status_t switchlink_db_mroute_delete(
    switchlink_db_mroute_info_t *mroute_info);

extern switchlink_db_status_t switchlink_db_mroute_get_info(
    switchlink_db_mroute_info_t *mroute_info);

extern void switchlink_db_mroute_mdb_walk(switchlink_db_mdb_info_t *mdb_info,
                                          switchlink_db_mroute_walk_fn notify);

/*** bridge multicast entry ***/
extern switchlink_db_status_t switchlink_db_mdb_add(
    switchlink_db_mdb_info_t *mdb_info);

extern switchlink_db_status_t switchlink_db_mdb_update(
    switchlink_db_mdb_info_t *mdb_info);

extern switchlink_db_status_t switchlink_db_mdb_delete(
    switchlink_db_mdb_info_t *mdb_info);

extern switchlink_db_status_t switchlink_db_mdb_get_info(
    switchlink_db_mdb_info_t *mdb_info);

#endif /* __SWITCHLINK_DB_H__ */
