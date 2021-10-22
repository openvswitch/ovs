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

#ifndef __SWITCHLINK_SAI_H__
#define __SWITCHLINK_SAI_H__

extern int switchlink_vrf_create(uint16_t vrf_id, switchlink_handle_t *vrf_h);

extern int switchlink_interface_create(switchlink_db_interface_info_t *intf,
                                       switchlink_handle_t *intf_h);

extern int switchlink_interface_forwarding_update(switchlink_handle_t intf_h,
                                                  int af,
                                                  bool value);

extern int switchlink_interface_mc_forwarding_update(switchlink_handle_t intf_h,
                                                     int af,
                                                     bool value);

extern int switchlink_interface_urpf_mode_update(switchlink_handle_t intf_h,
                                                 int af,
                                                 bool value);

extern int switchlink_interface_delete(switchlink_db_interface_info_t *intf,
                                       switchlink_handle_t intf_h);

extern int switchlink_stp_state_update(switchlink_db_interface_info_t *intf);

extern int switchlink_stp_group_create(switchlink_handle_t *stp_h);

extern int switchlink_stp_group_delete(switchlink_handle_t stp_h);

extern int switchlink_add_interface_to_bridge(
    switchlink_db_interface_info_t *intf);

extern int switchlink_del_interface_from_bridge(
    switchlink_db_interface_info_t *intf, switchlink_handle_t old_bridge_h);

extern int switchlink_bridge_create(
    switchlink_db_bridge_info_t *bridge_db_info);

extern int switchlink_bridge_update(
    switchlink_db_bridge_info_t *bridge_db_info);

extern int switchlink_bridge_delete(
    switchlink_db_bridge_info_t *bridge_db_info);

extern int switchlink_lag_create(switchlink_handle_t *lag_h);

extern int switchlink_mac_create(switchlink_mac_addr_t mac_addr,
                                 switchlink_handle_t bridge_h,
                                 switchlink_handle_t intf_h);

extern int switchlink_mac_update(switchlink_mac_addr_t mac_addr,
                                 switchlink_handle_t bridge_h,
                                 switchlink_handle_t intf_h);

extern int switchlink_mac_delete(switchlink_mac_addr_t mac_addr,
                                 switchlink_handle_t bridge_h);

extern int switchlink_neighbor_create(switchlink_db_neigh_info_t *neigh_info);

extern int switchlink_neighbor_delete(switchlink_db_neigh_info_t *neigh_info);

extern int switchlink_nexthop_create(switchlink_db_neigh_info_t *neigh_info);

extern int switchlink_nexthop_delete(switchlink_db_neigh_info_t *neigh_info);

extern int switchlink_ecmp_create(switchlink_db_ecmp_info_t *ecmp_info);

extern int switchlink_ecmp_delete(switchlink_db_ecmp_info_t *ecmp_info);

extern int switchlink_route_create(switchlink_db_route_info_t *route_info);

extern int switchlink_route_delete(switchlink_db_route_info_t *route_info);

extern int switchlink_mroute_create(switchlink_db_mroute_info_t *mroute_info);

extern int switchlink_mroute_delete(switchlink_db_mroute_info_t *mroute_info);

extern int switchlink_mdb_create(switchlink_db_mdb_info_t *mdb_info);

extern int switchlink_mdb_delete(switchlink_db_mdb_info_t *mdb_info);

extern int switchlink_send_packet(char *buf,
                                  uint32_t buf_size,
                                  uint16_t port_id);

#endif /* __SWITCHLINK_SAI_H__ */
