/*
Copyright 2013-present Barefoot Networks, Inc.
Copyright(c) 2021 Intel Corporation.

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

#ifndef __SWITCH_INTERFACE_H_
#define __SWITCH_INTERFACE_H_

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_tunnel.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup Interface Interface configuration API
 *  API functions listed to configure the interfaces
    Interface API
    Interfaces are the basic element for provisioning services on the device.
    Interfaces can be any of physical, link aggregation group, or tunnels.
 *  @{
 */  // begin of interface

/** Interface Types */

typedef enum switch_interface_type_s {
  SWITCH_INTERFACE_TYPE_NONE = 0,
  SWITCH_INTERFACE_TYPE_ACCESS = 2,
  SWITCH_INTERFACE_TYPE_PORT = SWITCH_INTERFACE_TYPE_ACCESS,
  SWITCH_INTERFACE_TYPE_TRUNK = 3,
  SWITCH_INTERFACE_TYPE_PORT_VLAN = 4,
  SWITCH_INTERFACE_TYPE_TUNNEL = 5,
  SWITCH_INTERFACE_TYPE_STRICT_ACCESS = 6,
  SWITCH_INTERFACE_TYPE_DOT1Q_TUNNEL = 7,
  SWITCH_INTERFACE_TYPE_QINQ_PORT = 8,
  SWITCH_INTERFACE_TYPE_MAX

} switch_interface_type_t;

/** interface attributes */
typedef enum switch_interface_attr_s {
  SWITCH_INTF_ATTR_TYPE = 1 << 0,
  SWITCH_INTF_ATTR_RIF_HANDLE = 1 << 2,
  SWITCH_INTF_ATTR_VLAN = 1 << 3,
  SWITCH_INTF_ATTR_PORT = 1 << 4,
} switch_interface_attr_t;

typedef enum switch_interface_counter_id_s {
  SWITCH_INTERFACE_COUNTER_IN_PACKETS = 0x0,
  SWITCH_INTERFACE_COUNTER_IN_BYTES = 0x1,
  SWITCH_INTERFACE_COUNTER_OUT_PACKETS = 0x2,
  SWITCH_INTERFACE_COUNTER_OUT_BYTES = 0x3,
  SWITCH_INTERFACE_COUNTER_MAX
} switch_interface_counter_id_t;

/** interface information */
typedef struct switch_api_interface_info_s {
  /** interface type - access/trunk/port-vlan/tunnel */
  switch_interface_type_t type;

  /** handle - port/lag/tunnel */
  switch_handle_t handle;

  /** vlan id */
  switch_vlan_t vlan;

  /** native vlan handle */
  switch_handle_t native_vlan_handle;

  /** router interface handle */
  switch_handle_t rif_handle;

  bool flood_enabled;

  /** qinq port */
  switch_vlan_t inner_vlan;
  switch_vlan_t outer_vlan;

} switch_api_interface_info_t;

/**
 Interface create
 @param device - device on which interface is created
 @param intf_info - interface information specific to type
 */
switch_status_t switch_api_interface_create(
    switch_device_t device,
    switch_api_interface_info_t *intf_info,
    switch_handle_t *intf_handle);

/**
 Interface delete
 @param device - device on which interface is created
 @param interface_handle handle returned by interface creation
 */
switch_status_t switch_api_interface_delete(switch_device_t device,
                                            switch_handle_t interface_handle);

switch_status_t switch_api_interface_handle_get(switch_device_t device,
                                                switch_handle_t intf_handle,
                                                switch_handle_t *port_handle);

switch_status_t switch_api_interface_by_type_get(
    switch_device_t device,
    switch_handle_t handle,
    switch_interface_type_t intf_type,
    switch_handle_t *intf_handle);

switch_status_t switch_api_interface_native_vlan_set(
    switch_device_t device,
    switch_handle_t intf_handle,
    switch_handle_t vlan_handle,
    switch_handle_t *member_handle);

switch_status_t switch_api_interface_native_vlan_get(
    switch_device_t device,
    switch_handle_t intf_handle,
    switch_handle_t *vlan_handle);

switch_status_t switch_api_interface_native_vlan_id_set(
    switch_device_t device,
    switch_handle_t intf_handle,
    switch_vlan_t vlan_id,
    switch_handle_t *member_handle);

switch_status_t switch_api_interface_native_vlan_id_get(
    switch_device_t device,
    switch_handle_t intf_handle,
    switch_vlan_t *vlan_id);

switch_status_t switch_api_interface_attribute_set(
    const switch_device_t device,
    const switch_handle_t intf_handle,
    const switch_uint64_t intf_flags,
    const switch_api_interface_info_t *api_intf_info);

switch_status_t switch_api_interface_attribute_get(
    const switch_device_t device,
    const switch_handle_t intf_handle,
    const switch_uint64_t intf_flags,
    switch_api_interface_info_t *api_intf_info);

switch_status_t switch_api_interface_handle_dump(
    const switch_device_t device,
    const switch_handle_t intf_handle,
    const void *cli_ctx);

switch_status_t switch_api_interface_ifindex_get(
    switch_device_t device,
    switch_handle_t interface_handle,
    switch_ifindex_t *ifindex);

switch_status_t switch_api_interface_handle_from_handle_get(
    switch_device_t device,
    switch_handle_t handle,
    switch_handle_t *intf_handle);

switch_status_t switch_api_interface_ln_handle_get(switch_device_t device,
                                                   switch_handle_t intf_handle,
                                                   switch_handle_t *ln_handle);
switch_status_t switch_api_interface_stats_get(
    switch_device_t device,
    switch_handle_t intf_handle,
    switch_uint16_t num_entries,
    switch_interface_counter_id_t *counter_id,
    switch_counter_t *counters);

switch_status_t switch_api_interface_port_lag_ifindex_get(
    const switch_device_t device,
    const switch_handle_t handle,
    switch_ifindex_t *ifindex);

/** @} */  // end of interface

#ifdef __cplusplus
}
#endif

#endif /* __SWITCH_INTERFACE_H__ */
