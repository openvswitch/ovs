/*
Copyright 2013-present Barefoot Networks, Inc.
Copyright(c) 2021 Intel Corporation

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
#include <openvswitch/util.h>
#include <openvswitch/vlog.h>
#include "switch_base_types.h"
#include "switch_port.h"
#include "switch_status.h"
#include "switch_port_int.h"


VLOG_DEFINE_THIS_MODULE(switch_port);
/*
 * Routine Description:
 *   @brief create a port on a device
 *
 * Arguments:
 *   @param[in] device - device id
 *   @param[in] port - port number
 *   @param[out] port_handle - port handle
 *
 * Return Values:
 *    @return  SWITCH_STATUS_SUCCESS on success
 *             Failure status code on error
 */

char *switch_error_to_string(switch_status_t status) {
  switch (status) {
    case SWITCH_STATUS_ITEM_NOT_FOUND:
      return "err: entry not found";
    case SWITCH_STATUS_FAILURE:
      return "err: general failure";
    case SWITCH_STATUS_NO_MEMORY:
      return "err: no memory";
    case SWITCH_STATUS_INSUFFICIENT_RESOURCES:
      return "err: insufficient resources";
    case SWITCH_STATUS_ITEM_ALREADY_EXISTS:
      return "err: item already exists";
    case SWITCH_STATUS_BUFFER_OVERFLOW:
      return "err: buffer overflow";
    case SWITCH_STATUS_INVALID_PORT_NUMBER:
      return "err: invalid port number";
    case SWITCH_STATUS_INVALID_PORT_MEMBER:
      return "err: invalid port member";
    case SWITCH_STATUS_UNINITIALIZED:
      return "err: uninitialized";
    case SWITCH_STATUS_TABLE_FULL:
      return "err: table full";
    case SWITCH_STATUS_INVALID_VLAN_ID:
      return "err: invalid vlan id";
    case SWITCH_STATUS_INVALID_ATTRIBUTE:
      return "err: invalid attribute";
    case SWITCH_STATUS_INVALID_INTERFACE:
      return "err: invalid interface";
    case SWITCH_STATUS_PORT_IN_USE:
      return "err: port in use";
    case SWITCH_STATUS_NOT_IMPLEMENTED:
      return "err: not implemented";
    case SWITCH_STATUS_INVALID_HANDLE:
      return "err: invalid handle";
    case SWITCH_STATUS_PD_FAILURE:
      return "err: pd failure";
    case SWITCH_STATUS_INVALID_PARAMETER:
      return "err: invalid parameter";
    default:
      return "err: unknown failure";
  }
}

switch_status_t switch_api_port_add(
    switch_device_t device,
    switch_api_port_info_t *api_port_info,
    switch_handle_t *port_handle) {

  switch_port_t port = SWITCH_PORT_INVALID;
  switch_port_speed_t port_speed = SWITCH_PORT_SPEED_NONE;
  switch_uint32_t mtu = SWITCH_PORT_RX_MTU_DEFAULT;
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  ovs_assert(api_port_info != NULL);

  port = api_port_info->port;
  mtu = api_port_info->rx_mtu;

  VLOG_INFO("switch_pd_port_add called with three parameters:\n");
  VLOG_INFO("device=%d\n", device);
  VLOG_INFO("port=%d\n", port);
  VLOG_INFO("mtu=%d\n", mtu);

  status = switch_pd_device_port_add(device, port, mtu);
  if (status != SWITCH_STATUS_SUCCESS) {
      VLOG_ERR(
          "port add failed on device %d port %d: "
          "port pd add failed(%s)\n",
          device,
          port,
          switch_error_to_string(status));
      return status;
   }
   return status;
}
