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

#ifndef __SWITCH_PORT_H__
#define __SWITCH_PORT_H__

#include "switch_base_types.h"
#include "switch_handle.h"
#include "switch_id.h"
#include "switch_interface.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @defgroup Port Port configuration API
 *  API functions listed to configure the ports. Mostly
 *  related to MAC programming
    The basic configuration on the port dictates the MAC programming.
    The modes can be set to one of 1x100G, 2x50G, 4x25G, 2x40G or 4x10G.
    The ports can be configured with an administrative mode and default behavior can be set.
    The tables that get modified in response to the port APIs are mostly the early stage tables.
    The port can have a default, which generally allows tagging of untagged packets to this default
    domain for forwarding the packets through the device.
 *  @{
 */  // begin of Port

#define SWITCH_MAX_HW_LANES 4
#define SWITCH_PORT_INVALID -1
#define SWITCH_PORT_RX_MTU_DEFAULT 1600
/** port speed */
typedef enum switch_port_speed_s {
  SWITCH_PORT_SPEED_NONE = 0,
  SWITCH_PORT_SPEED_10G = 1,
  SWITCH_PORT_SPEED_25G = 2,
  SWITCH_PORT_SPEED_40G = 3,
  SWITCH_PORT_SPEED_50G = 4,
  SWITCH_PORT_SPEED_100G = 5
} switch_port_speed_t;

typedef enum switch_port_attribute_s {
  SWITCH_PORT_ATTR_ADMIN_STATE = (1 << 0),
  SWITCH_PORT_ATTR_SPEED = (1 << 1),
  SWITCH_PORT_ATTR_DEFAULT_TC = (1 << 2),
  SWITCH_PORT_ATTR_INGRESS_QOS_GROUP = (1 << 3),
  SWITCH_PORT_ATTR_EGRESS_QOS_GROUP = (1 << 4),
  SWITCH_PORT_ATTR_TC_QOS_GROUP = (1 << 5),
  SWITCH_PORT_ATTR_TRUST_DSCP = (1 << 6),
  SWITCH_PORT_ATTR_TRUST_PCP = (1 << 7),
  SWITCH_PORT_ATTR_DEFAULT_COLOR = (1 << 8),
  SWITCH_PORT_ATTR_UUC_METER_HANDLE = (1 << 9),
  SWITCH_PORT_ATTR_UMC_METER_HANDLE = (1 << 10),
  SWITCH_PORT_ATTR_BCAST_METER_HANDLE = (1 << 11),
  SWITCH_PORT_ATTR_OPER_STATUS = (1 << 12),
  SWITCH_PORT_ATTR_LANE_LIST = (1 << 13),
  SWITCH_PORT_ATTR_INGRESS_ACL_GROUP = (1 << 14),
  SWITCH_PORT_ATTR_LOOPBACK_MODE = (1 << 15),
  SWITCH_PORT_ATTR_AUTO_NEG_MODE = (1 << 16),
  SWITCH_PORT_ATTR_MTU = (1 << 17),
  SWITCH_PORT_ATTR_NUM_QUEUES = (1 << 18),
  SWITCH_PORT_ATTR_LEARNING_ENABLED = (1 << 19),
  SWITCH_PORT_ATTR_EGRESS_ACL_GROUP = (1 << 20),
} switch_port_attribute_t;

typedef enum switch_port_oper_status_s {
  SWITCH_PORT_OPER_STATUS_NONE = 0,
  SWITCH_PORT_OPER_STATUS_UNKNOWN = 1,
  SWITCH_PORT_OPER_STATUS_UP = 2,
  SWITCH_PORT_OPER_STATUS_DOWN = 3,
  SWITCH_PORT_OPER_STATUS_MAX
} switch_port_oper_status_t;

typedef struct switch_port_lane_list_s {
  switch_uint16_t num_lanes;
  switch_uint16_t lane[SWITCH_MAX_HW_LANES];
} switch_port_lane_list_t;

typedef enum switch_port_breakout_type_s {
  SWITCH_PORT_BREAKOUT_TYPE_LANE_1 = 1,
  SWITCH_PORT_BREAKOUT_TYPE_LANE_2 = 2,
  SWITCH_PORT_BREAKOUT_TYPE_LANE_4 = 3
} switch_port_breakout_type_t;

typedef enum switch_port_loopback_mode_s {
  SWITCH_PORT_LOOPBACK_MODE_NONE = 0,
  SWITCH_PORT_LOOPBACK_MODE_PHY_NEAR = 1,
  SWITCH_PORT_LOOPBACK_MODE_PHY_FAR = 2,
  SWITCH_PORT_LOOPBACK_MODE_MAC_NEAR = 3,
  SWITCH_PORT_LOOPBACK_MODE_MAC_FAR = 4,
  SWITCH_PORT_LOOPBACK_MODE_MAX
} switch_port_loopback_mode_t;

typedef enum switch_port_auto_neg_mode_s {
  SWITCH_PORT_AUTO_NEG_MODE_DEFAULT = 0,
  SWITCH_PORT_AUTO_NEG_MODE_ENABLE = 1,
  SWITCH_PORT_AUTO_NEG_MODE_DISABLE = 2
} switch_port_auto_neg_mode_t;

typedef struct switch_port_attribute_info_s {
  switch_port_oper_status_t oper_status;
  switch_handle_t ingress_qos_group;
  switch_handle_t egress_qos_group;
  switch_handle_t tc_qos_group;
  bool trust_dscp;
  bool trust_pcp;
  switch_color_t default_color;
  switch_port_lane_list_t lane_list;
  switch_port_speed_t port_speed;
  switch_port_breakout_type_t breakout_type;
  switch_s32_list_t supported_breakouts;
  bool admin_state;
  switch_handle_t ingress_acl_group_handle;
  switch_handle_t egress_acl_group_handle;
  switch_port_loopback_mode_t lb_mode;
  switch_port_auto_neg_mode_t an_mode;
  switch_uint8_t num_queues;
  bool learning_enabled;
} switch_port_attribute_info_t;

typedef struct switch_api_port_info_s {
  switch_port_t port;
  switch_port_speed_t port_speed;
  switch_int32_t tx_mtu;
  switch_int32_t rx_mtu;
} switch_api_port_info_t;

/**
  this function calls into driver to create port
  @param device device to use
  @param dev_port port id of the port
  @param mtu mtu of the port
*/
switch_status_t switch_pd_device_port_add(switch_device_t device,
    switch_dev_port_t dev_port,
    switch_uint32_t mtu);

/**
 Port L2 MTU settings
 @param device device to use
 @param port port on device to set
 @param l2mtu Max frame size on port
*/
switch_status_t switch_api_port_mtu_set(switch_device_t device,
                                        switch_handle_t port_handle,
                                        switch_uint32_t rx_mtu,
                                        switch_uint32_t tx_mtu);

/**
 Port L3 MTU settings
 @param device device to use
 @param port port on device to set
 @param l3mtu IP MTU on port
*/
switch_status_t switch_api_port_mtu_get(switch_device_t device,
                                        switch_handle_t port_handle,
                                        switch_uint32_t *rx_mtu,
                                        switch_uint32_t *tx_mtu);

/**
 Set Port configuration
 @param device device to use
 @param api_port_info port information inclduing port number
 (portnumber specified in port_info->port_number)
*/
switch_status_t switch_api_port_set(switch_device_t device,
                                    switch_api_port_info_t *api_port_info);

/**
 Get Port configuration
 @param device device to use
 @param api_port_info port information inclduing port number
 (portnumber specified in port_info->port_number)
*/
switch_status_t switch_api_port_get(switch_device_t device,
                                    switch_api_port_info_t *api_port_info);


switch_status_t switch_api_port_add(switch_device_t device,
                                    switch_api_port_info_t *api_port_info,
                                    switch_handle_t *port_handle);

switch_status_t switch_api_port_delete(switch_device_t device,
                                       switch_handle_t port_handle);

/** @} */  // end of Port
#ifdef __cplusplus
}
#endif

#endif /* __SWITCH_PORT_H__ */
