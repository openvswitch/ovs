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

#ifndef __SWITCHLINK_LINK_H__
#define __SWITCHLINK_LINK_H__

typedef enum {
  SWITCHLINK_INTF_TYPE_NONE,
  SWITCHLINK_INTF_TYPE_L2_ACCESS,
  SWITCHLINK_INTF_TYPE_L3,
  SWITCHLINK_INTF_TYPE_L3VI,
} switchlink_intf_type_t;

typedef enum {
  SWITCHLINK_LINK_TYPE_NONE,
  SWITCHLINK_LINK_TYPE_ETH,
  SWITCHLINK_LINK_TYPE_TUN,
  SWITCHLINK_LINK_TYPE_BRIDGE,
  SWITCHLINK_LINK_TYPE_VXLAN,
  SWITCHLINK_LINK_TYPE_BOND,
} switchlink_link_type_t;

typedef enum {
  SWITCHLINK_STP_STATE_NONE,
  SWITCHLINK_STP_STATE_DISABLED,
  SWITCHLINK_STP_STATE_LEARNING,
  SWITCHLINK_STP_STATE_FORWARDING,
  SWITCHLINK_STP_STATE_BLOCKING,
} switchlink_stp_state_t;

typedef enum {
  SWITCHLINK_URPF_MODE_NONE,
  SWITCHLINK_URPF_MODE_STRICT,
  SWITCHLINK_URPF_MODE_LOOSE,
} switchlink_urpf_mode_t;

extern void interface_change_type(uint32_t ifindex,
                                  switchlink_intf_type_t type);
extern void interface_create_l3vi(uint32_t ifindex);

#endif /* __SWITCHLINK_LINK_H__ */
