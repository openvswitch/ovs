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

#ifndef __SWITCH_BASE_TYPES_H__
#define __SWITCH_BASE_TYPES_H__

/**
 * Third party includes
 */
#include <target_utils/Judy.h>
#include <target_utils/tommyds/tommyhashtbl.h>
#include <target_utils/tommyds/tommylist.h>
#include <target_sys/bf_sal/bf_sys_mem.h>
#include <target_sys/bf_sal/bf_sys_timer.h>
#ifdef STATIC_LINK_LIB
#include <bf_switchd/bf_switchd.h>
#endif  // STATIC_LINK_LIB

/**
 * P4 includes
 */
//#include "p4features.h"
//#include "drop_reason_codes.h"
//#include "p4_table_sizes.h"

/**
 * standard includes
 */
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/***************************************************************************
 * DEFINES
 ***************************************************************************/

/**
 * MALLOC wrapper
 * d - device
 * x - size of the instance
 * c - number of instances
 */
#define SWITCH_MALLOC(d, x, c) bf_sys_malloc((x) * (c))

/**
 * FREE wrapper
 * d - device
 * x - memory pointer
 */
#define SWITCH_FREE(d, x) bf_sys_free(x)

/**
 * REALLOC wrapper
 * d - device
 * x - memory pointer
 * c - size of new memory
 */
#define SWITCH_REALLOC(d, x, c) bf_sys_realloc(x, c)

/**
 * CALLOC wrapper
 * d - device
 * x - memory pointer
 * c - size of new memory
 */
#define SWITCH_CALLOC(d, x, c) bf_sys_calloc(x, c)

#define SWITCH_MEMSET memset
#define SWITCH_MEMCPY memcpy
#define SWITCH_MEMCMP memcmp

#define UNUSED(x) (void) x;

#define __MODULE__ SWITCH_API_TYPE_NONE

#define TRUE 1
#define FALSE 0

/**
 * API Invalid handle
 * Returned when switchapi handle allocation fails
 */
#define SWITCH_API_INVALID_HANDLE 0x0

/** Id allocator invalid value */
#define SWITCH_API_INVALID_ID 0xFFFFFFFF

#define SWITCH_MAX_STRING_SIZE 30

/** ACL Default priority */
#define SWITCH_PRIORITY_DEFAULT 1000

/** Host interface name size */
#define SWITCH_HOSTIF_NAME_SIZE 16

/**
 * This flag is to unlink the P4 PD wrappers.
 * Undefining it will compile only switchapi
 */
#define SWITCH_PD

/** Mac address length */
#define SWITCH_MAC_LENGTH 6

#define _In_

#define _Out_

#define PACKED __attribute__((__packed__))

#define SWITCH_IPV4_VERSION 4

#define SWITCH_IPV6_VERSION 6

#define ETH_LEN 6

/** IPv4 length in bytes */
#define SWITCH_IPV4_PREFIX_LENGTH 4

/** IPv6 length in bytes */
#define SWITCH_IPV6_PREFIX_LENGTH 16

/** IPv4 length in bits */
#define SWITCH_IPV4_PREFIX_LENGTH_IN_BITS SWITCH_IPV4_PREFIX_LENGTH * 8

/** IPv6 length in bits */
#define SWITCH_IPV6_PREFIX_LENGTH_IN_BITS SWITCH_IPV6_PREFIX_LENGTH * 8

#define SWITCH_PORT_LAG_INDEX_WIDTH 9

#define SWITCH_IPV4_COMPUTE_MASK(_len) (0xFFFFFFFF << (32 - _len))

#define SWITCH_MAC_VALID(_mac)                                                 \
  !(_mac.mac_addr[0] == 0 && _mac.mac_addr[1] == 0 && _mac.mac_addr[2] == 0 && \
    _mac.mac_addr[3] == 0 && _mac.mac_addr[4] == 0 && _mac.mac_addr[5] == 0)

#define SWITCH_MAC_VRRP_RESV_RANGE(_mac)                  \
  (_mac->mac_addr[0] == 0 && _mac->mac_addr[1] == 0 &&    \
   _mac->mac_addr[2] == 0x5E && _mac->mac_addr[3] == 0 && \
   _mac->mac_addr[4] == 0x01)

#define SWITCH_MAC_MULTICAST(_mac) (_mac.mac_addr[0] & 0x1)

#define SWITCH_MAC_BROADCAST(_mac)                         \
  (_mac.mac_addr[0] == 0xFF && _mac.mac_addr[1] == 0xFF && \
   _mac.mac_addr[2] == 0xFF && _mac.mac_addr[3] == 0xFF && \
   _mac.mac_addr[4] == 0xFF && _mac.mac_addr[5] == 0xFF)

#define SWITCH_IPV4_ADDRESS_VALID(_ip) ((_ip & 0xFF) > 0)

#define SWITCH_IPV4_MULTICAST(_ip) \
  ((((_ip >> 24) & 0xFF) >= 224) && (((_ip >> 24) & 0xFF) <= 239))

#define SWITCH_IPV4_BROADCAST(_ip)                     \
  (((_ip & 0xFF) == 0xFF)(((_ip > 8) & 0xFF) == 0xFF)( \
      ((_ip > 16) & 0xFF) == 0xFF)(((_ip > 24) & 0xFF) == 0xFF))

#define SWITCH_IPV6_ADDRESS_VALID(_ip)                                      \
  !((_ip.addr32[0] == 0) && (_ip.addr32[1] == 0) && (_ip.addr32[2] == 0) && \
    (_ip.addr32[3] == 0))

/***************************************************************************
 * ENUMS
 ***************************************************************************/

/**
 * switchapi application type
 */
typedef enum switch_api_type_s {
  SWITCH_API_TYPE_NONE = 0,
  SWITCH_API_TYPE_PORT = 1,
  SWITCH_API_TYPE_L2 = 2,
  SWITCH_API_TYPE_BD = 3,
  SWITCH_API_TYPE_VRF = 4,
  SWITCH_API_TYPE_L3 = 5,
  SWITCH_API_TYPE_RMAC = 6,
  SWITCH_API_TYPE_INTERFACE = 7,
  SWITCH_API_TYPE_LAG = 8,
  SWITCH_API_TYPE_NHOP = 9,
  SWITCH_API_TYPE_NEIGHBOR = 10,
  SWITCH_API_TYPE_TUNNEL = 11,
  SWITCH_API_TYPE_MCAST = 12,
  SWITCH_API_TYPE_HOSTIF = 13,
  SWITCH_API_TYPE_ACL = 14,
  SWITCH_API_TYPE_MIRROR = 15,
  SWITCH_API_TYPE_METER = 16,
  SWITCH_API_TYPE_SFLOW = 17,
  SWITCH_API_TYPE_DTEL = 18,
  SWITCH_API_TYPE_STP = 19,
  SWITCH_API_TYPE_VLAN = 20,
  SWITCH_API_TYPE_QOS = 21,
  SWITCH_API_TYPE_QUEUE = 22,
  SWITCH_API_TYPE_LOGICAL_NETWORK = 23,
  SWITCH_API_TYPE_NAT = 24,
  SWITCH_API_TYPE_BUFFER = 25,
  SWITCH_API_TYPE_BFD = 26,
  SWITCH_API_TYPE_HASH = 27,
  SWITCH_API_TYPE_WRED = 28,
  SWITCH_API_TYPE_ILA = 29,
  SWITCH_API_TYPE_FAILOVER = 30,
  SWITCH_API_TYPE_LABEL = 31,
  SWITCH_API_TYPE_RPF = 32,
  SWITCH_API_TYPE_DEVICE = 33,
  SWITCH_API_TYPE_RIF = 34,
  SWITCH_API_TYPE_PACKET_DRIVER = 35,
  SWITCH_API_TYPE_SCHEDULER = 36,
  SWITCH_API_TYPE_MPLS = 37,

  SWITCH_API_TYPE_MAX
} switch_api_type_t;

/** direction - ingress/egress/both */
typedef enum switch_direction_s {
  SWITCH_API_DIRECTION_BOTH = 0,
  SWITCH_API_DIRECTION_INGRESS = 1,
  SWITCH_API_DIRECTION_EGRESS = 2
} switch_direction_t;

/** ip address type */
typedef enum switch_ip_addr_type_s {
  SWITCH_API_IP_ADDR_V4 = 0,
  SWITCH_API_IP_ADDR_V6 = 1
} switch_ip_addr_type_t;

/** port lag index type */
typedef enum switch_port_lag_index_type_s {
  SWITCH_PORT_LAG_INDEX_TYPE_PORT = 0,
  SWITCH_PORT_LAG_INDEX_TYPE_LAG = 1,
} switch_port_lag_index_type_t;

/** Packet type */
typedef enum switch_packet_type_s {
  SWITCH_PACKET_TYPE_UNICAST = (1 << 0),
  SWITCH_PACKET_TYPE_MULTICAST = (1 << 1),
  SWITCH_PACKET_TYPE_BROADCAST = (1 << 2),
  SWITCH_PACKET_TYPE_MAX = SWITCH_PACKET_TYPE_BROADCAST + 1
} switch_packet_type_t;

/** ARP Opcodes */
typedef enum switch_arp_opcode_s {
  SWITCH_ARP_OPCODE_NONE = 0,
  SWITCH_ARP_OPCODE_REQ = 1,
  SWITCH_ARP_OPCODE_RES = 2
} switch_arp_opcode_t;

/* packet color */
typedef enum switch_color_s {
  SWITCH_COLOR_GREEN,
  SWITCH_COLOR_YELLOW,
  SWITCH_COLOR_RED,
  SWITCH_COLOR_MAX
} switch_color_t;

/** port bind mode */
typedef enum switch_port_bind_mode_s {
  SWITCH_PORT_BIND_MODE_PORT,
  SWITCH_PORT_BIND_MODE_PORT_VLAN,
} switch_port_bind_mode_t;

/** IP type */
typedef enum switch_ip_type_s {
  SWITCH_IP_TYPE_NONE = 0,
  SWITCH_IP_TYPE_IPV4 = 1,
  SWITCH_IP_TYPE_IPV4_WITH_OPTIONS = 2,
  SWITCH_IP_TYPE_IPV6 = 3,
  SWITCH_IP_TYPE_IPV6_WITH_OPTIONS = 4,
} switch_ip_type_t;

/**
 * common definitions
 */
typedef unsigned char switch_uint8_t;
typedef unsigned short switch_uint16_t;
typedef unsigned int switch_uint32_t;
typedef uint64_t switch_uint64_t;
typedef unsigned char switch_uchar_t;
typedef char switch_int8_t;
typedef char switch_char_t;
typedef short switch_int16_t;
typedef int switch_int32_t;
typedef int64_t switch_int64_t;

typedef switch_int32_t switch_status_t;
typedef switch_uint16_t switch_vlan_t;
typedef switch_uint32_t switch_ifindex_t;
typedef switch_uint32_t switch_port_lag_index_t;
typedef switch_uint32_t switch_port_t;
typedef switch_uint16_t switch_device_t;
typedef switch_uint8_t switch_pipe_t;
typedef switch_uint8_t switch_cos_t;
typedef switch_uint32_t switch_vrf_t;
typedef switch_uint32_t switch_prefix_t;
typedef unsigned long switch_handle_t;
typedef switch_uint32_t switch_size_t;
typedef switch_uint32_t switch_id_t;
typedef switch_uint32_t switch_mpls_label_t;
typedef switch_uint32_t switch_mirror_id_t;
typedef switch_uint32_t switch_vni_t;
typedef switch_uint8_t switch_qid_t;
typedef switch_uint16_t switch_tc_t;
typedef switch_uint16_t switch_mrpf_group_t;
typedef switch_uint32_t switch_mtu_id_t;
typedef switch_uint16_t switch_mtu_t;
typedef switch_uint16_t switch_app_id_t;
typedef switch_uint16_t switch_lane_t;
typedef switch_uint32_t switch_arrival_time_t;
typedef switch_uint16_t switch_bd_label_t;
typedef switch_uint16_t switch_port_lag_label_t;
typedef switch_int32_t switch_dev_port_t;

/***************************************************************************
 * STRUCTS
 ***************************************************************************/

/**
 * @brief Defines a list of API object handle used as value
 *
 * Used in get to return a list of API handles and its count
 */
typedef struct switch_handle_list_s {
  /** handle array */
  switch_handle_t *handles;

  /** number of handles */
  switch_size_t num_handles;

} switch_handle_list_t;

/** 128 bit field */
typedef struct switch_uint128_t {
  union {
    uint8_t addr8[16];
    uint16_t addr16[8];
    uint32_t addr32[4];
  } u;
} switch_uint128_t;

typedef switch_uint32_t switch_ip4_t;
typedef switch_uint128_t switch_ip6_t;

/** List of signed 32 bit integer values */
typedef struct switch_s32_list_s {
  /** integer array */
  switch_int32_t *value;

  /** number of entries */
  switch_uint16_t num_entries;

} switch_s32_list_t;

/** List of unsigned 32 bit integer values */
typedef struct switch_u32_list_s {
  /** integer array */
  switch_int32_t *value;

  /** number of entries */
  switch_uint16_t num_entries;

} switch_u32_list_t;

/** Mac address */
typedef struct switch_mac_addr_s {
  /** mac address array */
  switch_uint8_t mac_addr[SWITCH_MAC_LENGTH];
} switch_mac_addr_t;

/** IP address */
typedef struct switch_ip_addr_s {
  /** IP type - v4 or v6 */
  switch_ip_addr_type_t type;
  union {
    /** IPv4 address */
    switch_ip4_t v4addr;

    /** IPv6 address */
    switch_ip6_t v6addr;
  } ip;

  /**
   * prefix length
   * Limit is 32 for IPv4 and 128 for IPv6
   */
  switch_prefix_t prefix_len;

} switch_ip_addr_t;

/**
 * @brief Counter values
 *
 * Returns the number of packets and number of bytes
 *
 * @note counter value can be packet or byte based on the P4
 */
typedef struct switch_counter_s {
  /** number of packets */
  switch_uint64_t num_packets;

  /** number of bytes */
  switch_uint64_t num_bytes;

} switch_counter_t;

/* init */
#ifdef STATIC_LINK_LIB
switch_status_t switch_api_init(switch_device_t device,
                                unsigned int num_ports,
                                char *cpu_port,
                                bool add_ports,
                                void *rpc_server_cookie);

switch_status_t switch_api_init_handlers_register(bf_switchd_context_t *ctx);

#else   // STATIC_LINK_LIB
switch_status_t switch_api_init(switch_device_t device,
                                unsigned int num_ports,
                                char *cpu_port,
                                bool add_ports);
#endif  // STATIC_LINK_LIB

switch_status_t switch_mirror_on_drop_set(switch_device_t device,
                                          bool mirror_on_drop);

#ifdef __cplusplus
}
#endif

#endif /* __SWITCH_BASE_TYPES_H__ */
