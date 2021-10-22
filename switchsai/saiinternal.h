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

#include <saitypes.h>
#include <sai.h>

//#include <switchapi/switch_base_types.h>
//#include <switchapi/switch_status.h>
//#include <switchapi/switch_handle.h>
//#include <switchapi/switch_acl.h>
//#include <switchapi/switch_meter.h>
//#include <switchapi/switch_port.h>
//#include <switchapi/switch_hostif.h>
//
#include <util.h>
#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>

#include <arpa/inet.h>
//#include <bfsys/bf_sal/bf_sys_intf.h>
//#include <bfsys/bf_sal/bf_sys_mem.h>
//
#ifndef __SAIINTERNAL_H_
#define __SAIINTERNAL_H_

#define SAI_MAX_ENTRY_STRING_LEN 200

#define SAI_LOG_BUFFER_SIZE 1000

#define SAI_ASSERT(x) ovs_assert(x)

#define SAI_MALLOC(x) bf_sys_malloc(x)

#define SAI_REALLOC(x, y) bf_sys_realloc(x, y)

#define SAI_FREE(x) bf_sys_free(x)

#define SAI_MAC_TABLE_DEFAULT_AGING_TIME 300000

#define SAI_MEMSET memset
#define SAI_MEMCPY memcpy
#define SAI_MEMCMP memcmp

void sai_log(int level, sai_api_t api, char *fmt, ...);

#define SAI_LOG(level, api_id, fmt, arg...) \
  do {                                      \
    sai_log(level,                          \
            api_id,                         \
            "[F:%s L:%d Func:%s] " fmt,     \
            __FILE__,                       \
            __LINE__,                       \
            __func__,                       \
            ##arg);                         \
  } while (0);

#ifdef SAI_LOG_STDOUT_ENABLE
#define SAI_LOG_ENTER() \
  SAI_LOG(SAI_LOG_LEVEL_DEBUG, api_id, "Entering %s\n", __FUNCTION__)

#define SAI_LOG_EXIT() \
  SAI_LOG(SAI_LOG_LEVEL_DEBUG, api_id, "Exiting %s\n", __FUNCTION__)

#define SAI_LOG_DEBUG(fmt, arg...) \
  SAI_LOG(SAI_LOG_LEVEL_DEBUG, api_id, fmt, ##arg)

#define SAI_LOG_INFO(fmt, arg...) \
  SAI_LOG(SAI_LOG_LEVEL_INFO, api_id, fmt, ##arg)

#define SAI_LOG_NOTICE(fmt, arg...) \
  SAI_LOG(SAI_LOG_LEVEL_NOTICE, api_id, fmt, ##arg)

#define SAI_LOG_WARN(fmt, arg...) \
  SAI_LOG(SAI_LOG_LEVEL_WARN, api_id, fmt, ##arg)

#define SAI_LOG_ERROR(fmt, arg...) \
  SAI_LOG(SAI_LOG_LEVEL_ERROR, api_id, fmt, ##arg)

#define SAI_LOG_CRITICAL(fmt, arg...) \
  SAI_LOG(SAI_LOG_LEVEL_CRITICAL, api_id, fmt, ##arg)

#else
#define SAI_LOG_ENTER() (void) api_id;

#define SAI_LOG_EXIT() (void) api_id;

/*
#define SAI_LOG_DEBUG(fmt, arg...) \
  VLOG_DBG(fmt, ##arg)

#define SAI_LOG_INFO(fmt, arg...) \
  VLOG_INFO(fmt, ##arg)

#define SAI_LOG_WARN(fmt, arg...) \
  VLOG_WARN(fmt, ##arg)

#define SAI_LOG_ERROR(fmt, arg...) \
  VLOG_ERR(fmt, ##arg)
*/
#endif

// L2 learn timeout in milliseconds
#define SAI_L2_LEARN_TIMEOUT 100

typedef struct _sai_api_service_t {
  sai_acl_api_t acl_api;
  sai_bridge_api_t bridge_api;
  sai_buffer_api_t buffer_api;
  sai_fdb_api_t fdb_api;
  sai_hash_api_t hash_api;
  sai_hostif_api_t hostif_api;
  sai_ipmc_api_t ipmc_api;
  sai_l2mc_api_t l2mc_api;
  sai_lag_api_t lag_api;
  sai_mirror_api_t mirror_api;
  sai_neighbor_api_t neighbor_api;
  sai_next_hop_api_t nhop_api;
  sai_next_hop_group_api_t nhop_group_api;
  sai_policer_api_t policer_api;
  sai_port_api_t port_api;
  sai_qos_map_api_t qos_api;
  sai_queue_api_t queue_api;
  sai_route_api_t route_api;
  sai_router_interface_api_t rif_api;
  sai_samplepacket_api_t samplepacket_api;
  sai_scheduler_api_t scheduler_api;
  sai_scheduler_group_api_t scheduler_group_api;
  sai_stp_api_t stp_api;
  sai_switch_api_t switch_api;
  sai_udf_api_t udf_api;
  sai_virtual_router_api_t vr_api;
  sai_vlan_api_t vlan_api;
  sai_dtel_api_t dtel_api;
  sai_wred_api_t wred_api;
  sai_tunnel_api_t tunnel_api;
} sai_api_service_t;

//extern switch_device_t device;

typedef struct _sai_switch_notification_t {
  sai_switch_state_change_notification_fn on_switch_state_change;
  sai_fdb_event_notification_fn on_fdb_event;
  sai_port_state_change_notification_fn on_port_state_change;
  sai_switch_shutdown_request_notification_fn on_switch_shutdown_request;
  sai_packet_event_notification_fn on_packet_event;
} sai_switch_notification_t;

extern sai_switch_notification_t sai_switch_notifications;

#define SWITCH_SAI_APP_ID 0x1

sai_status_t sai_acl_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_buffer_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_fdb_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_hash_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_hostif_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_initialize();
sai_status_t sai_ipmc_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_l2mc_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_lag_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_mirror_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_neighbor_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_next_hop_group_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_next_hop_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_policer_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_port_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_qos_map_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_bridge_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_route_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_router_interface_initialize(
    sai_api_service_t *sai_api_service);
sai_status_t sai_scheduler_group_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_scheduler_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_stp_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_switch_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_udf_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_virtual_router_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_vlan_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_queue_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_dtel_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_wred_initialize(sai_api_service_t *sai_api_service);
sai_status_t sai_tunnel_initialize(sai_api_service_t *sai_api_service);

char *sai_status_to_string(_In_ const sai_status_t status);

char *sai_object_type_to_string(_In_ sai_object_type_t object_type);

//sai_status_t sai_switch_status_to_sai_status(_In_ const switch_status_t status);

sai_status_t sai_ipv4_prefix_length(_In_ sai_ip4_t ip4,
                                    _Out_ uint32_t *prefix_length);

sai_status_t sai_ipv6_prefix_length(_In_ const sai_ip6_t ip6,
                                    _Out_ uint32_t *prefix_length);

sai_status_t sai_ipv4_to_string(_In_ sai_ip4_t ip4,
                                _In_ uint32_t max_length,
                                _Out_ char *entry_string,
                                _Out_ int *entry_length);

sai_status_t sai_ipv6_to_string(_In_ sai_ip6_t ip6,
                                _In_ uint32_t max_length,
                                _Out_ char *entry_string,
                                _Out_ int *entry_length);

sai_status_t sai_ipaddress_to_string(_In_ sai_ip_address_t ip_addr,
                                     _In_ uint32_t max_length,
                                     _Out_ char *entry_string,
                                     _Out_ int *entry_length);

sai_status_t sai_ipprefix_to_string(_In_ sai_ip_prefix_t ip_prefix,
                                    _In_ uint32_t max_length,
                                    _Out_ char *entry_string,
                                    _Out_ int *entry_length);

//sai_status_t sai_ip_prefix_to_switch_ip_addr(
  //  const _In_ sai_ip_prefix_t *sai_ip_prefix, _Out_ switch_ip_addr_t *ip_addr);

//sai_status_t sai_ip_addr_to_switch_ip_addr(
  //  const _In_ sai_ip_address_t *sai_ip_addr, _Out_ switch_ip_addr_t *ip_addr);

//sai_status_t sai_port_speed_to_switch_port_speed(
  //  uint32_t sai_port_speed, _Out_ switch_port_speed_t *switch_port_speed);

//switch_acl_action_t sai_packet_action_to_switch_packet_action(
  //  _In_ sai_packet_action_t action);

//sai_packet_action_t switch_packet_action_to_sai_packet_action(
  //  switch_acl_action_t acl_action);

//sai_status_t sai_switch_status_to_sai_status(_In_ const switch_status_t status);

//sai_status_t sai_switch_ip_addr_to_sai_ip_addr(
  //  _Out_ sai_ip_address_t *sai_ip_addr, const _In_ switch_ip_addr_t *ip_addr);

//sai_status_t sai_switch_port_enabled_to_sai_oper_status(
  //  _In_ switch_port_oper_status_t oper_status, _Out_ sai_attribute_t *attr);

const sai_attribute_t *get_attr_from_list(_In_ sai_attr_id_t attr_id,
                                          _In_ const sai_attribute_t *attr_list,
                                          _In_ uint32_t attr_count);

sai_object_id_t sai_id_to_oid(_In_ uint32_t type, _In_ uint32_t id);

sai_uint32_t sai_oid_to_id(_In_ sai_object_id_t oid);

typedef unsigned int switch_uint32_t;
typedef switch_uint32_t switch_size_t;

typedef struct sai_array_ {
  void *array;
  switch_size_t num_entries;
} sai_array_t;

sai_status_t sai_array_init(sai_array_t *array);

switch_uint32_t sai_array_count(sai_array_t *array);

sai_status_t sai_array_insert(sai_array_t *array,
                              sai_uint64_t index,
                              void *data);

sai_status_t sai_array_delete(sai_array_t *array, sai_uint64_t index);

sai_status_t sai_array_get(sai_array_t *array, sai_uint64_t index, void **data);

// -----------------------------------------------------------------------------
// Hash table utils
// -----------------------------------------------------------------------------
/*
typedef tommy_hashtable_node sai_hashnode_t;

typedef sai_status_t (*sai_key_func_t)(void *args, uint8_t *key, uint32_t *len);

typedef sai_int32_t (*sai_hash_compare_func_t)(const void *key1,
                                               const void *key2);

typedef struct sai_hashtable_ {
  tommy_hashtable table;
  sai_hash_compare_func_t compare_func;
  sai_key_func_t key_func;
  sai_size_t num_entries;
  sai_size_t size;
  sai_size_t hash_seed;
} sai_hashtable_t;

sai_status_t sai_hashtable_init(sai_hashtable_t *hashtable);

sai_size_t sai_hashtable_count(sai_hashtable_t *hashtable);

sai_status_t sai_hashtable_insert(sai_hashtable_t *hashtable,
                                  sai_hashnode_t *node,
                                  void *key,
                                  void *data);

sai_status_t sai_hashtable_delete(sai_hashtable_t *hashtable,
                                  void *key,
                                  void **data);

sai_status_t sai_hashtable_search(sai_hashtable_t *hashtable,
                                  void *key,
                                  void **data);

sai_status_t sai_hashtable_done(sai_hashtable_t *hashtable);
*/
switch_uint32_t sai_acl_priority_to_switch_priority(sai_uint32_t);

switch_uint32_t switch_sai_port_non_default_ppgs();
bool switch_sai_default_initialize();

//void sai_recv_hostif_packet_cb(switch_hostif_packet_t *hostif_packet);
/*
sai_status_t sai_switch_acl_actions_to_sai(
    _In_ switch_acl_action_t *switch_actions,
    _In_ uint32_t switch_actions_count,
    _In_ sai_acl_stage_t stage,
    _Out_ sai_acl_action_type_t *sai_actions,
    _Inout_ uint32_t *sai_actions_count);

sai_status_t sai_acl_get_number_of_supported_actions(
    _Out_ uint32_t *actions_count);
*/

#if defined(STATIC_LINK_LIB) && defined(THRIFT_ENABLED)
int start_p4_sai_thrift_rpc_server(char *port);
#endif  // STATIC_LINK_LIB && THRIFT_ENABLED

// -----------------------------------------------------------------------------
// Object ID allocator
// -----------------------------------------------------------------------------

#endif  // __SAIINTERNAL_H_
