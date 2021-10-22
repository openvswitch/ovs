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


#ifndef __SWITCH_HANDLE_H__
#define __SWITCH_HANDLE_H__

#include "switch_base_types.h"
#include "switch_status.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/***************************************************************************
 * DEFINES
 ***************************************************************************/

/**
 * Number of bits to shift to set the handle type
 */
#define SWITCH_HANDLE_TYPE_SHIFT 25

/***************************************************************************
 * ENUMS
 ***************************************************************************/

/** Handle types */
typedef enum switch_handle_type_s {
  SWITCH_HANDLE_TYPE_NONE = 0,
  SWITCH_HANDLE_TYPE_PORT = 1,
  SWITCH_HANDLE_TYPE_LAG = 2,
  SWITCH_HANDLE_TYPE_LAG_MEMBER = 3,
  SWITCH_HANDLE_TYPE_INTERFACE = 4,
  SWITCH_HANDLE_TYPE_VRF = 5,
  SWITCH_HANDLE_TYPE_BD = 6,
  SWITCH_HANDLE_TYPE_NHOP = 7,
  SWITCH_HANDLE_TYPE_NEIGHBOR = 8,
  SWITCH_HANDLE_TYPE_RMAC = 9,
  SWITCH_HANDLE_TYPE_VLAN = 10,
  SWITCH_HANDLE_TYPE_STP = 11,
  SWITCH_HANDLE_TYPE_MGID = 12,
  SWITCH_HANDLE_TYPE_ACL = 13,
  SWITCH_HANDLE_TYPE_MGID_ECMP = 14,
  SWITCH_HANDLE_TYPE_URPF = 15,
  SWITCH_HANDLE_TYPE_HOSTIF_GROUP = 16,
  SWITCH_HANDLE_TYPE_HOSTIF = 17,
  SWITCH_HANDLE_TYPE_ACE = 18,
  SWITCH_HANDLE_TYPE_MIRROR = 19,
  SWITCH_HANDLE_TYPE_METER = 20,
  SWITCH_HANDLE_TYPE_SFLOW = 21,
  SWITCH_HANDLE_TYPE_SFLOW_ACE = 22,
  SWITCH_HANDLE_TYPE_ACL_COUNTER = 23,
  SWITCH_HANDLE_TYPE_QOS_MAP = 24,
  SWITCH_HANDLE_TYPE_PRIORITY_GROUP = 25,
  SWITCH_HANDLE_TYPE_QUEUE = 26,
  SWITCH_HANDLE_TYPE_SCHEDULER = 27,
  SWITCH_HANDLE_TYPE_BUFFER_POOL = 28,
  SWITCH_HANDLE_TYPE_BUFFER_PROFILE = 29,
  SWITCH_HANDLE_TYPE_LABEL = 30,
  SWITCH_HANDLE_TYPE_BD_MEMBER = 31,
  SWITCH_HANDLE_TYPE_LOGICAL_NETWORK = 32,
  SWITCH_HANDLE_TYPE_BFD = 33,
  SWITCH_HANDLE_TYPE_TUNNEL_MAPPER = 34,
  SWITCH_HANDLE_TYPE_HASH = 35,
  SWITCH_HANDLE_TYPE_WRED = 36,
  SWITCH_HANDLE_TYPE_RANGE = 37,
  SWITCH_HANDLE_TYPE_ECMP_MEMBER = 38,
  SWITCH_HANDLE_TYPE_STP_PORT = 39,
  SWITCH_HANDLE_TYPE_HOSTIF_REASON_CODE = 40,
  SWITCH_HANDLE_TYPE_RPF_GROUP = 41,
  SWITCH_HANDLE_TYPE_MAC = 42,
  SWITCH_HANDLE_TYPE_ROUTE = 43,
  SWITCH_HANDLE_TYPE_DEVICE = 44,
  SWITCH_HANDLE_TYPE_MTU = 45,
  SWITCH_HANDLE_TYPE_ACL_GROUP = 46,
  SWITCH_HANDLE_TYPE_ACL_GROUP_MEMBER = 47,
  SWITCH_HANDLE_TYPE_RIF = 48,
  SWITCH_HANDLE_TYPE_HOSTIF_RX_FILTER = 49,
  SWITCH_HANDLE_TYPE_HOSTIF_TX_FILTER = 50,
  SWITCH_HANDLE_TYPE_PKTDRIVER_RX_FILTER = 51,
  SWITCH_HANDLE_TYPE_PKTDRIVER_TX_FILTER = 52,
  SWITCH_HANDLE_TYPE_RACL_COUNTER = 53,
  SWITCH_HANDLE_TYPE_EGRESS_ACL_COUNTER = 54,
  SWITCH_HANDLE_TYPE_WRED_COUNTER = 55,
  SWITCH_HANDLE_TYPE_SCHEDULER_GROUP = 56,
  SWITCH_HANDLE_TYPE_WRED_PROFILE = 57,
  SWITCH_HANDLE_TYPE_DTEL = 58,
  SWITCH_HANDLE_TYPE_DTEL_QUEUE_ALERT = 59,
  SWITCH_HANDLE_TYPE_DTEL_INT_SESSION = 60,
  SWITCH_HANDLE_TYPE_DTEL_REPORT_SESSION = 61,
  SWITCH_HANDLE_TYPE_DTEL_EVENT = 62,
  SWITCH_HANDLE_TYPE_TUNNEL = 63,
  SWITCH_HANDLE_TYPE_TUNNEL_ENCAP = 64,
  SWITCH_HANDLE_TYPE_TUNNEL_TERM = 65,
  SWITCH_HANDLE_TYPE_TUNNEL_MAPPER_ENTRY = 66,
  SWITCH_HANDLE_TYPE_MPLS = 67,
  SWITCH_HANDLE_TYPE_MPLS_LABEL_STACK = 68,
  SWITCH_HANDLE_TYPE_SR_SIDLIST = 69,
  SWITCH_HANDLE_TYPE_EGRESS_METER = 70,
  SWITCH_HANDLE_TYPE_METER_COLOR_ACTION = 71,
  SWITCH_HANDLE_TYPE_MAX = 128
} switch_handle_type_t;

/***************************************************************************
 * APIS
 ***************************************************************************/

/**
 * @brief Get the handle type of a handle
 *
 * @param[in] handle handle
 *
 * @return #SWITCH_STATUS_SUCCESS if success otherwise error code is
 * returned.
 */
switch_handle_type_t switch_handle_type_get(switch_handle_t handle);

/**
 * @brief Iterator to get next handle
 *
 * @param[in] device device id
 * @param[in] handle type handle type
 * @param[in] old_handle old handle value.
 *            Set it to 0 when calling for the first time.
 * @param[out] new_handle next handle in the iterator
 *
 * @return #SWITCH_STATUS_SUCCESS if success otherwise error code is
 * returned.
 */
switch_status_t switch_api_handle_iterate(switch_device_t device,
                                          switch_handle_type_t type,
                                          switch_handle_t old_handle,
                                          switch_handle_t *new_handle);

/**
 * @brief Returns a list of all handles allocated of a handle type
 *
 * NOTE: The memory is allocated by the underlying API and the the application
 * has to free the memory.
 *
 * @param[in] device device id
 * @param[in] handle_type handle type
 * @param[out] num_entries number of handles
 * @param[out] handles handle values
 *
 * @return #SWITCH_STATUS_SUCCESS if success otherwise error code is
 * returned.
 */
switch_status_t switch_api_handles_get(switch_device_t device,
                                       switch_handle_type_t type,
                                       switch_size_t *num_entries,
                                       switch_handle_t **handles);

/**
 * @brief Dump handle info
 *
 * @param[in] device device id
 * @param[in] handle handle
 * @param[in] cli_ctx cli context
 *
 * @return #SWITCH_STATUS_SUCCESS if success otherwise error code is
 * returned.
 */
switch_status_t switch_api_handle_dump(const switch_device_t device,
                                       const switch_handle_t handle,
                                       void *cli_ctx);

/**
 * @brief Dump all handle info based on handle type
 *
 * @param[in] device device id
 * @param[in] handle_type handle type
 * @param[in] cli_ctx cli context
 *
 * @return #SWITCH_STATUS_SUCCESS if success otherwise error code is
 * returned.
 */
switch_status_t switch_api_handle_dump_all(
    const switch_device_t device,
    const switch_handle_type_t handle_type,
    void *cli_ctx);

switch_status_t switch_api_handle_info_dump_all(const switch_device_t device,
                                                const void *cli_ctx);

#ifdef __cplusplus
}
#endif

#endif /** __SWITCH_HANDLE_H__ */
