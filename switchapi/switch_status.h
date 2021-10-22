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

#ifndef __SWITCH_STATUS_H__
#define __SWITCH_STATUS_H__

#include "switch_base_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Status success
 */
#define SWITCH_STATUS_SUCCESS 0x00000000L

/*
 *  General failure
 */
#define SWITCH_STATUS_FAILURE 0x00000001L

/*
 *  The request is not supported
 */
#define SWITCH_STATUS_NOT_SUPPORTED 0x00000002L

/*
 *  Not enough memory to complete the operation
 */
#define SWITCH_STATUS_NO_MEMORY 0x00000003L

/*
 *  Insufficient system resources exist to complete the operation
 */
#define SWITCH_STATUS_INSUFFICIENT_RESOURCES 0x00000004L

/*
 *  An invalid parameter was passed to a function
 */
#define SWITCH_STATUS_INVALID_PARAMETER 0x00000005L

/*
 *  An item already exists
 */
#define SWITCH_STATUS_ITEM_ALREADY_EXISTS 0x00000006L

/*
 *  An item was not found
 */
#define SWITCH_STATUS_ITEM_NOT_FOUND 0x00000007L

/*
 *  The data was too large to fit into the specified buffer.
 */
#define SWITCH_STATUS_BUFFER_OVERFLOW 0x00000008L

/*
 *  Invalid port number
 */
#define SWITCH_STATUS_INVALID_PORT_NUMBER 0x00000009L

/*
 *  Invalid port member
 */
#define SWITCH_STATUS_INVALID_PORT_MEMBER 0x0000000AL

/*
 *  Invalid VLAN id
 */
#define SWITCH_STATUS_INVALID_VLAN_ID 0x0000000BL

/*
 *  Object is uninitialized
 */
#define SWITCH_STATUS_UNINITIALIZED 0x0000000CL

/*
 *   Table is full
 */
#define SWITCH_STATUS_TABLE_FULL 0x0000000DL

/*
 *  Attribute is invalid
 */
#define SWITCH_STATUS_INVALID_ATTRIBUTE 0x0000000EL

/*
 *  Invalid interface id
 */
#define SWITCH_STATUS_INVALID_INTERFACE 0x0000000FL

/*
 *   Port is in use
 */
#define SWITCH_STATUS_PORT_IN_USE 0x00000010L

/*
 *   Invalid switch ID
 */
#define SWITCH_STATUS_INVALID_SWITCH_ID 0x00000011L

/*
 *   Function is not implemented
 */
#define SWITCH_STATUS_NOT_IMPLEMENTED 0x00000012L

/*
 *   Address not found
 */
#define SWITCH_STATUS_ADDR_NOT_FOUND 0x00000013L

/*
 *   Invalid virtual router ID
 */
#define SWITCH_STATUS_INVALID_VRID 0x00000014L

/*
 *   Invalid attribute value
 */
#define SWITCH_STATUS_INVALID_ATTR_VALUE 0x00000015L

/*
 * Invalid Tunnel type
 */
#define SWITCH_STATUS_INVALID_TUNNEL_TYPE 0x000000016L

/*
 * Invalid Next Hop
 */
#define SWITCH_STATUS_INVALID_NHOP 0x000000017L

/*
 * Invalid Handle
 */
#define SWITCH_STATUS_INVALID_HANDLE 0x000000018L

/*
*  RESOURCE is in use
*/
#define SWITCH_STATUS_RESOURCE_IN_USE 0x00000019L

/*
 * Invalid LN type
 */
#define SWITCH_STATUS_INVALID_LN_TYPE 0x00000001AL

/*
 * Invalid encap type
 */
#define SWITCH_STATUS_INVALID_ENCAP_TYPE 0x00000001BL

/*
 * Unsupported type
 */
#define SWITCH_STATUS_UNSUPPORTED_TYPE 0x00000001CL

/*
 * pd failure
 */
#define SWITCH_STATUS_PD_FAILURE 0x00000001DL

/*
 * invalid device id
 */
#define SWITCH_STATUS_INVALID_DEVICE 0x00000001EL

/*
 * Hardware failure
 */
#define SWITCH_STATUS_HW_FAILURE 0x00000001FL

/*
 * Invalid pd handle
 */
#define SWITCH_STATUS_INVALID_PD_HANDLE 0x00000001FL

#ifdef __cplusplus
}
#endif

#endif /* __SWITCH_STATUS_H__ */
