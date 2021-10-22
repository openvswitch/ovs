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

#include <stdio.h>
#include <config.h>
#include <openvswitch/vlog.h>
#include "switch_base_types.h"
#include "switch_port.h"
#include "switch_port_int.h"

#include <bf_types/bf_types.h>
#include <port_mgr/dpdk/bf_dpdk_port_if.h>

VLOG_DEFINE_THIS_MODULE(switch_pd_port);

enum switch_tuntap_type {
     SWITCH_PORT_ATTR_TYPE_UNKNOWN,
     SWITCH_PORT_ATTR_TYPE_TUN,
     SWITCH_PORT_ATTR_TYPE_TAP,
     SWITCH_PORT_ATTR_TYPE_MAX,
};

// ifdef SWITCH_PD
// typedef p4_pd_status_t switch_pd_status_t;
// endif

// Typedefs to compile stuff
typedef uint16_t switch_pd_table_id_t;
typedef uint16_t switch_pd_action_id_t;
typedef switch_status_t bf_status_t;
typedef switch_status_t switch_pd_status_t;
#define SWITCH_PD_STATUS_SUCCESS 0

switch_status_t switch_pd_status_to_status(switch_pd_status_t pd_status) {
  switch_status_t status = SWITCH_STATUS_SUCCESS;

  switch (pd_status) {
    case BF_SUCCESS:
      status = SWITCH_STATUS_SUCCESS;
      break;

    case BF_NO_SYS_RESOURCES:
      status = SWITCH_STATUS_INSUFFICIENT_RESOURCES;
      break;

    case BF_ALREADY_EXISTS:
      status = SWITCH_STATUS_ITEM_ALREADY_EXISTS;
      break;

    case BF_IN_USE:
      status = SWITCH_STATUS_RESOURCE_IN_USE;
      break;

    case BF_HW_COMM_FAIL:
      status = SWITCH_STATUS_HW_FAILURE;
      break;

    case BF_OBJECT_NOT_FOUND:
      status = SWITCH_STATUS_ITEM_NOT_FOUND;
      break;

    case BF_NOT_IMPLEMENTED:
      status = SWITCH_STATUS_NOT_IMPLEMENTED;
      break;

    case BF_INVALID_ARG:
      status = SWITCH_STATUS_INVALID_PARAMETER;
      break;

    case BF_NO_SPACE:
      status = SWITCH_STATUS_TABLE_FULL;
      break;

    default:
      status = SWITCH_STATUS_PD_FAILURE;
      break;
  }
  return status;
}

switch_status_t switch_pd_device_port_add(switch_device_t device,
    switch_dev_port_t dev_port,
    switch_uint32_t mtu)
{
   bf_status_t bf_status = BF_SUCCESS;
   struct port_attributes_t port_attrib;
   bf_dev_id_t bf_dev_id;
   bf_dev_port_t bf_dev_port;
   char portNameDpdk[10];
   char portName[25] = "TAP";

   memset(&port_attrib, 0, sizeof(port_attrib));
   snprintf(portNameDpdk, sizeof(portNameDpdk), "%d", dev_port);
   bf_dev_id = (bf_dev_id_t)device;
   bf_dev_port = (bf_dev_port_t)dev_port;
   port_attrib.port_type = BF_DPDK_TAP;
   strncat(portName, portNameDpdk,10);
   port_attrib.port_dir = PM_PORT_DIR_DEFAULT;
   port_attrib.port_in_id = dev_port;
   port_attrib.port_out_id = dev_port;
   strncpy(port_attrib.mempool_name, "MEMPOOL0",
                   sizeof(port_attrib.mempool_name));
   strncpy(port_attrib.pipe_name, "pipe", sizeof(port_attrib.pipe_name));
   port_attrib.tap.mtu = mtu;
   strncpy(port_attrib.port_name, portName, sizeof(port_attrib.port_name));

   VLOG_INFO("bf_pal_port_add called with three parameters:\n");
   VLOG_INFO("[bf_dev_id, bf_dev_port, port_attrib]\n");
   VLOG_INFO("bf_dev_id=%d\n", bf_dev_id);
   VLOG_INFO("bf_dev_port=%d\n", bf_dev_port);
   VLOG_INFO("port name dpdk = %s\n", portNameDpdk);
   VLOG_INFO("port name=%s\n", portName);
   VLOG_INFO("port_attrib.port_name=%s\n", port_attrib.port_name);
   VLOG_INFO("port_attrib.tap.mtu=%d\n", port_attrib.tap.mtu);
   VLOG_INFO("port_attrib.pipe_name=%s\n", port_attrib.pipe_name);
   VLOG_INFO("port_attrib.mempool_name=%s\n", port_attrib.mempool_name);
   VLOG_INFO("port_attrib.port_in_id=%d\n", port_attrib.port_in_id);
   VLOG_INFO("port_attrib.port_out_id=%d\n", port_attrib.port_out_id);
   VLOG_INFO("port_attrib.port_dir=%d\n", port_attrib.port_dir);
   VLOG_INFO("port_attrib.port_type=%d\n", port_attrib.port_type);

   bf_status = bf_pal_port_add(bf_dev_id, bf_dev_port, &port_attrib);
   if (bf_status != BF_SUCCESS)
   {
       VLOG_ERR(
       "port add failed "
       "on device %d \n",
       device);
       return bf_status;
   }
   return switch_pd_status_to_status(bf_status);
}
