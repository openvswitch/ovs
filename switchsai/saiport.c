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

#include <config.h>
#include <openvswitch/vlog.h>
#include <saiport.h>
#include "saiinternal.h"
#include "switch_port.h"
#include "switch_base_types.h"

/*
#include <switchapi/switch.h>
#include <switchapi/switch_port.h>
#include <switchapi/switch_qos.h>
#include <switchapi/switch_vlan.h>
#include <switchapi/switch_sflow.h>
#include <switchapi/switch_queue.h>
#include <switchapi/switch_buffer.h>
#include <switchapi/switch_wred.h>
*/

VLOG_DEFINE_THIS_MODULE(saiport);


/*
extern switch_status_t switch_api_port_attribute_get(
    switch_device_t device,
    switch_handle_t port_handle,
    switch_uint64_t flags,
    switch_port_attribute_info_t *port_attr_info);
*/
static sai_api_t api_id = SAI_API_PORT;

static char *port_attr_map[] = {
    "SAI_PORT_ATTR_TYPE",
    "SAI_PORT_ATTR_OPER_STATUS",
    "SAI_PORT_ATTR_SUPPORTED_BREAKOUT_MODE_TYPE",
    "SAI_PORT_ATTR_CURRENT_BREAKOUT_MODE_TYPE",
    "SAI_PORT_ATTR_QOS_NUMBER_OF_QUEUES",
    "SAI_PORT_ATTR_QOS_QUEUE_LIST",
    "SAI_PORT_ATTR_QOS_NUMBER_OF_SCHEDULER_GROUPS",
    "SAI_PORT_ATTR_QOS_SCHEDULER_GROUP_LIST",
    "SAI_PORT_ATTR_SUPPORTED_SPEED",
    "SAI_PORT_ATTR_SUPPORTED_FEC_MODE",
    "SAI_PORT_ATTR_SUPPORTED_HALF_DUPLEX_SPEED",
    "SAI_PORT_ATTR_SUPPORTED_AUTO_NEG_MODE",
    "SAI_PORT_ATTR_SUPPORTED_FLOW_CONTROL_MODE",
    "SAI_PORT_ATTR_SUPPORTED_ASYMMETRIC_PAUSE_MODE",
    "SAI_PORT_ATTR_SUPPORTED_MEDIA_TYPE",
    "SAI_PORT_ATTR_REMOTE_ADVERTISED_SPEED",
    "SAI_PORT_ATTR_REMOTE_ADVERTISED_FEC_MODE",
    "SAI_PORT_ATTR_REMOTE_ADVERTISED_HALF_DUPLEX_SPEED",
    "SAI_PORT_ATTR_REMOTE_ADVERTISED_AUTO_NEG_MODE",
    "SAI_PORT_ATTR_REMOTE_ADVERTISED_FLOW_CONTROL_MODE",
    "SAI_PORT_ATTR_REMOTE_ADVERTISED_ASYMMETRIC_PAUSE_MODE",
    "SAI_PORT_ATTR_REMOTE_ADVERTISED_MEDIA_TYPE",
    "SAI_PORT_ATTR_REMOTE_ADVERTISED_OUI_CODE",
    "SAI_PORT_ATTR_NUMBER_OF_INGRESS_PRIORITY_GROUPS",
    "SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST",
    "SAI_PORT_ATTR_HW_LANE_LIST",
    "SAI_PORT_ATTR_SPEED",
    "SAI_PORT_ATTR_FULL_DUPLEX_MODE",
    "SAI_PORT_ATTR_AUTO_NEG_MODE",
    "SAI_PORT_ATTR_ADMIN_STATE",
    "SAI_PORT_ATTR_MEDIA_TYPE",
    "SAI_PORT_ATTR_ADVERTISED_SPEED",
    "SAI_PORT_ATTR_ADVERTISED_FEC_MODE",
    "SAI_PORT_ATTR_ADVERTISED_HALF_DUPLEX_SPEED",
    "SAI_PORT_ATTR_ADVERTISED_AUTO_NEG_MODE",
    "SAI_PORT_ATTR_ADVERTISED_FLOW_CONTROL_MODE",
    "SAI_PORT_ATTR_ADVERTISED_ASYMMETRIC_PAUSE_MODE",
    "SAI_PORT_ATTR_ADVERTISED_MEDIA_TYPE",
    "SAI_PORT_ATTR_ADVERTISED_OUI_CODE",
    "SAI_PORT_ATTR_PORT_VLAN_ID",
    "SAI_PORT_ATTR_DEFAULT_VLAN_PRIORITY",
    "SAI_PORT_ATTR_DROP_UNTAGGED",
    "SAI_PORT_ATTR_DROP_TAGGED",
    "SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE",
    "SAI_PORT_ATTR_FEC_MODE",
    "SAI_PORT_ATTR_UPDATE_DSCP",
    "SAI_PORT_ATTR_MTU",
    "SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID",
    "SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID",
    "SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID",
    "SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE",
    "SAI_PORT_ATTR_INGRESS_ACL",
    "SAI_PORT_ATTR_EGRESS_ACL",
    "SAI_PORT_ATTR_INGRESS_MIRROR_SESSION",
    "SAI_PORT_ATTR_EGRESS_MIRROR_SESSION",
    "SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE",
    "SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE",
    "SAI_PORT_ATTR_POLICER_ID",
    "SAI_PORT_ATTR_QOS_DEFAULT_TC",
    "SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP",
    "SAI_PORT_ATTR_QOS_DOT1P_TO_COLOR_MAP",
    "SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP",
    "SAI_PORT_ATTR_QOS_DSCP_TO_COLOR_MAP",
    "SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP",
    "SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP",
    "SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP",
    "SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP",
    "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_PRIORITY_GROUP_MAP",
    "SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP",
    "SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID",
    "SAI_PORT_ATTR_QOS_INGRESS_BUFFER_PROFILE_LIST",
    "SAI_PORT_ATTR_QOS_EGRESS_BUFFER_PROFILE_LIST",
    "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_MODE",
    "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL",
    "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_RX",
    "SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL_TX",
    "SAI_PORT_ATTR_META_DATA",
    "SAI_PORT_ATTR_EGRESS_BLOCK_PORT_LIST",
    "SAI_PORT_ATTR_HW_PROFILE_ID",
    "SAI_PORT_ATTR_EEE_ENABLE",
    "SAI_PORT_ATTR_EEE_IDLE_TIME",
    "SAI_PORT_ATTR_EEE_WAKE_TIME",
    "SAI_PORT_ATTR_PORT_POOL_LIST",
};
/*
switch_status_t sai_port_counter_to_switch_port_counter(
    sai_stat_id_t port_stat_id, switch_port_counter_id_t *counter_id) {
  sai_status_t status = SAI_STATUS_SUCCESS;

  switch (port_stat_id) {
    case SAI_PORT_STAT_IF_IN_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_ALL_OCTETS;
      break;

    case SAI_PORT_STAT_IF_IN_UCAST_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_UCAST_PKTS;
      break;

    case SAI_PORT_STAT_IF_IN_ERRORS:
      *counter_id = SWITCH_PORT_STAT_IN_ERROR_PKTS;
      break;

    case SAI_PORT_STAT_IF_IN_BROADCAST_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_BCAST_PKTS;
      break;

    case SAI_PORT_STAT_IF_IN_MULTICAST_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_MCAST_PKTS;
      break;

    case SAI_PORT_STAT_IF_OUT_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_ALL_OCTETS;
      break;

    case SAI_PORT_STAT_IF_OUT_UCAST_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_UCAST_PKTS;
      break;

    case SAI_PORT_STAT_IF_OUT_ERRORS:
      *counter_id = SWITCH_PORT_STAT_OUT_ERROR_PKTS;
      break;

    case SAI_PORT_STAT_IF_OUT_BROADCAST_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_BCAST_PKTS;
      break;

    case SAI_PORT_STAT_IF_OUT_MULTICAST_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_MCAST_PKTS;
      break;

    case SAI_PORT_STAT_IF_IN_NON_UCAST_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_NON_UCAST_PKTS;
      break;

    case SAI_PORT_STAT_IF_IN_DISCARDS:
      *counter_id = SWITCH_PORT_STAT_IF_IN_DISCARDS;
      break;

    case SAI_PORT_STAT_IF_IN_UNKNOWN_PROTOS:
    case SAI_PORT_STAT_IF_IN_VLAN_DISCARDS:
      break;

    case SAI_PORT_STAT_IF_OUT_NON_UCAST_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_NON_UCAST_PKTS;
      break;

    case SAI_PORT_STAT_IF_OUT_DISCARDS:
      *counter_id = SWITCH_PORT_STAT_IF_OUT_DISCARDS;
      break;
    case SAI_PORT_STAT_IF_OUT_QLEN:                 // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_DROP_EVENTS:     // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_MULTICAST_PKTS:  // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_BROADCAST_PKTS:  // Unsupported
      status = SAI_STATUS_NOT_SUPPORTED;
      break;

    case SAI_PORT_STAT_ETHER_STATS_FRAGMENTS:
      *counter_id = SWITCH_PORT_STAT_IN_FRAGMENTS;
      break;

    case SAI_PORT_STAT_ETHER_STATS_PKTS_64_OCTETS:             // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_65_TO_127_OCTETS:      // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_128_TO_255_OCTETS:     // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_256_TO_511_OCTETS:     // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_512_TO_1023_OCTETS:    // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_1024_TO_1518_OCTETS:   // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_1519_TO_2047_OCTETS:   // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_2048_TO_4095_OCTETS:   // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_4096_TO_9216_OCTETS:   // Unsupported
    case SAI_PORT_STAT_ETHER_STATS_PKTS_9217_TO_16383_OCTETS:  // Unsupported
      status = SAI_STATUS_NOT_SUPPORTED;
      break;

    case SAI_PORT_STAT_ETHER_RX_OVERSIZE_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_OVER_SIZED_PKTS;
      break;

    case SAI_PORT_STAT_ETHER_TX_OVERSIZE_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_OVER_SIZED_PKTS;
      break;

    case SAI_PORT_STAT_ETHER_STATS_JABBERS:
      *counter_id = SWITCH_PORT_STAT_IN_JABBERS;
      break;

    case SAI_PORT_STAT_ETHER_STATS_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OCTETS;
      break;

    case SAI_PORT_STAT_ETHER_STATS_PKTS:
      *counter_id = SWITCH_PORT_STAT_PKTS;
      break;

    case SAI_PORT_STAT_ETHER_STATS_COLLISIONS:  // Unsupported
      status = SAI_STATUS_NOT_SUPPORTED;
      break;

    case SAI_PORT_STAT_ETHER_STATS_CRC_ALIGN_ERRORS:
      *counter_id = SWITCH_PORT_STAT_IN_CRC_ERRORS;
      break;

    case SAI_PORT_STAT_ETHER_STATS_TX_NO_ERRORS:
      *counter_id = SWITCH_PORT_STAT_OUT_GOOD_PKTS;
      break;

    case SAI_PORT_STAT_ETHER_STATS_RX_NO_ERRORS:
      *counter_id = SWITCH_PORT_STAT_IN_GOOD_PKTS;
      break;

    case SAI_PORT_STAT_IP_IN_RECEIVES:               // Unsupported
    case SAI_PORT_STAT_IP_IN_OCTETS:                 // Unsupported
    case SAI_PORT_STAT_IP_IN_UCAST_PKTS:             // Unsupported
    case SAI_PORT_STAT_IP_IN_NON_UCAST_PKTS:         // Unsupported
    case SAI_PORT_STAT_IP_IN_DISCARDS:               // Unsupported
    case SAI_PORT_STAT_IP_OUT_OCTETS:                // Unsupported
    case SAI_PORT_STAT_IP_OUT_UCAST_PKTS:            // Unsupported
    case SAI_PORT_STAT_IP_OUT_NON_UCAST_PKTS:        // Unsupported
    case SAI_PORT_STAT_IP_OUT_DISCARDS:              // Unsupported
    case SAI_PORT_STAT_IPV6_IN_RECEIVES:             // Unsupported
    case SAI_PORT_STAT_IPV6_IN_OCTETS:               // Unsupported
    case SAI_PORT_STAT_IPV6_IN_UCAST_PKTS:           // Unsupported
    case SAI_PORT_STAT_IPV6_IN_NON_UCAST_PKTS:       // Unsupported
    case SAI_PORT_STAT_IPV6_IN_MCAST_PKTS:           // Unsupported
    case SAI_PORT_STAT_IPV6_IN_DISCARDS:             // Unsupported
    case SAI_PORT_STAT_IPV6_OUT_OCTETS:              // Unsupported
    case SAI_PORT_STAT_IPV6_OUT_UCAST_PKTS:          // Unsupported
    case SAI_PORT_STAT_IPV6_OUT_NON_UCAST_PKTS:      // Unsupported
    case SAI_PORT_STAT_IPV6_OUT_MCAST_PKTS:          // Unsupported
    case SAI_PORT_STAT_IPV6_OUT_DISCARDS:            // Unsupported
    case SAI_PORT_STAT_GREEN_WRED_DROPPED_PACKETS:   // Unsupported
    case SAI_PORT_STAT_GREEN_WRED_DROPPED_BYTES:     // Unsupported
    case SAI_PORT_STAT_YELLOW_WRED_DROPPED_PACKETS:  // Unsupported
    case SAI_PORT_STAT_YELLOW_WRED_DROPPED_BYTES:    // Unsupported
    case SAI_PORT_STAT_RED_WRED_DROPPED_PACKETS:     // Unsupported
    case SAI_PORT_STAT_RED_WRED_DROPPED_BYTES:       // Unsupported
    case SAI_PORT_STAT_WRED_DROPPED_PACKETS:         // Unsupported
    case SAI_PORT_STAT_WRED_DROPPED_BYTES:           // Unsupported
      status = SAI_STATUS_NOT_SUPPORTED;
      break;

    case SAI_PORT_STAT_ECN_MARKED_PACKETS:
      *counter_id = SWITCH_PORT_STAT_ECN_MARKED_PACKETS;
      break;

    case SAI_PORT_STAT_ETHER_STATS_OVERSIZE_PKTS:  // Unsupported
      status = SAI_STATUS_NOT_SUPPORTED;
      break;

    case SAI_PORT_STAT_ETHER_STATS_UNDERSIZE_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_UNDER_SIZED_PKTS;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_64_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_LT_64;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_65_TO_127_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_65_TO_127;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_128_TO_255_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_128_TO_255;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_256_TO_511_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_256_TO_511;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_512_TO_1023_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_512_TO_1023;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_1024_TO_1518_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_1024_TO_1518;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_1519_TO_2047_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_1519_TO_2047;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_2048_TO_4095_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_2048_TO_4095;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_4096_TO_9216_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_4096_TO_8191;
      break;

    case SAI_PORT_STAT_ETHER_IN_PKTS_9217_TO_16383_OCTETS:
      *counter_id = SWITCH_PORT_STAT_IN_PKTS_9216;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_64_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_LT_64;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_65_TO_127_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_65_TO_127;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_128_TO_255_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_128_TO_255;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_256_TO_511_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_256_TO_511;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_512_TO_1023_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_512_TO_1023;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_1024_TO_1518_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_1024_TO_1518;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_1519_TO_2047_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_1519_TO_2047;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_2048_TO_4095_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_2048_TO_4095;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_4096_TO_9216_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_4096_TO_8191;
      break;

    case SAI_PORT_STAT_ETHER_OUT_PKTS_9217_TO_16383_OCTETS:
      *counter_id = SWITCH_PORT_STAT_OUT_PKTS_9216;
      break;

    case SAI_PORT_STAT_IN_CURR_OCCUPANCY_BYTES:
      *counter_id = SWITCH_PORT_STAT_IN_CURR_OCCUPANCY_BYTES;
      break;

    case SAI_PORT_STAT_IN_WATERMARK_BYTES:              // Unsupported
    case SAI_PORT_STAT_IN_SHARED_CURR_OCCUPANCY_BYTES:  // Unsupported
    case SAI_PORT_STAT_IN_SHARED_WATERMARK_BYTES:       // Unsupported
      status = SAI_STATUS_NOT_SUPPORTED;
      break;
    case SAI_PORT_STAT_OUT_CURR_OCCUPANCY_BYTES:
      *counter_id = SWITCH_PORT_STAT_OUT_CURR_OCCUPANCY_BYTES;
      break;
    case SAI_PORT_STAT_OUT_WATERMARK_BYTES:              // Unsupported
    case SAI_PORT_STAT_OUT_SHARED_CURR_OCCUPANCY_BYTES:  // Unsupported
    case SAI_PORT_STAT_OUT_SHARED_WATERMARK_BYTES:       // Unsupported
    case SAI_PORT_STAT_IN_DROPPED_PKTS:                  // Unsupported
    case SAI_PORT_STAT_OUT_DROPPED_PKTS:                 // Unsupported
    case SAI_PORT_STAT_PAUSE_RX_PKTS:                    // Unsupported
    case SAI_PORT_STAT_PAUSE_TX_PKTS:                    // Unsupported
      status = SAI_STATUS_NOT_SUPPORTED;
      break;

    case SAI_PORT_STAT_PFC_0_RX_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_0_PKTS;
      break;

    case SAI_PORT_STAT_PFC_0_TX_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_PFC_0_PKTS;
      break;

    case SAI_PORT_STAT_PFC_1_RX_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_1_PKTS;
      break;

    case SAI_PORT_STAT_PFC_1_TX_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_PFC_1_PKTS;
      break;

    case SAI_PORT_STAT_PFC_2_RX_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_2_PKTS;
      break;

    case SAI_PORT_STAT_PFC_2_TX_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_PFC_2_PKTS;
      break;

    case SAI_PORT_STAT_PFC_3_RX_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_3_PKTS;
      break;

    case SAI_PORT_STAT_PFC_3_TX_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_PFC_3_PKTS;
      break;

    case SAI_PORT_STAT_PFC_4_RX_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_4_PKTS;
      break;

    case SAI_PORT_STAT_PFC_4_TX_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_PFC_4_PKTS;
      break;

    case SAI_PORT_STAT_PFC_5_RX_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_5_PKTS;
      break;

    case SAI_PORT_STAT_PFC_5_TX_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_PFC_5_PKTS;
      break;

    case SAI_PORT_STAT_PFC_6_RX_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_6_PKTS;
      break;

    case SAI_PORT_STAT_PFC_6_TX_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_PFC_6_PKTS;
      break;

    case SAI_PORT_STAT_PFC_7_RX_PKTS:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_7_PKTS;
      break;

    case SAI_PORT_STAT_PFC_7_TX_PKTS:
      *counter_id = SWITCH_PORT_STAT_OUT_PFC_7_PKTS;
      break;

    case SAI_PORT_STAT_PFC_0_RX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_0_RX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_1_RX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_1_RX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_2_RX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_2_RX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_3_RX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_3_RX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_4_RX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_4_RX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_5_RX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_5_RX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_6_RX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_6_RX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_7_RX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_7_RX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_0_TX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_0_TX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_1_TX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_1_TX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_2_TX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_2_TX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_3_TX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_3_TX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_4_TX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_4_TX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_5_TX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_5_TX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_6_TX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_6_TX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_PFC_7_TX_PAUSE_DURATION:
      *counter_id = SWITCH_PORT_STAT_IN_PFC_7_TX_PAUSE_DURATION;
      break;

    case SAI_PORT_STAT_EEE_TX_EVENT_COUNT:  // Unsupported
    case SAI_PORT_STAT_EEE_RX_EVENT_COUNT:  // Unsupported
    case SAI_PORT_STAT_EEE_TX_DURATION:     // Unsupported
    case SAI_PORT_STAT_EEE_RX_DURATION:     // Unsupported
      status = SAI_STATUS_NOT_SUPPORTED;
      break;

    default:
      status = SAI_STATUS_INVALID_PARAMETER;
      break;
  }

  return status;
}
*/

//
//switch_packet_type_t sai_storm_to_switch_packet_type(uint32_t storm_pkt_type) {
//  switch (storm_pkt_type) {
//    case SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID:
//      return SWITCH_PACKET_TYPE_BROADCAST;
//
//    case SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID:
//      return SWITCH_PACKET_TYPE_MULTICAST;
//
//    case SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID:
//      /*
//       * TODO: Need to include unknown multicast as well.
//       */
//      return SWITCH_PACKET_TYPE_UNICAST;
//
//    default:
//      SAI_ASSERT(0);
//  }
//}
//

/*
 * Map SAI loopback mode to switch-api loopback mode.
 * SAI doesn't have near/far end loopback types, so supporting
 * only near-end loopback mode.
 * Remote partner(far-end) can also be supported.
 */
/*
switch_port_loopback_mode_t sai_loopback_mode_to_switch_api(uint32_t lbk_mode) {
  switch (lbk_mode) {
    case SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY:
      return SWITCH_PORT_LOOPBACK_MODE_PHY_NEAR;

    case SAI_PORT_INTERNAL_LOOPBACK_MODE_MAC:
      return SWITCH_PORT_LOOPBACK_MODE_MAC_NEAR;

    case SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE:
      return SWITCH_PORT_LOOPBACK_MODE_NONE;

    default:
      SAI_ASSERT(0);
  }
}
*/

/*
uint32_t switch_api_loopback_mode_to_sai(switch_port_loopback_mode_t mode) {
  switch (mode) {
    case SWITCH_PORT_LOOPBACK_MODE_PHY_NEAR:
      // case SWITCH_PORT_LOOPBACK_MODE_PHY_FAR:
      return SAI_PORT_INTERNAL_LOOPBACK_MODE_PHY;

    case SWITCH_PORT_LOOPBACK_MODE_MAC_NEAR:
      // case SWITCH_PORT_LOOPBACK_MODE_MAC_FAR:
      return SWITCH_PORT_LOOPBACK_MODE_MAC_NEAR;

    case SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE:
      return SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE;

    default:
      return SAI_PORT_INTERNAL_LOOPBACK_MODE_NONE;
  }
}
*/

/*
switch_port_fec_mode_t sai_fec_mode_to_switch_fec(
    sai_port_fec_mode_t sai_fec_mode) {
  switch (sai_fec_mode) {
    case SAI_PORT_FEC_MODE_NONE:
      return SWITCH_PORT_FEC_MODE_NONE;
    case SAI_PORT_FEC_MODE_RS:
      return SWITCH_PORT_FEC_MODE_RS;
    case SAI_PORT_FEC_MODE_FC:
      return SWITCH_PORT_FEC_MODE_FC;
    default:
      return SWITCH_PORT_FEC_MODE_NONE;
  }
}

sai_port_fec_mode_t switch_api_fec_mode_to_sai_fec(
    switch_port_fec_mode_t switch_fec_mode) {
  switch (switch_fec_mode) {
    case SWITCH_PORT_FEC_MODE_NONE:
      return SAI_PORT_FEC_MODE_NONE;
    case SWITCH_PORT_FEC_MODE_RS:
      return SAI_PORT_FEC_MODE_RS;
    case SWITCH_PORT_FEC_MODE_FC:
      return SAI_PORT_FEC_MODE_FC;
    default:
      return SAI_PORT_FEC_MODE_NONE;
  }
}

switch_port_speed_t switch_sai_port_speed_to_switch_port_speed(
    uint32_t port_speed) {
  switch (port_speed) {
    case 10000:
      return SWITCH_PORT_SPEED_10G;
    case 25000:
      return SWITCH_PORT_SPEED_25G;
    case 40000:
      return SWITCH_PORT_SPEED_40G;
    case 50000:
      return SWITCH_PORT_SPEED_50G;
    case 100000:
      return SWITCH_PORT_SPEED_100G;
    default:
      return 0;
  }
}

#define SAI_PORT_MAX_PFC_COS 8
static void sai_port_convert_cos_bmap_icos_map(switch_uint32_t cos_bmap,
                                               uint8_t *cos_to_icos) {
  uint8_t index = 0;
  for (index = 0; index < SAI_PORT_MAX_PFC_COS; index++) {
    if (cos_bmap & (1 << index)) {
      cos_to_icos[index] = index;
    }
  }
}
*/

#define SAI_PORT_DEFAULT_MTU 9400
/*
* Routine Description:
*   Set port attribute value.
*
* Arguments:
*    [in] port_id - port id
*    [in] attr - attribute
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/

sai_status_t sai_set_port_attribute(_In_ sai_object_id_t port_id,
                                    _In_ const sai_attribute_t *attr) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    return status;
}

//
//sai_status_t sai_set_port_attribute(_In_ sai_object_id_t port_id,
//                                    _In_ const sai_attribute_t *attr) {
//  SAI_LOG_ENTER();
//
//  sai_status_t status = SAI_STATUS_SUCCESS;
//  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
//  switch_handle_t handle = SWITCH_API_INVALID_HANDLE;
//  switch_handle_t acl_table_handle = SWITCH_API_INVALID_HANDLE;
//  sai_object_id_t meter_handle = SWITCH_API_INVALID_HANDLE;
//  switch_handle_t sflow_handle = SWITCH_API_INVALID_HANDLE;
//  bool rx_pause = FALSE, tx_pause = FALSE;
//  switch_uint32_t pfc_set = 0;
//  switch_port_auto_neg_mode_t auto_neg_mode;
//  switch_port_auto_neg_mode_t conf_an_mode;
//  switch_port_speed_t port_speed = SWITCH_PORT_SPEED_25G;
//  switch_uint32_t rx_mtu = 0;
//  switch_uint32_t tx_mtu = 0;
//  switch_port_fec_mode_t fec_mode = SWITCH_PORT_FEC_MODE_NONE;
//  switch_port_fec_mode_t conf_fec_mode = SWITCH_PORT_FEC_MODE_NONE;
//  uint8_t cos_to_icos[SAI_PORT_MAX_PFC_COS];
//
//  bool trust = FALSE;
//
//  // is port part of lag? should we forbid setting attributes if so?
//  if (!attr) {
//    status = SAI_STATUS_INVALID_PARAMETER;
//    VLOG_ERR("null attribute: %s", sai_status_to_string(status));
//    return status;
//  }
//
//  switch (attr->id) {
//    case SAI_PORT_ATTR_PORT_VLAN_ID:
//      // Todo: This looks broken?
//      switch_status = switch_api_vlan_id_to_handle_get(
//          device, (switch_vlan_t)attr->value.u16, &handle);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to get vlan %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      /* TBD: Default BD */
//      break;
//
//    case SAI_PORT_ATTR_QOS_DEFAULT_TC:
//      switch_status =
//          switch_api_port_tc_default_set(device, port_id, attr->value.u8);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set default tc for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//    case SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE:
//      // need for disabling ports on shutdown
//      if (attr->value.oid == SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE) {
//        rx_pause = TRUE;
//        tx_pause = TRUE;
//      } else if (attr->value.oid == SAI_PORT_FLOW_CONTROL_MODE_TX_ONLY) {
//        rx_pause = FALSE;
//        tx_pause = TRUE;
//      } else if (SAI_PORT_FLOW_CONTROL_MODE_RX_ONLY) {
//        rx_pause = TRUE;
//        tx_pause = FALSE;
//      } else {
//        rx_pause = FALSE;
//        tx_pause = FALSE;
//      }
//      switch_status =
//          switch_api_port_link_pause_set(device, port_id, rx_pause, tx_pause);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set link pause for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL:
//      pfc_set = attr->value.u8;
//      switch_uint32_t max_queues = 0;
//      switch_handle_t queue_handles[SAI_PORT_MAX_PFC_COS];
//      switch_uint32_t i = 0;
//
//      switch_status = switch_api_port_max_queues_get(
//          device, (switch_handle_t)(port_id), &max_queues);
//
//      if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//          SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to get max queues for port %d admin state: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//
//      // The max queues number has to be equal to max pfc cos number otherwise
//      // we won't be able to map them
//      if (SAI_PORT_MAX_PFC_COS != max_queues) {
//        VLOG_ERR(
//            "max queues number %d for port %d is not equal to max pfc cos "
//            "number: %d",
//            max_queues,
//            (port_id & 0xFFFF),
//            SAI_PORT_MAX_PFC_COS);
//        return SAI_STATUS_FAILURE;
//      }
//
//      memset(queue_handles, 0, sizeof(queue_handles));
//      max_queues = 0;
//      switch_status = switch_api_queues_get(
//          device, (switch_handle_t)(port_id), &max_queues, queue_handles);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("Failed to retrieve queue handle list for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//
//      switch_status = switch_api_port_pfc_set(device, port_id, pfc_set);
//
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set priority pause for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      memset(cos_to_icos, 0, sizeof(cos_to_icos));
//      if (pfc_set) {
//        sai_port_convert_cos_bmap_icos_map(pfc_set, cos_to_icos);
//        switch_status =
//            switch_api_port_pfc_cos_mapping(device, port_id, cos_to_icos);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to set pfc cos mapping for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        switch_status = switch_api_port_flowcontrol_mode_set(
//            device, port_id, SWITCH_FLOWCONTROL_TYPE_PFC);
//
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to enable pfc on port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//
//        // Set the queue pfc to cos mapping so queues will react to the
//        // to the PFC frames with right priorities
//        for (i = 0; i < max_queues; i++) {
//          if (queue_handles[i]) {
//            switch_status = switch_api_queue_pfc_cos_mapping(
//                device, queue_handles[i], cos_to_icos[i]);
//
//            status = sai_switch_status_to_sai_status(switch_status);
//            if (status != SAI_STATUS_SUCCESS) {
//              VLOG_ERR("Failed to set pfc cos mapping for queue 0x%lx: %s",
//                            queue_handles[i],
//                            sai_status_to_string(status));
//              return status;
//            }
//          }
//        }
//      } else {
//        switch_status = switch_api_port_flowcontrol_mode_set(
//            device, port_id, SWITCH_FLOWCONTROL_TYPE_NONE);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to enable pfc on port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//
//        for (i = 0; i < max_queues; i++) {
//          if (queue_handles[i]) {
//            switch_status =
//                switch_api_queue_pfc_cos_mapping(device, queue_handles[i], 0);
//
//            status = sai_switch_status_to_sai_status(switch_status);
//            if (status != SAI_STATUS_SUCCESS) {
//              VLOG_ERR("Failed to set pfc cos mapping for queue 0x%lx: %s",
//                            queue_handles[i],
//                            sai_status_to_string(status));
//              return status;
//            }
//          }
//        }
//      }
//      break;
//
//    case SAI_PORT_ATTR_SPEED:
//      port_speed = switch_sai_port_speed_to_switch_port_speed(attr->value.u32);
//      switch_status = switch_api_port_speed_set(device, port_id, port_speed);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set speed for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//    case SAI_PORT_ATTR_ADVERTISED_SPEED:
//      if (attr->value.u32list.count <= 0) {
//        status = SAI_STATUS_INVALID_PARAMETER;
//        VLOG_ERR("failed to set advertised speed for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      port_speed = switch_sai_port_speed_to_switch_port_speed(
//          attr->value.u32list.list[0]);
//      switch_status = switch_api_port_speed_set(device, port_id, port_speed);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set advertised speed for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//    case SAI_PORT_ATTR_MTU:
//      if (attr->value.u32 == 0) {
//        rx_mtu = SAI_PORT_DEFAULT_MTU;
//        tx_mtu = SAI_PORT_DEFAULT_MTU;
//      } else {
//        rx_mtu = attr->value.u32;
//        tx_mtu = attr->value.u32;
//      }
//      switch_status = switch_api_port_mtu_set(device, port_id, tx_mtu, rx_mtu);
//
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set MTU for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//    case SAI_PORT_ATTR_QOS_DOT1P_TO_COLOR_MAP:
//    case SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP:
//      trust = attr->value.oid != 0 ? TRUE : FALSE;
//      switch_status = switch_api_port_trust_pcp_set(device, port_id, trust);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set pcp trust for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      switch_status = switch_api_port_qos_group_ingress_set(
//          device, port_id, attr->value.oid);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set ingress qos handle for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//
//      break;
//
//    case SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP:
//    case SAI_PORT_ATTR_QOS_DSCP_TO_COLOR_MAP:
//      trust = attr->value.oid != 0 ? TRUE : FALSE;
//      switch_status = switch_api_port_trust_dscp_set(device, port_id, trust);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set dscp trust for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      switch_status = switch_api_port_qos_group_ingress_set(
//          device, port_id, attr->value.oid);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set ingress qos handle for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//
//      break;
//    case SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_PRIORITY_GROUP_MAP:
//      switch_status =
//          switch_api_port_icos_to_ppg_set(device, port_id, attr->value.oid);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR(
//            "Failed to set pfc to ppg qos map handle 0x%lx for port %d: %s",
//            attr->value.oid,
//            port_id,
//            sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP:
//      switch_status = switch_api_port_pfc_priority_to_queue_set(
//          device, port_id, attr->value.oid);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR(
//            "Failed to set pfc priority to queue qos map 0x%lx for port %d: %s",
//            attr->value.oid,
//            (port_id & 0xFFFF),
//            sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP:
//    case SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP:
//      switch_status =
//          switch_api_port_qos_group_tc_set(device, port_id, attr->value.oid);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set ingress tc handle for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP:
//    case SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP:
//      switch_status = switch_api_port_qos_group_egress_set(
//          device, port_id, attr->value.oid);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set egress qos handle for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//    case SAI_PORT_ATTR_INGRESS_ACL:
//    case SAI_PORT_ATTR_EGRESS_ACL: {
//      switch_handle_t port_handle = port_id;
//      acl_table_handle = (switch_handle_t)attr->value.oid;
//      if (switch_handle_type_get(port_id) != SWITCH_HANDLE_TYPE_PORT) {
//        // hack alert.. sometimes we pass in the port id where we should use the
//        // port handle..
//        status = switch_api_port_id_to_handle_get(
//            SWITCH_HANDLE_TYPE_PORT, port_id, &port_handle);
//      }
//
//      if (acl_table_handle == SAI_NULL_OBJECT_ID) {
//        if (attr->id == SAI_PORT_ATTR_INGRESS_ACL) {
//          switch_status = switch_api_port_ingress_acl_group_get(
//              device, port_handle, &acl_table_handle);
//          if (status != SAI_STATUS_SUCCESS) {
//            VLOG_ERR("failed to get ingress acl handle for port %d: %s",
//                          (port_handle & 0xFFFF),
//                          sai_status_to_string(status));
//            return status;
//          }
//        } else {
//          switch_status = switch_api_port_egress_acl_group_get(
//              device, port_handle, &acl_table_handle);
//          if (status != SAI_STATUS_SUCCESS) {
//            VLOG_ERR("failed to get egress acl handle for port %d: %s",
//                          (port_handle & 0xFFFF),
//                          sai_status_to_string(status));
//            return status;
//          }
//        }
//        switch_status =
//            switch_api_acl_dereference(device, acl_table_handle, port_handle);
//      } else {
//        switch_status =
//            switch_api_acl_reference(device, acl_table_handle, port_handle);
//      }
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to bind port to acl for port %d: %s",
//                      (port_handle & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//    } break;
//    case SAI_PORT_ATTR_ADMIN_STATE:
//      switch_status = switch_api_port_admin_state_set(
//          device, port_id, attr->value.booldata);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set admin state for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID:
//    case SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID:
//    case SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID:
//      meter_handle = (switch_handle_t)attr->value.oid;
//      switch_status = switch_api_port_storm_control_set(
//          device,
//          port_id,
//          sai_storm_to_switch_packet_type(attr->id),
//          ((meter_handle == SAI_NULL_OBJECT_ID) ? SWITCH_API_INVALID_HANDLE
//                                                : meter_handle));
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set storm control policer for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE:
//      /*
//       * To attach sflow session to the port, switchApi uses ACL.
//       */
//      sflow_handle = ((attr->value.oid == SAI_NULL_OBJECT_ID)
//                          ? SWITCH_API_INVALID_HANDLE
//                          : (switch_handle_t)attr->value.oid);
//      switch_status = switch_api_sflow_session_port_set(
//          device, sflow_handle, port_id, SWITCH_API_DIRECTION_INGRESS);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set sflow ingress for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE:
//      sflow_handle = ((attr->value.oid == SAI_NULL_OBJECT_ID)
//                          ? SWITCH_API_INVALID_HANDLE
//                          : (switch_handle_t)attr->value.oid);
//      switch_status = switch_api_sflow_session_port_set(
//          device, sflow_handle, port_id, SWITCH_API_DIRECTION_EGRESS);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set sflow egress for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE:
//      switch_status = switch_api_port_loopback_mode_set(
//          device, port_id, sai_loopback_mode_to_switch_api(attr->value.s32));
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set sflow ingress for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_AUTO_NEG_MODE:
//      if (attr->value.booldata) {
//        auto_neg_mode = SWITCH_PORT_AUTO_NEG_MODE_ENABLE;
//      } else {
//        auto_neg_mode = SWITCH_PORT_AUTO_NEG_MODE_DISABLE;
//      }
//
//      switch_status =
//          switch_api_port_auto_neg_get(device, port_id, &conf_an_mode);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR(
//            "failed to set autoneg mode for port %d: %s"
//            "failed to query pre configured an mode",
//            (port_id & 0xFFFF),
//            sai_status_to_string(status));
//        return status;
//      }
//
//      if (auto_neg_mode != conf_an_mode) {
//        switch_status =
//            switch_api_port_auto_neg_set(device, port_id, auto_neg_mode);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to set autoneg mode for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//      } else {
//        VLOG_DBG(
//            "Skipping setting autoneg for port %d: Autoneg mode %s already set",
//            (port_id & 0xFFFF),
//            (auto_neg_mode == SWITCH_PORT_AUTO_NEG_MODE_ENABLE)
//                ? "SWITCH_PORT_AUTO_NEG_MODE_ENABLE"
//                : "SWITCH_PORT_AUTO_NEG_MODE_DISABLE");
//      }
//      break;
//
//    case SAI_PORT_ATTR_FEC_MODE:
//      fec_mode = sai_fec_mode_to_switch_fec(attr->value.s32);
//
//      switch_status =
//          switch_api_port_fec_mode_get(device, port_id, &conf_fec_mode);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR(
//            "Failed to set FEC mode for port %d: %s. Failed to get configured "
//            "fec mode",
//            (port_id & 0xFFFF),
//            sai_status_to_string(status));
//        return status;
//      }
//
//      if (conf_fec_mode != fec_mode) {
//        switch_status = switch_api_port_fec_mode_set(device, port_id, fec_mode);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to set port fec mode for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//      } else {
//        VLOG_DBG(
//            "Skipping setting fec mode for port %d. No change in configured "
//            "FEC",
//            (port_id & 0xFFFF));
//      }
//      break;
//
//    case SAI_PORT_ATTR_INGRESS_MIRROR_SESSION:
//      SAI_ASSERT(attr->value.objlist.count == 1);
//      switch_status = switch_api_port_ingress_mirror_set(
//          device, port_id, attr->value.objlist.list[0]);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("Failed to set ingress port mirror for prot %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_EGRESS_MIRROR_SESSION:
//      SAI_ASSERT(attr->value.objlist.count == 1);
//      switch_status = switch_api_port_egress_mirror_set(
//          device, port_id, attr->value.objlist.list[0]);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("Failed to set egress port mirror for prot %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//
//    case SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID:
//      switch_status = switch_api_port_scheduler_profile_set(
//          device, port_id, attr->value.oid);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("Failed to set port scheduler for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//    case SAI_PORT_ATTR_DROP_UNTAGGED:
//      switch_status = switch_api_port_drop_untagged_packet_set(
//          device, port_id, attr->value.booldata);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set drop_untagged attribute for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//    case SAI_PORT_ATTR_DROP_TAGGED:
//      switch_status = switch_api_port_drop_tagged_packet_set(
//          device, port_id, attr->value.booldata);
//      status = sai_switch_status_to_sai_status(switch_status);
//      if (status != SAI_STATUS_SUCCESS) {
//        VLOG_ERR("failed to set drop_tagged attribute for port %d: %s",
//                      (port_id & 0xFFFF),
//                      sai_status_to_string(status));
//        return status;
//      }
//      break;
//    default:
//      VLOG_ERR("Port Attr Set Not supported %d %s\n",
//                    attr->id,
//                    port_attr_map[attr->id]);
//      return SAI_STATUS_NOT_SUPPORTED;
//      break;
//  }
//
//  SAI_LOG_EXIT();
//
//  return (sai_status_t)status;
//}
//

/*
 * Return SAI port speed from switchApi port speed.
 * SAI expects speed in Mbps.
 */
//
//uint32_t switch_api_port_speed_to_sai_port_speed(
//    switch_port_speed_t port_speed) {
//  switch (port_speed) {
//    case SWITCH_PORT_SPEED_10G:
//      return 10000;
//    case SWITCH_PORT_SPEED_25G:
//      return 25000;
//    case SWITCH_PORT_SPEED_40G:
//      return 40000;
//    case SWITCH_PORT_SPEED_50G:
//      return 50000;
//    case SWITCH_PORT_SPEED_100G:
//      return 100000;
//    default:
//      return 0;
//  }
//}
//
//static void sai_port_qos_map_handle(switch_handle_t qos_handle,
//                                    switch_qos_map_ingress_t ingress_type,
//                                    switch_qos_map_egress_t egress_type,
//                                    uint32_t attr_id,
//                                    uint64_t *handle) {
//  bool handle_valid = FALSE;
//  switch (attr_id) {
//    case SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP:
//      if (ingress_type == SWITCH_QOS_MAP_INGRESS_PCP_TO_TC) {
//        *handle = qos_handle;
//        handle_valid = TRUE;
//      }
//      break;
//
//    case SAI_PORT_ATTR_QOS_DOT1P_TO_COLOR_MAP:
//      if (ingress_type == SWITCH_QOS_MAP_INGRESS_PCP_TO_COLOR) {
//        *handle = qos_handle;
//        handle_valid = TRUE;
//      }
//      break;
//
//    case SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP:
//      if (ingress_type == SWITCH_QOS_MAP_INGRESS_DSCP_TO_TC) {
//        *handle = qos_handle;
//        handle_valid = TRUE;
//      }
//      break;
//
//    case SAI_PORT_ATTR_QOS_DSCP_TO_COLOR_MAP:
//      if (ingress_type == SWITCH_QOS_MAP_INGRESS_DSCP_TO_COLOR) {
//        *handle = qos_handle;
//        handle_valid = TRUE;
//      }
//      break;
//
//    case SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP:
//      if (egress_type == SWITCH_QOS_MAP_EGRESS_TC_AND_COLOR_TO_PCP) {
//        *handle = qos_handle;
//        handle_valid = TRUE;
//      }
//      break;
//    case SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP:
//      if (egress_type == SWITCH_QOS_MAP_EGRESS_TC_AND_COLOR_TO_DSCP) {
//        *handle = qos_handle;
//        handle_valid = TRUE;
//      }
//      break;
//
//    default:
//      handle_valid = FALSE;
//      break;
//  }
//  if (handle_valid == FALSE) {
//    *handle = SAI_NULL_OBJECT_ID;
//  }
//}
//
/*
* Routine Description:
*   Get port attribute value.
*
* Arguments:
*    [in] port_id - port id
*    [in] attr_count - number of attributes
*    [inout] attr_list - array of attributes
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/

sai_status_t sai_get_port_attribute(_In_ sai_object_id_t port_id,
                                    _In_ uint32_t attr_count,
                                    _Inout_ sai_attribute_t *attr_list) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    return status;
}

//sai_status_t sai_get_port_attribute(_In_ sai_object_id_t port_id,
//                                    _In_ uint32_t attr_count,
//                                    _Inout_ sai_attribute_t *attr_list) {
//  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
//  unsigned int i = 0;
//  unsigned int index = 0;
//  sai_attribute_t *attr = attr_list;
//  sai_status_t status = SAI_STATUS_SUCCESS;
//  switch_port_oper_status_t oper_status = 0;
//  switch_handle_t acl_handle;
//  switch_handle_t cpu_port_handle = 0;
//  sai_object_list_t *objlist = NULL;
//  switch_uint32_t max_queues = 0;
//  switch_handle_t *queue_handles = NULL;
//  switch_handle_t meter_handle;
//  switch_port_loopback_mode_t switch_loopback_mode;
//  bool rx_pause = FALSE;
//  bool tx_pause = FALSE;
//  switch_uint32_t pfc_map = 0;
//  switch_port_auto_neg_mode_t auto_neg_mode;
//  switch_port_speed_t port_speed = 0;
//  switch_uint32_t rx_mtu = 0;
//  switch_uint32_t tx_mtu = 0;
//  switch_port_fec_mode_t fec_mode = SWITCH_PORT_FEC_MODE_NONE;
//  switch_port_t port_num = 0;
//  switch_direction_t dir;
//  switch_qos_map_ingress_t map_ingress;
//  switch_qos_map_egress_t map_egress;
//  switch_handle_t ingress_qos_handle = SWITCH_API_INVALID_HANDLE,
//                  egress_qos_handle = SWITCH_API_INVALID_HANDLE,
//                  tc_queue_handle = SWITCH_API_INVALID_HANDLE,
//                  tc_ppg_handle = SWITCH_API_INVALID_HANDLE,
//                  mirror_handle = SWITCH_API_INVALID_HANDLE,
//                  sflow_handle = SWITCH_API_INVALID_HANDLE,
//                  qos_handle = SWITCH_API_INVALID_HANDLE;
//  switch_uint8_t num_ppgs = 0;
//  switch_handle_t *ppg_handles = NULL;
//  switch_uint32_t group_count = 0;
//  switch_handle_t *group_handles = NULL;
//  switch_handle_t scheduler_handle = SWITCH_API_INVALID_HANDLE;
//  switch_port_lane_list_t lane_list;
//
//  SAI_LOG_ENTER();
//
//  if (!attr_list) {
//    status = SAI_STATUS_INVALID_PARAMETER;
//    VLOG_ERR("null attribute list: %s", sai_status_to_string(status));
//    return status;
//  }
//  for (i = 0, attr = attr_list; i < attr_count; i++, attr++) {
//    switch (attr->id) {
//      case SAI_PORT_ATTR_TYPE: {
//        switch_api_device_cpu_port_handle_get(device, &cpu_port_handle);
//        if (cpu_port_handle == (switch_handle_t)port_id)
//          attr->value.s32 = SAI_PORT_TYPE_CPU;
//        else
//          attr->value.s32 = SAI_PORT_TYPE_LOGICAL;
//      } break;
//
//      case SAI_PORT_ATTR_CURRENT_BREAKOUT_MODE_TYPE:
//      case SAI_PORT_ATTR_HW_LANE_LIST:
//        memset(&lane_list, 0x0, sizeof(lane_list));
//        status = switch_api_port_lane_list_get(device, port_id, &lane_list);
//        if (status != SWITCH_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get port %d lane list: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        if (attr->id == SAI_PORT_ATTR_HW_LANE_LIST) {
//          attr->value.u32list.count = lane_list.num_lanes;
//          for (index = 0; index < lane_list.num_lanes; index++) {
//            attr->value.u32list.list[index] = lane_list.lane[index];
//          }
//        } else {
//          if (lane_list.num_lanes == 1) {
//            attr->value.s32 = SAI_PORT_BREAKOUT_MODE_TYPE_1_LANE;
//          } else if (lane_list.num_lanes == 2) {
//            attr->value.s32 = SAI_PORT_BREAKOUT_MODE_TYPE_2_LANE;
//          } else {
//            attr->value.s32 = SAI_PORT_BREAKOUT_MODE_TYPE_4_LANE;
//          }
//        }
//        break;
//      case SAI_PORT_ATTR_SUPPORTED_BREAKOUT_MODE_TYPE:
//        attr->value.s32list.count = 3;
//        attr->value.s32list.list[0] = SAI_PORT_BREAKOUT_MODE_TYPE_4_LANE;
//        attr->value.s32list.list[1] = SAI_PORT_BREAKOUT_MODE_TYPE_2_LANE;
//        attr->value.s32list.list[2] = SAI_PORT_BREAKOUT_MODE_TYPE_1_LANE;
//        status = SAI_STATUS_SUCCESS;
//        break;
//      case SAI_PORT_ATTR_OPER_STATUS:
//        switch_status = switch_api_port_oper_status_get(
//            device, (switch_handle_t)(port_id), &(oper_status));
//        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get port %d oper state: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        status = sai_switch_port_enabled_to_sai_oper_status(oper_status, attr);
//        break;
//      case SAI_PORT_ATTR_SPEED:
//        switch_status = switch_api_port_speed_get(
//            device, (switch_handle_t)(port_id), &port_speed);
//        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get port %d speed: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.u32 = switch_api_port_speed_to_sai_port_speed(port_speed);
//        break;
//      case SAI_PORT_ATTR_ADVERTISED_SPEED:
//        switch_status = switch_api_port_speed_get(
//            device, (switch_handle_t)(port_id), &port_speed);
//        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get advertised port %d speed: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        if (attr->value.u32list.list) {
//          attr->value.u32list.list[0] =
//              switch_api_port_speed_to_sai_port_speed(port_speed);
//        }
//        attr->value.u32list.count = 1;
//        break;
//      case SAI_PORT_ATTR_SUPPORTED_SPEED:
//        switch_api_device_cpu_port_handle_get(device, &cpu_port_handle);
//        if (attr->value.u32list.list) {
//          attr->value.u32list.list[0] = 10000;
//          attr->value.u32list.list[1] = 25000;
//        }
//        attr->value.u32list.count = 2;
//        // get port number from handle
//        switch_status = switch_api_port_handle_to_id_get(
//            device, (switch_handle_t)port_id, &port_num);
//        if (switch_status == SWITCH_STATUS_SUCCESS) {
//          if ((port_num % 2) == 0) {
//            if (attr->value.u32list.list)
//              attr->value.u32list.list[attr->value.u32list.count] = 50000;
//            attr->value.u32list.count++;
//          }
//          if ((port_num % 4) == 0) {
//            if (attr->value.u32list.list)
//              attr->value.u32list.list[attr->value.u32list.count] = 40000;
//            attr->value.u32list.count++;
//            if (attr->value.u32list.list)
//              attr->value.u32list.list[attr->value.u32list.count] = 100000;
//            attr->value.u32list.count++;
//          }
//        }
//        if (cpu_port_handle == (switch_handle_t)port_id) {
//          if (attr->value.u32list.list)
//            attr->value.u32list.list[attr->value.u32list.count] = 1000;
//          attr->value.u32list.count++;
//        }
//        if (attr->value.u32list.list)
//          status = SAI_STATUS_SUCCESS;
//        else
//          status = SAI_STATUS_BUFFER_OVERFLOW;
//        break;
//      case SAI_PORT_ATTR_INGRESS_ACL:
//        switch_status =
//            switch_api_port_ingress_acl_group_get(device, port_id, &acl_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SWITCH_STATUS_SUCCESS) {
//          return status;
//        }
//        attr->value.oid = (acl_handle == SWITCH_API_INVALID_HANDLE)
//                              ? SAI_NULL_OBJECT_ID
//                              : acl_handle;
//        break;
//      case SAI_PORT_ATTR_EGRESS_ACL:
//        switch_status =
//            switch_api_port_egress_acl_group_get(device, port_id, &acl_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SWITCH_STATUS_SUCCESS) {
//          return status;
//        }
//        attr->value.oid = (acl_handle == SWITCH_API_INVALID_HANDLE)
//                              ? SAI_NULL_OBJECT_ID
//                              : acl_handle;
//        break;
//      case SAI_PORT_ATTR_ADMIN_STATE:
//        switch_status = switch_api_port_admin_state_get(
//            device, (switch_handle_t)(port_id), &(attr->value.booldata));
//        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get port %d admin state: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        break;
//      case SAI_PORT_ATTR_QOS_NUMBER_OF_QUEUES:
//        switch_status = switch_api_port_max_queues_get(
//            device, (switch_handle_t)(port_id), &max_queues);
//        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get max queues for port %d : %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.u32 = max_queues;
//        break;
//
//      case SAI_PORT_ATTR_QOS_QUEUE_LIST:
//      case SAI_PORT_ATTR_QOS_EGRESS_BUFFER_PROFILE_LIST:
//        switch_status = switch_api_port_max_queues_get(
//            device, (switch_handle_t)(port_id), &max_queues);
//
//        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get max queues for port %d admin state: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        objlist = &attr->value.objlist;
//        objlist->count = max_queues;
//
//        queue_handles = SAI_MALLOC(sizeof(switch_handle_t) * max_queues);
//        if (!queue_handles) {
//          status = SAI_STATUS_NO_MEMORY;
//          VLOG_ERR("Failed to create list of queue handles: %s",
//                        sai_status_to_string(status));
//          return status;
//        }
//        max_queues = 0;
//        if ((status = switch_api_queues_get(device,
//                                            (switch_handle_t)(port_id),
//                                            &max_queues,
//                                            queue_handles)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to retrieve queue handle list for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          SAI_FREE(queue_handles);
//          return status;
//        }
//        SAI_ASSERT(objlist->list);
//        if (attr->id == SAI_PORT_ATTR_QOS_QUEUE_LIST) {
//          for (i = 0; i < max_queues; i++) {
//            objlist->list[i] = (sai_object_id_t)queue_handles[i];
//          }
//        }
//        if (attr->id == SAI_PORT_ATTR_QOS_EGRESS_BUFFER_PROFILE_LIST) {
//          for (i = 0; i < max_queues; i++) {
//            switch_handle_t prof_handle = SWITCH_API_INVALID_HANDLE;
//            switch_status = switch_api_queue_buffer_profile_get(
//                device, queue_handles[i], &prof_handle);
//            status = sai_switch_status_to_sai_status(switch_status);
//            if (status != SAI_STATUS_SUCCESS) {
//              VLOG_ERR(
//                  "Failed to get buffer profile handle for queue 0x%lx: %s",
//                  queue_handles[i],
//                  sai_status_to_string(status));
//              return status;
//            }
//            objlist->list[i] = (sai_object_id_t)prof_handle;
//          }
//        }
//        SAI_FREE(queue_handles);
//        break;
//
//      case SAI_PORT_ATTR_FLOOD_STORM_CONTROL_POLICER_ID:
//      case SAI_PORT_ATTR_MULTICAST_STORM_CONTROL_POLICER_ID:
//      case SAI_PORT_ATTR_BROADCAST_STORM_CONTROL_POLICER_ID:
//        switch_status = switch_api_port_storm_control_get(
//            device,
//            port_id,
//            sai_storm_to_switch_packet_type(attr->id),
//            &meter_handle);
//
//        if (meter_handle == SWITCH_API_INVALID_HANDLE) {
//          attr->value.oid = SAI_NULL_OBJECT_ID;
//        }
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get storm control policer for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = meter_handle;
//        break;
//      case SAI_PORT_ATTR_INTERNAL_LOOPBACK_MODE:
//        switch_status = switch_api_port_loopback_mode_get(
//            device, port_id, &switch_loopback_mode);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get loopback mode for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = switch_api_loopback_mode_to_sai(switch_loopback_mode);
//        break;
//      case SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL_MODE:
//        switch_status = switch_api_port_link_pause_get(
//            device, port_id, &rx_pause, &tx_pause);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get loopback mode for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        if (rx_pause && tx_pause) {
//          attr->value.oid = SAI_PORT_FLOW_CONTROL_MODE_BOTH_ENABLE;
//        } else if (rx_pause) {
//          attr->value.oid = SAI_PORT_FLOW_CONTROL_MODE_RX_ONLY;
//        } else if (tx_pause) {
//          attr->value.oid = SAI_PORT_FLOW_CONTROL_MODE_TX_ONLY;
//        } else {
//          attr->value.oid = SAI_PORT_FLOW_CONTROL_MODE_DISABLE;
//        }
//        break;
//
//      case SAI_PORT_ATTR_PRIORITY_FLOW_CONTROL:
//        switch_status = switch_api_port_pfc_get(device, port_id, &pfc_map);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get pfc for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = pfc_map;
//        break;
//
//      case SAI_PORT_ATTR_AUTO_NEG_MODE:
//        switch_status =
//            switch_api_port_auto_neg_get(device, port_id, &auto_neg_mode);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to set autoneg mode for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.booldata =
//            (auto_neg_mode == SWITCH_PORT_AUTO_NEG_MODE_DISABLE) ? false : true;
//        break;
//
//      case SAI_PORT_ATTR_MTU:
//        switch_api_port_mtu_get(device, port_id, &tx_mtu, &rx_mtu);
//        attr->value.u32 = rx_mtu;
//        break;
//
//      case SAI_PORT_ATTR_FEC_MODE:
//        switch_status =
//            switch_api_port_fec_mode_get(device, port_id, &fec_mode);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to get FEC mode for port %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.u32 = switch_api_fec_mode_to_sai_fec(fec_mode);
//        break;
//
//      case SAI_PORT_ATTR_QOS_DOT1P_TO_COLOR_MAP:
//      case SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP:
//      case SAI_PORT_ATTR_QOS_DSCP_TO_TC_MAP:
//      case SAI_PORT_ATTR_QOS_DSCP_TO_COLOR_MAP:
//      case SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP:
//      case SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DOT1P_MAP:
//      case SAI_PORT_ATTR_QOS_TC_AND_COLOR_TO_DSCP_MAP:
//      case SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP:
//        switch_status = switch_api_port_qos_group_get(device,
//                                                      port_id,
//                                                      &ingress_qos_handle,
//                                                      &tc_queue_handle,
//                                                      &tc_ppg_handle,
//                                                      &egress_qos_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get port qosmap for port %lx: %s",
//                        port_id,
//                        sai_status_to_string(status));
//          return status;
//        }
//        if (attr->id == SAI_PORT_ATTR_QOS_TC_TO_QUEUE_MAP) {
//          attr->value.oid = tc_queue_handle;
//          continue;
//        }
//        if (attr->id == SAI_PORT_ATTR_QOS_TC_TO_PRIORITY_GROUP_MAP) {
//          attr->value.oid = tc_ppg_handle;
//          continue;
//        }
//        if ((attr->id >= SAI_PORT_ATTR_QOS_DOT1P_TO_TC_MAP) &&
//            (attr->id <= SAI_PORT_ATTR_QOS_DSCP_TO_COLOR_MAP)) {
//          qos_handle = ingress_qos_handle;
//        } else {
//          qos_handle = egress_qos_handle;
//        }
//
//        if (qos_handle) {
//          switch_status = switch_api_qos_map_type_get(
//              device, qos_handle, &dir, &map_ingress, &map_egress);
//          status = sai_switch_status_to_sai_status(switch_status);
//          if (status != SAI_STATUS_SUCCESS) {
//            VLOG_ERR("failed to get qosmap type for port %lx: %s",
//                          port_id,
//                          sai_status_to_string(status));
//            return status;
//          }
//          sai_port_qos_map_handle(qos_handle,
//                                  map_ingress,
//                                  map_egress,
//                                  attr->id,
//                                  &(attr->value.oid));
//        } else {
//          attr->value.oid = SAI_NULL_OBJECT_ID;
//        }
//        break;
//
//      case SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_PRIORITY_GROUP_MAP:
//        switch_status = switch_api_port_icos_to_ppg_get(
//            device, port_id, &ingress_qos_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR(
//              "Failed to get port pfc priority to PG group map for port 0x%lx: "
//              "%s",
//              port_id,
//              sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = ingress_qos_handle;
//        break;
//
//      case SAI_PORT_ATTR_QOS_PFC_PRIORITY_TO_QUEUE_MAP:
//        switch_status = switch_api_port_pfc_priority_to_queue_get(
//            device, port_id, &ingress_qos_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR(
//              "Failed to get pfc priority to queue map for port 0x%lx: %s",
//              port_id,
//              sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = ingress_qos_handle;
//        break;
//
//      case SAI_PORT_ATTR_NUMBER_OF_INGRESS_PRIORITY_GROUPS:
//      case SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST:
//      case SAI_PORT_ATTR_QOS_INGRESS_BUFFER_PROFILE_LIST:
//        switch_status = switch_api_port_max_ppg_get(device, port_id, &num_ppgs);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to get port's max PPG for port 0x%lx: %s",
//                        port_id,
//                        sai_status_to_string(status));
//          return status;
//        }
//        if (attr->id == SAI_PORT_ATTR_NUMBER_OF_INGRESS_PRIORITY_GROUPS) {
//          attr->value.u32 = num_ppgs;
//          break;
//        }
//        ppg_handles =
//            (switch_handle_t *)SAI_MALLOC(num_ppgs * sizeof(switch_handle_t));
//        switch_status =
//            switch_api_port_ppg_get(device, port_id, &num_ppgs, ppg_handles);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to get port's PPG handles for port 0x%lx: %s",
//                        port_id,
//                        sai_status_to_string(status));
//          SAI_FREE(ppg_handles);
//          return status;
//        }
//        objlist = &attr->value.objlist;
//        objlist->count = num_ppgs;
//        if (attr->id == SAI_PORT_ATTR_INGRESS_PRIORITY_GROUP_LIST) {
//          for (i = 0; i < num_ppgs; i++) {
//            objlist->list[i] = (sai_object_id_t)ppg_handles[i];
//          }
//        }
//
//        if (attr->id == SAI_PORT_ATTR_QOS_INGRESS_BUFFER_PROFILE_LIST) {
//          for (i = 0; i < num_ppgs; i++) {
//            switch_handle_t ppg_profile_handle = SWITCH_API_INVALID_HANDLE;
//            switch_status = switch_api_priority_group_buffer_profile_get(
//                device, ppg_handles[i], &ppg_profile_handle);
//            status = sai_switch_status_to_sai_status(switch_status);
//            if (status != SAI_STATUS_SUCCESS) {
//              VLOG_ERR(
//                  "Failed to get buffer profile handle for PG 0x%lx: %s",
//                  ppg_handles[i],
//                  sai_status_to_string(status));
//              SAI_FREE(ppg_handles);
//              return status;
//            }
//            if (ppg_profile_handle == SWITCH_API_INVALID_HANDLE) {
//              VLOG_ERR("PPG profile handle is null for port 0x%lx",
//                            port_id);
//            }
//            objlist->list[i] = (sai_object_id_t)ppg_profile_handle;
//          }
//        }
//        SAI_FREE(ppg_handles);
//        break;
//
//      case SAI_PORT_ATTR_QOS_NUMBER_OF_SCHEDULER_GROUPS:
//      case SAI_PORT_ATTR_QOS_SCHEDULER_GROUP_LIST:
//        switch_status = switch_api_port_queue_scheduler_group_handle_count_get(
//            device, port_id, &group_count);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR(
//              "Failed to get number of scheduler groups for port 0x%lx: %s",
//              port_id,
//              sai_status_to_string(status));
//          return status;
//        }
//        if (attr->id == SAI_PORT_ATTR_QOS_NUMBER_OF_SCHEDULER_GROUPS) {
//          attr->value.u32 = group_count;
//          break;
//        }
//        if (group_count) {
//          group_handles = SAI_MALLOC(group_count * sizeof(switch_handle_t));
//          switch_status = switch_api_port_qos_scheduler_group_handles_get(
//              device, port_id, group_handles);
//          status = sai_switch_status_to_sai_status(switch_status);
//          if (status != SAI_STATUS_SUCCESS) {
//            VLOG_ERR(
//                "Failed to get scheduler group handles for port 0x%lx: %s",
//                port_id,
//                sai_status_to_string(status));
//            SAI_FREE(group_handles);
//            return status;
//          }
//          objlist = &attr->value.objlist;
//          objlist->count = group_count;
//          for (i = 0; i < group_count; i++) {
//            objlist->list[i] = (sai_object_id_t)(group_handles[i]);
//          }
//          SAI_FREE(group_handles);
//        }
//        break;
//
//      case SAI_PORT_ATTR_INGRESS_MIRROR_SESSION:
//        switch_status =
//            switch_api_port_ingress_mirror_get(device, port_id, &mirror_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to get ingress port mirror for prot %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = mirror_handle;
//        break;
//
//      case SAI_PORT_ATTR_EGRESS_MIRROR_SESSION:
//        switch_status =
//            switch_api_port_egress_mirror_get(device, port_id, &mirror_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to get egress port mirror for prot %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = mirror_handle;
//        break;
//
//      case SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE:
//        switch_status = switch_api_port_ingress_sflow_handle_get(
//            device, port_id, &sflow_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to get ingress sflow handle for prot %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = sflow_handle;
//        break;
//
//      case SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE:
//        switch_status = switch_api_port_egress_sflow_handle_get(
//            device, port_id, &sflow_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to get egress sflow handle for prot %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = sflow_handle;
//        break;
//
//      case SAI_PORT_ATTR_QOS_SCHEDULER_PROFILE_ID:
//        switch_status = switch_api_port_scheduler_profile_get(
//            device, port_id, &scheduler_handle);
//        status = sai_switch_status_to_sai_status(switch_status);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("Failed to get scheduler handle for prot %d: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.oid = scheduler_handle;
//        break;
//      case SAI_PORT_ATTR_DROP_UNTAGGED: {
//        bool drop_untagged_Pkt;
//        switch_status = switch_api_port_drop_untagged_packet_get(
//            device, (switch_handle_t)(port_id), &drop_untagged_Pkt);
//        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get port %d speed: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.booldata = drop_untagged_Pkt;
//        break;
//      }
//      case SAI_PORT_ATTR_DROP_TAGGED: {
//        bool drop_tagged_Pkt;
//        switch_status = switch_api_port_drop_tagged_packet_get(
//            device, (switch_handle_t)(port_id), &drop_tagged_Pkt);
//        if ((status = sai_switch_status_to_sai_status(switch_status)) !=
//            SAI_STATUS_SUCCESS) {
//          VLOG_ERR("failed to get port %d speed: %s",
//                        (port_id & 0xFFFF),
//                        sai_status_to_string(status));
//          return status;
//        }
//        attr->value.booldata = drop_tagged_Pkt;
//        break;
//      }
//      default:
//        VLOG_ERR("Port Attr Get Not supported %d %s\n",
//                      attr->id,
//                      port_attr_map[attr->id]);
//        status = SAI_STATUS_NOT_SUPPORTED;
//        break;
//    }
//  }
//
//  SAI_LOG_EXIT();
//
//  return (sai_status_t)status;
//}

/**
 * * @brief Create port
 * *
 * * @param[out] port_id Port id
 * * @param[in] switch_id Switch id
 * * @param[in] attr_count Number of attributes
 * * @param[in] attr_list Array of attributes
 * *
 * * @return #SAI_STATUS_SUCCESS on success Failure status code on error
 * */
sai_status_t sai_create_port(_Out_ sai_object_id_t *port_id,
                             _In_ sai_object_id_t switch_id,
                             _In_ uint32_t attr_count,
                             _In_ const sai_attribute_t *attr_list) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    const sai_attribute_t *attribute = NULL;
    uint64_t portid = 0;
    uint32_t mtu = 0;

    switch_device_t device = 0;

    switch_handle_t port_handle = SWITCH_API_INVALID_HANDLE;
    switch_api_port_info_t api_port_info = {0};

    VLOG_INFO("[SAI_CREATE_PORT] called ..\n");

    for (uint32_t index = 0; index < attr_count; index++) {
        attribute = &attr_list[index];
        switch (attribute->id) {
            case SAI_PORT_ATTR_HW_LANE_LIST:
                portid = attribute->value.oid;
                VLOG_INFO("[SAI_CREATE_PORT]: Port ID = %d\n", portid);
                break;
            case SAI_PORT_ATTR_MTU:
                mtu = attribute->value.u32;
                VLOG_INFO("[SAI_CREATE_PORT]: MTU = %d\n", mtu);
                break;
            default:
                status = SAI_STATUS_NOT_IMPLEMENTED;
        }
    }

   // UDIT: Re-create strucutre and populate only required parametes ??
   // Filling some commmon attrs with above values for now
      api_port_info.port = portid;
      api_port_info.tx_mtu = mtu;
      api_port_info.rx_mtu = mtu;
    //api_port_info.port_speed = SWITCH_PORT_SPEED_25G;
   // api_port_info.fec_mode = fec_mode;
   // api_port_info.initial_admin_state = admin_state;
   // api_port_info.non_default_ppgs = switch_sai_port_non_default_ppgs();

    status = switch_api_port_add(device, &api_port_info, &port_handle);
    return status;
}

//sai_status_t sai_create_port(_Out_ sai_object_id_t *port_id,
//                             _In_ sai_object_id_t switch_id,
//                             _In_ uint32_t attr_count,
//                             _In_ const sai_attribute_t *attr_list) {
//  switch_lane_t lane_number = 0;
//  switch_lane_t lane_count = 0;
//  const sai_attribute_t *attribute = NULL;
//  switch_port_speed_t port_speed = SWITCH_PORT_SPEED_25G;
//  switch_api_port_info_t api_port_info = {0};
//  sai_status_t status = SAI_STATUS_SUCCESS;
//  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
//  switch_handle_t port_handle = SWITCH_API_INVALID_HANDLE;
//  switch_port_fec_mode_t fec_mode = SWITCH_PORT_FEC_MODE_NONE;
//  bool admin_state = FALSE;
//  switch_port_auto_neg_mode_t auto_neg_mode = SWITCH_PORT_AUTO_NEG_MODE_DEFAULT;
//
//  *port_id = SAI_NULL_OBJECT_ID;
//  for (uint32_t index = 0; index < attr_count; index++) {
//    attribute = &attr_list[index];
//    switch (attribute->id) {
//      case SAI_PORT_ATTR_HW_LANE_LIST:
//        SAI_ASSERT(attribute->value.s32list.count != 0);
//        lane_number = attribute->value.s32list.list[0];
//        lane_count = attribute->value.s32list.count;
//        break;
//      case SAI_PORT_ATTR_ADMIN_STATE:
//        admin_state = attribute->value.booldata;
//        break;
//      case SAI_PORT_ATTR_SPEED:
//        port_speed =
//            switch_sai_port_speed_to_switch_port_speed(attribute->value.u32);
//        break;
//      case SAI_PORT_ATTR_FEC_MODE:
//        fec_mode = sai_fec_mode_to_switch_fec(attribute->value.u32);
//        break;
//      case SAI_PORT_ATTR_AUTO_NEG_MODE:
//        if (attribute->value.booldata) {
//          auto_neg_mode = SWITCH_PORT_AUTO_NEG_MODE_ENABLE;
//        } else {
//          auto_neg_mode = SWITCH_PORT_AUTO_NEG_MODE_DISABLE;
//        }
//        break;
//      default:
//        status = SAI_STATUS_NOT_IMPLEMENTED;
//    }
//  }
//
//  api_port_info.port = lane_number;
//  if (port_speed) {
//    api_port_info.port_speed = port_speed;
//  } else if (lane_count == 1) {
//    api_port_info.port_speed = SWITCH_PORT_SPEED_25G;
//  } else if (lane_count == 2) {
//    api_port_info.port_speed = SWITCH_PORT_SPEED_50G;
//  } else if (lane_count == 4) {
//    api_port_info.port_speed = SWITCH_PORT_SPEED_100G;
//  } else {
//    VLOG_ERR("create port failed: port lane count %d invalid", lane_count);
//    return SAI_STATUS_INVALID_PARAMETER;
//  }
//
//  api_port_info.fec_mode = fec_mode;
//  api_port_info.initial_admin_state = admin_state;
//  api_port_info.non_default_ppgs = switch_sai_port_non_default_ppgs();
//  switch_status = switch_api_port_add(device, &api_port_info, &port_handle);
//  status = sai_switch_status_to_sai_status(switch_status);
//  if (status != SAI_STATUS_SUCCESS) {
//    VLOG_ERR("create port failed: %s", sai_status_to_string(status));
//    return status;
//  }
//  if (auto_neg_mode != SWITCH_PORT_AUTO_NEG_MODE_DEFAULT) {
//    switch_status =
//        switch_api_port_auto_neg_set(device, port_handle, auto_neg_mode);
//    status = sai_switch_status_to_sai_status(switch_status);
//    if (status != SAI_STATUS_SUCCESS) {
//      VLOG_ERR("Failed to set autoneg mode for port 0x%lx: %s",
//                    port_handle,
//                    sai_status_to_string(status));
//      return status;
//    }
//  }
//
//  *port_id = port_handle;
//  return status;
//}

sai_status_t sai_remove_port(_In_ sai_object_id_t port_id) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    return status;
}

//sai_status_t sai_remove_port(_In_ sai_object_id_t port_id) {
//  sai_status_t status = SAI_STATUS_SUCCESS;
//  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
//
//  switch_status = switch_api_port_delete(device, port_id);
//  status = sai_switch_status_to_sai_status(switch_status);
//  if (status != SAI_STATUS_SUCCESS) {
//    VLOG_ERR("remove port failed: %s", sai_status_to_string(status));
//    return status;
//  }
//  return status;
//}
//
/*
* Routine Description:
*   Get port statistics counters.
*
* Arguments:
*    [in] port_id - port id
*    [in] counter_ids - specifies the array of counter ids
*    [in] number_of_counters - number of counters in the array
*    [out] counters - array of resulting counter values.
*
* Return Values:
*    SAI_STATUS_SUCCESS on success
*    Failure status code on error
*/


sai_status_t sai_get_port_stats(_In_ sai_object_id_t port_id,
                                _In_ uint32_t number_of_counters,
                                _In_ const sai_stat_id_t *counter_ids,
                                _Out_ uint64_t *counters) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    return status;
}

//sai_status_t sai_get_port_stats(_In_ sai_object_id_t port_id,
//                                _In_ uint32_t number_of_counters,
//                                _In_ const sai_stat_id_t *counter_ids,
//                                _Out_ uint64_t *counters) {
//  SAI_LOG_ENTER();
//
//  sai_status_t status = SAI_STATUS_SUCCESS;
//  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
//  switch_port_counter_id_t *switch_counter_ids = NULL;
//  switch_port_counter_id_t switch_counter_id;
//  uint64_t switch_counters[number_of_counters];
//  uint64_t drop_count = 0;
//  uint64_t in_bytes = 0;
//  uint64_t out_bytes = 0;
//  uint64_t in_wm = 0;
//  uint64_t out_wm = 0;
//
//  memset(switch_counters, 0, sizeof(switch_counters));
//
//  uint32_t index = 0;
//
//  switch_counter_ids =
//      SAI_MALLOC(number_of_counters * sizeof(switch_port_counter_id_t));
//  for (index = 0; index < number_of_counters; index++) {
//    status = sai_port_counter_to_switch_port_counter(counter_ids[index],
//                                                     &switch_counter_id);
//    if (status != SAI_STATUS_SUCCESS) {
//      VLOG_INFO("failed to map port stat id %d for port 0x%x: %s",
//                   counter_ids[index],
//                   port_id,
//                   sai_status_to_string(status));
//      SAI_FREE(switch_counter_ids);
//      return status;
//    }
//    switch_counter_ids[index] = switch_counter_id;
//  }
//
//  switch_status = switch_api_port_stats_get(
//      device, port_id, number_of_counters, switch_counter_ids, switch_counters);
//  status = sai_switch_status_to_sai_status(switch_status);
//  if (status != SAI_STATUS_SUCCESS) {
//    //    VLOG_ERR("sai get port stats for prt 0x%x : %s", port_id,
//    //    sai_status_to_string(status));
//    //    SAI_FREE(switch_counter_ids);
//    //    return status;
//  }
//
//  for (index = 0; index < number_of_counters; index++) {
//    switch (counter_ids[index]) {
//      case SAI_PORT_STAT_IF_IN_DISCARDS:
//        status = switch_api_port_ppg_drop_get(device, port_id, &drop_count);
//        counters[index] = drop_count;
//        break;
//
//      case SAI_PORT_STAT_IF_OUT_DISCARDS:
//        status = switch_api_port_queue_drop_get(device, port_id, &drop_count);
//        counters[index] = drop_count;
//        break;
//
//      case SAI_PORT_STAT_ECN_MARKED_PACKETS: {
//        switch_wred_counter_t ecn_counter_id = SWITCH_WRED_STATS_ECN_MARKED;
//        switch_counter_t ecn_counter = {0};
//        status = switch_api_wred_port_stats_get(
//            device, port_id, 1, &ecn_counter_id, &ecn_counter);
//        counters[index] = ecn_counter.num_packets;
//        break;
//      }
//      case SAI_PORT_STAT_IN_CURR_OCCUPANCY_BYTES:
//      case SAI_PORT_STAT_OUT_CURR_OCCUPANCY_BYTES:
//        status = switch_api_port_usage_get(
//            device, port_id, &in_bytes, &out_bytes, &in_wm, &out_wm);
//        if (counter_ids[index] == SAI_PORT_STAT_IN_CURR_OCCUPANCY_BYTES)
//          counters[index] = in_bytes;
//        else
//          counters[index] = out_bytes;
//        break;
//      default:
//        counters[index] = switch_counters[index];
//        break;
//    }
//  }
//
//  if (switch_counter_ids) {
//    SAI_FREE(switch_counter_ids);
//  }
//
//  SAI_LOG_EXIT();
//
//  return (sai_status_t)status;
//}
//
/**
 * @brief Clear port statistics counters.
 *
 * @param[in] port_id Port id
 * @param[in] number_of_counters Number of counters in the array
 * @param[in] counter_ids Specifies the array of counter ids
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */

sai_status_t sai_clear_port_stats(_In_ sai_object_id_t port_id,
                                  _In_ uint32_t number_of_counters,
                                  _In_ const sai_stat_id_t *counter_ids) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    return status;
}


//sai_status_t sai_clear_port_stats(_In_ sai_object_id_t port_id,
//                                  _In_ uint32_t number_of_counters,
//                                  _In_ const sai_stat_id_t *counter_ids) {
//  sai_status_t status = SAI_STATUS_SUCCESS;
//  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
//  switch_port_counter_id_t *switch_counter_ids = NULL;
//  switch_port_counter_id_t switch_counter_id;
//  uint32_t index = 0;
//
//  SAI_LOG_ENTER();
//
//  switch_counter_ids =
//      SAI_MALLOC(number_of_counters * sizeof(switch_port_counter_id_t));
//  for (index = 0; index < number_of_counters; index++) {
//    status = sai_port_counter_to_switch_port_counter(counter_ids[index],
//                                                     &switch_counter_id);
//    if (status != SAI_STATUS_SUCCESS) {
//      VLOG_INFO("failed to map port stat id %d for port 0x%x: %s",
//                   counter_ids[index],
//                   port_id,
//                   sai_status_to_string(status));
//      SAI_FREE(switch_counter_ids);
//      return status;
//    }
//    switch_counter_ids[index] = switch_counter_id;
//  }
//
//  switch_status = switch_api_port_stats_counter_id_clear(
//      device, port_id, number_of_counters, switch_counter_ids);
//  status = sai_switch_status_to_sai_status(switch_status);
//  if (status != SAI_STATUS_SUCCESS) {
//    VLOG_ERR("sai clear port stats: %s", sai_status_to_string(status));
//    SAI_FREE(switch_counter_ids);
//    return status;
//  }
//
//  for (index = 0; index < number_of_counters; index++) {
//    switch (counter_ids[index]) {
//      case SAI_PORT_STAT_IF_IN_DISCARDS:
//        status = switch_api_port_ppg_drop_stats_clear(device, port_id);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("sai clear port stats for counter %d failed: %s",
//                        counter_ids[index],
//                        sai_status_to_string(status));
//          goto cleanup;
//        }
//        break;
//
//      case SAI_PORT_STAT_IF_OUT_DISCARDS:
//        status = switch_api_port_queue_drop_stats_clear(device, port_id);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("sai clear port stats for counter %d failed: %s",
//                        counter_ids[index],
//                        sai_status_to_string(status));
//          goto cleanup;
//        }
//        break;
//
//      case SAI_PORT_STAT_ECN_MARKED_PACKETS: {
//        switch_wred_counter_t ecn_counter_id = SWITCH_WRED_STATS_ECN_MARKED;
//        status = switch_api_wred_port_stats_clear(
//            device, port_id, 1, &ecn_counter_id);
//        if (status != SAI_STATUS_SUCCESS) {
//          VLOG_ERR("sai clear port stats for counter %d failed: %s",
//                        counter_ids[index],
//                        sai_status_to_string(status));
//          goto cleanup;
//        }
//        break;
//      }
//      case SAI_PORT_STAT_IN_CURR_OCCUPANCY_BYTES:
//      case SAI_PORT_STAT_OUT_CURR_OCCUPANCY_BYTES:
//        VLOG_DBG(
//            "Cannot clear PORT IN and OUT Curr Occupancy counters. Counter "
//            "clear skipped");
//        break;
//      default:
//        break;
//    }
//  }
//
//cleanup:
//  SAI_FREE(switch_counter_ids);
//  SAI_LOG_EXIT();
//
//  return status;
//}
//
/**
 * @brief Clear port's all statistics counters.
 *
 * @param[in] port_id Port id
 *
 * @return #SAI_STATUS_SUCCESS on success, failure status code on error
 */

sai_status_t sai_clear_port_all_stats(_In_ sai_object_id_t port_id) {
    sai_status_t status = SAI_STATUS_SUCCESS;
    return status;
}

//sai_status_t sai_clear_port_all_stats(_In_ sai_object_id_t port_id) {
//  sai_status_t status = SAI_STATUS_SUCCESS;
//  switch_status_t switch_status = SWITCH_STATUS_SUCCESS;
//
//  SAI_LOG_ENTER();
//
//  switch_status = switch_api_port_stats_clear(device, port_id);
//  status = sai_switch_status_to_sai_status(switch_status);
//  if (status != SAI_STATUS_SUCCESS) {
//    VLOG_ERR("sai clear all port stats failed 0x%lx: %s",
//                  port_id,
//                  sai_status_to_string(status));
//    return status;
//  }
//
//  SAI_LOG_EXIT();
//
//  return status;
//}

/*
* Port methods table retrieved with sai_api_query()
*/
sai_port_api_t port_api = {.create_port = sai_create_port,
                           .remove_port = sai_remove_port,
                           .set_port_attribute = sai_set_port_attribute,
                           .get_port_attribute = sai_get_port_attribute,
                           .get_port_stats = sai_get_port_stats,
                           .clear_port_stats = sai_clear_port_stats,
                           .clear_port_all_stats = sai_clear_port_all_stats};

sai_status_t sai_port_initialize(sai_api_service_t *sai_api_service) {
  VLOG_DBG("Initializing port");
  sai_api_service->port_api = port_api;
  return SAI_STATUS_SUCCESS;
}
