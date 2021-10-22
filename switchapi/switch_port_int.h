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

#ifndef __SWITCH_PORT_INT_H__
#define __SWITCH_PORT_INT_H__

#define SWITCH_YID_MAX 288

#define SWITCH_YID_INVALID 0x1FF

#define SWITCH_CPU_PORT_DEFAULT 64

#define SWITCH_PORT_INVALID -1

#define SWITCH_PORT_STATE_MAX SWITCH_PORT_STATE_DOWN + 1

#define SWITCH_INVALID_PORT_ID 0xFFFF

#define SWITCH_PPG_HANDLE_SIZE 4096

#define SWITCH_MAX_PPG_10G 1
#define SWITCH_MAX_PPG_100G 2
#define SWITCH_MAX_PPG 8

/*
 * ppg_gmin tm default value: 40(cells) * 80 = 3200 bytes
 */
#define SWITCH_PPG_DEFAULT_GMIN_LIMIT 3200

#define SWITCH_MAX_ICOS 8

#define SWITCH_INVALID_HW_PORT 0x1FF

#define SWITCH_PORT_EVENT_REGISTRATION_MAX 32

#define SWITCH_PORT_STATE_CHANGE_REGISTRATION_MAX 32

#define SWITCH_PORT_RX_MTU_DEFAULT 1600

#define SWITCH_PORT_TX_MTU_DEFAULT 1600

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum switch_port_type_ {
  SWITCH_PORT_TYPE_NORMAL = 0,
  SWITCH_PORT_TYPE_FABRIC = 1,
  SWITCH_PORT_TYPE_CPU = 2,
  SWITCH_PORT_TYPE_RECIRC = 3
} switch_port_type_t;

typedef enum switch_port_queues_s {
  SWITCH_PORT_NUM_QUEUES_8 = 8,
  SWITCH_PORT_NUM_QUEUES_16 = 16,
  SWITCH_PORT_NUM_QUEUES_32 = 32,
  SWITCH_PORT_MAX_QUEUES = 32,
} switch_port_queue_t;

typedef enum switch_port_vlan_xlate_entry_type_s {
  SWITCH_PORT_VLAN_XLATE_ENTRY_TAGGED = 0,
  SWITCH_PORT_VLAN_XLATE_ENTRY_BD = 1,
  SWITCH_PORT_VLAN_XLATE_ENTRY_QINQ = 2,
  SWITCH_PORT_VLAN_XLATE_ENTRY_NOP = 3,
} switch_port_vlan_xlate_entry_type_t;

#define SWITCH_PORT_NHOP_REF_LIST(info) info->PJLarr_nexthops

#define SWITCH_PORT_MALLOC(_d, _n, _p)                  \
  do {                                                  \
    switch_size_t _p_size = sizeof(switch_port_info_t); \
    _p = SWITCH_MALLOC(_d, _p_size, _n);                \
    if (_p) {                                           \
      SWITCH_MEMSET(_port, 0x0, _p_size);               \
    }                                                   \
  } while (0);

#define SWITCH_PORT_FREE(_d, _p) SWITCH_FREE(_d, _p)

/** port handle wrappers */
#define switch_port_handle_create(_device) \
  switch_handle_create(                    \
      _device, SWITCH_HANDLE_TYPE_PORT, sizeof(switch_port_info_t))

#define switch_port_handle_delete(_device, _handle) \
  switch_handle_delete(_device, SWITCH_HANDLE_TYPE_PORT, _handle)

#define switch_port_get(_device, _handle, _info)                    \
  ({                                                                \
    switch_port_info_t *_tmp_port_info = NULL;                      \
    (void)(_tmp_port_info == *_info);                               \
    switch_handle_get(                                              \
        _device, SWITCH_HANDLE_TYPE_PORT, _handle, (void **)_info); \
  })

/** port priority group handle wrappers */
#define switch_ppg_handle_create(_device)                 \
  switch_handle_create(_device,                           \
                       SWITCH_HANDLE_TYPE_PRIORITY_GROUP, \
                       sizeof(switch_port_priority_group_t))

#define switch_ppg_handle_delete(_device, _handle) \
  switch_handle_delete(_device, SWITCH_HANDLE_TYPE_PRIORITY_GROUP, _handle)

#define switch_ppg_get(_device, _handle, _info)                               \
  ({                                                                          \
    switch_port_priority_group_t *_tmp_port_priority_group = NULL;            \
    (void)(_tmp_port_priority_group == *_info);                               \
    switch_handle_get(                                                        \
        _device, SWITCH_HANDLE_TYPE_PRIORITY_GROUP, _handle, (void **)_info); \
  })

#define SWITCH_PORT_DEV_PORT_GET(_device, _port_handle, _dev_port, _status) \
  do {                                                                      \
    switch_port_info_t *_port_info = NULL;                                  \
    _status = SWITCH_STATUS_INVALID_HANDLE;                                 \
    _status = switch_port_get(_device, _port_handle, &_port_info);          \
    if (_port_info) {                                                       \
      _dev_port = _port_info->dev_port;                                     \
    }                                                                       \
  } while (0);


static inline char *switch_port_speed_to_string(
    switch_port_speed_t port_speed) {
  switch (port_speed) {
    case SWITCH_PORT_SPEED_10G:
      return "10G";
    case SWITCH_PORT_SPEED_25G:
      return "25G";
    case SWITCH_PORT_SPEED_40G:
      return "40G";
    case SWITCH_PORT_SPEED_50G:
      return "50G";
    case SWITCH_PORT_SPEED_100G:
      return "100G";
    case SWITCH_PORT_SPEED_NONE:
      return "none";
    default:
      return "unknown";
  }
}

static inline char *switch_port_type_to_string(switch_port_type_t port_type) {
  switch (port_type) {
    case SWITCH_PORT_TYPE_NORMAL:
      return "NORMAL";
    case SWITCH_PORT_TYPE_FABRIC:
      return "FABRIC";
    case SWITCH_PORT_TYPE_CPU:
      return "CPU";
    case SWITCH_PORT_TYPE_RECIRC:
      return "RECIRC";
    default:
      return "unknown";
  }
}

static inline char *switch_port_oper_status_to_string(
    switch_port_oper_status_t oper_status) {
  switch (oper_status) {
    case SWITCH_PORT_OPER_STATUS_UNKNOWN:
      return "UNKNOWN";
    case SWITCH_PORT_OPER_STATUS_UP:
      return "UP";
    case SWITCH_PORT_OPER_STATUS_DOWN:
      return "DOWN";
    default:
      return "NONE";
  }
}

static inline char *switch_port_auto_neg_mode_to_string(
    switch_port_auto_neg_mode_t an_mode) {
  switch (an_mode) {
    case SWITCH_PORT_AUTO_NEG_MODE_DEFAULT:
      return "default";
    case SWITCH_PORT_AUTO_NEG_MODE_ENABLE:
      return "enabled";
    case SWITCH_PORT_AUTO_NEG_MODE_DISABLE:
      return "disabled";
    default:
      return "default";
  }
}

static inline char *switch_port_lb_mode_to_string(
    switch_port_loopback_mode_t lb_mode) {
  switch (lb_mode) {
    case SWITCH_PORT_LOOPBACK_MODE_NONE:
      return "none";
    case SWITCH_PORT_LOOPBACK_MODE_PHY_NEAR:
      return "phy near";
    case SWITCH_PORT_LOOPBACK_MODE_PHY_FAR:
      return "phy far";
    case SWITCH_PORT_LOOPBACK_MODE_MAC_NEAR:
      return "mac near";
    case SWITCH_PORT_LOOPBACK_MODE_MAC_FAR:
      return "mac far";
    default:
      return "none";
  }
}

typedef enum switch_port_num_lanes_s {
  SWITCH_PORT_NUM_LANES_1 = 1,
  SWITCH_PORT_NUM_LANES_2 = 2,
  SWITCH_PORT_NUM_LANES_4 = 4
} switch_port_num_lanes_t;

#define SWITCH_PORT_LANE_MAPPING(_fp_num, _port_speed, _lane_list, _status) \
  do {                                                                      \
    _status = SWITCH_STATUS_SUCCESS;                                        \
    _lane_list.num_lanes = 0;                                               \
    switch (_port_speed) {                                                  \
      case SWITCH_PORT_SPEED_10G:                                           \
      case SWITCH_PORT_SPEED_25G:                                           \
        _lane_list.num_lanes = SWITCH_PORT_NUM_LANES_1;                     \
        _lane_list.lane[0] = _fp_num;                                       \
        break;                                                              \
                                                                            \
      case SWITCH_PORT_SPEED_40G:                                           \
      case SWITCH_PORT_SPEED_100G:                                          \
        _lane_list.num_lanes = SWITCH_PORT_NUM_LANES_4;                     \
        _lane_list.lane[0] = _fp_num;                                       \
        _lane_list.lane[1] = _fp_num + 1;                                   \
        _lane_list.lane[2] = _fp_num + 2;                                   \
        _lane_list.lane[3] = _fp_num + 3;                                   \
        break;                                                              \
                                                                            \
      case SWITCH_PORT_SPEED_50G:                                           \
        _lane_list.num_lanes = SWITCH_PORT_NUM_LANES_2;                     \
        _lane_list.lane[0] = _fp_num;                                       \
        _lane_list.lane[1] = _fp_num + 1;                                   \
        break;                                                              \
                                                                            \
      default:                                                              \
        _status = SWITCH_STATUS_INVALID_PARAMETER;                          \
        break;                                                              \
    }                                                                       \
  } while (0);

#define SWITCH_PORT_VALID(_port)                                            \
  ((_port <= SWITCH_MAX_PORTS) || (_port == SWITCH_CPU_PORT_ETH_DEFAULT) || \
   (_port == SWITCH_CPU_PORT_PCIE_DEFAULT))

#define SWITCH_PORT_INTERNAL(_port) (_port == SWITCH_CPU_PORT_PCIE_DEFAULT)

#define SWITCH_DEV_PORT_INTERNAL(_dev_port) (_dev_port & 0x40)

#define SWITCH_PORT_SC_PKT_TYPE_HW_FLAG_SET(_port_info, _pkt_type) \
  do {                                                             \
    if (_pkt_type == SWITCH_PACKET_TYPE_UNICAST) {                 \
      SWITCH_HW_FLAG_SET(_port_info, SWITCH_PORT_SC_UCAST_ENTRY);  \
    } else if (_pkt_type == SWITCH_PACKET_TYPE_MULTICAST) {        \
      SWITCH_HW_FLAG_SET(_port_info, SWITCH_PORT_SC_MCAST_ENTRY);  \
    } else {                                                       \
      SWITCH_HW_FLAG_SET(_port_info, SWITCH_PORT_SC_BCAST_ENTRY);  \
    }                                                              \
  } while (0);

#define SWITCH_PORT_SC_PKT_TYPE_HW_FLAG_CLEAR(_port_info, _pkt_type) \
  do {                                                               \
    if (pkt_type == SWITCH_PACKET_TYPE_UNICAST) {                    \
      SWITCH_HW_FLAG_CLEAR(port_info, SWITCH_PORT_SC_UCAST_ENTRY);   \
    } else if (pkt_type == SWITCH_PACKET_TYPE_MULTICAST) {           \
      SWITCH_HW_FLAG_CLEAR(port_info, SWITCH_PORT_SC_MCAST_ENTRY);   \
    } else {                                                         \
      SWITCH_HW_FLAG_CLEAR(port_info, SWITCH_PORT_SC_BCAST_ENTRY);   \
    }                                                                \
  } while (0);

#define SWITCH_PORT_SC_PKT_TYPE_HW_FLAG_ISSET(_port_info, _pkt_type, _hw_set) \
  do {                                                                        \
    if (pkt_type == SWITCH_PACKET_TYPE_UNICAST) {                             \
      _hw_set = SWITCH_HW_FLAG_ISSET(port_info, SWITCH_PORT_SC_UCAST_ENTRY);  \
    } else if (pkt_type == SWITCH_PACKET_TYPE_MULTICAST) {                    \
      _hw_set = SWITCH_HW_FLAG_ISSET(port_info, SWITCH_PORT_SC_MCAST_ENTRY);  \
    } else {                                                                  \
      _hw_set = SWITCH_HW_FLAG_ISSET(port_info, SWITCH_PORT_SC_BCAST_ENTRY);  \
    }                                                                         \
  } while (0);

#define SWITCH_PORT_SC_STATS_HW_FLAG_SET(_port_info, _pkt_type, _color)       \
  do {                                                                        \
    if (_pkt_type == SWITCH_PACKET_TYPE_UNICAST) {                            \
      if (_color == SWITCH_COLOR_GREEN) {                                     \
        SWITCH_HW_FLAG_SET(_port_info,                                        \
                           SWITCH_PORT_SC_STATS_UCAST_GREEN_ENTRY);           \
      } else {                                                                \
        SWITCH_HW_FLAG_SET(_port_info, SWITCH_PORT_SC_STATS_UCAST_RED_ENTRY); \
      }                                                                       \
    } else if (_pkt_type == SWITCH_PACKET_TYPE_MULTICAST) {                   \
      if (_color == SWITCH_COLOR_GREEN) {                                     \
        SWITCH_HW_FLAG_SET(_port_info,                                        \
                           SWITCH_PORT_SC_STATS_MCAST_GREEN_ENTRY);           \
      } else {                                                                \
        SWITCH_HW_FLAG_SET(_port_info, SWITCH_PORT_SC_STATS_MCAST_RED_ENTRY); \
      }                                                                       \
    } else {                                                                  \
      if (_color == SWITCH_COLOR_GREEN) {                                     \
        SWITCH_HW_FLAG_SET(_port_info,                                        \
                           SWITCH_PORT_SC_STATS_BCAST_GREEN_ENTRY);           \
      } else {                                                                \
        SWITCH_HW_FLAG_SET(_port_info, SWITCH_PORT_SC_STATS_BCAST_RED_ENTRY); \
      }                                                                       \
    }                                                                         \
  } while (0);

#define SWITCH_PORT_SC_STATS_HW_FLAG_CLEAR(_port_info, _pkt_type, _color) \
  do {                                                                    \
    if (_pkt_type == SWITCH_PACKET_TYPE_UNICAST) {                        \
      if (_color == SWITCH_COLOR_GREEN) {                                 \
        SWITCH_HW_FLAG_CLEAR(_port_info,                                  \
                             SWITCH_PORT_SC_STATS_UCAST_GREEN_ENTRY);     \
      } else {                                                            \
        SWITCH_HW_FLAG_CLEAR(_port_info,                                  \
                             SWITCH_PORT_SC_STATS_UCAST_RED_ENTRY);       \
      }                                                                   \
    } else if (_pkt_type == SWITCH_PACKET_TYPE_MULTICAST) {               \
      if (_color == SWITCH_COLOR_GREEN) {                                 \
        SWITCH_HW_FLAG_CLEAR(_port_info,                                  \
                             SWITCH_PORT_SC_STATS_MCAST_GREEN_ENTRY);     \
      } else {                                                            \
        SWITCH_HW_FLAG_CLEAR(_port_info,                                  \
                             SWITCH_PORT_SC_STATS_MCAST_RED_ENTRY);       \
      }                                                                   \
    } else {                                                              \
      if (_color == SWITCH_COLOR_GREEN) {                                 \
        SWITCH_HW_FLAG_CLEAR(_port_info,                                  \
                             SWITCH_PORT_SC_STATS_BCAST_GREEN_ENTRY);     \
      } else {                                                            \
        SWITCH_HW_FLAG_CLEAR(_port_info,                                  \
                             SWITCH_PORT_SC_STATS_BCAST_RED_ENTRY);       \
      }                                                                   \
    }                                                                     \
  } while (0);

#define SWITCH_PORT_SC_STATS_HW_FLAG_ISSET(                                   \
    _port_info, _pkt_type, _color, _hw_set)                                   \
  do {                                                                        \
    if (_pkt_type == SWITCH_PACKET_TYPE_UNICAST) {                            \
      if (_color == SWITCH_COLOR_GREEN) {                                     \
        _hw_set = SWITCH_HW_FLAG_ISSET(                                       \
            _port_info, SWITCH_PORT_SC_STATS_UCAST_GREEN_ENTRY);              \
      } else {                                                                \
        _hw_set = SWITCH_HW_FLAG_ISSET(_port_info,                            \
                                       SWITCH_PORT_SC_STATS_UCAST_RED_ENTRY); \
      }                                                                       \
    } else if (_pkt_type == SWITCH_PACKET_TYPE_MULTICAST) {                   \
      if (_color == SWITCH_COLOR_GREEN) {                                     \
        _hw_set = SWITCH_HW_FLAG_ISSET(                                       \
            _port_info, SWITCH_PORT_SC_STATS_MCAST_GREEN_ENTRY);              \
      } else {                                                                \
        _hw_set = SWITCH_HW_FLAG_ISSET(_port_info,                            \
                                       SWITCH_PORT_SC_STATS_MCAST_RED_ENTRY); \
      }                                                                       \
    } else {                                                                  \
      if (_color == SWITCH_COLOR_GREEN) {                                     \
        _hw_set = SWITCH_HW_FLAG_ISSET(                                       \
            _port_info, SWITCH_PORT_SC_STATS_BCAST_GREEN_ENTRY);              \
      } else {                                                                \
        _hw_set = SWITCH_HW_FLAG_ISSET(_port_info,                            \
                                       SWITCH_PORT_SC_STATS_BCAST_RED_ENTRY); \
      }                                                                       \
    }                                                                         \
  } while (0);

typedef enum switch_port_pd_entry_s {
  SWITCH_PORT_INGRESS_PORT_MAPPING_ENTRY = (1 << 0),
  SWITCH_PORT_INGRESS_PORT_PROPERTIES_ENTRY = (1 << 1),
  SWITCH_PORT_EGRESS_PORT_MAPPING_ENTRY = (1 << 2),
  SWITCH_PORT_LAG_GROUP_ENTRY = (1 << 3),
  SWITCH_PORT_LAG_MEMBER_ENTRY = (1 << 4),
  SWITCH_PORT_SC_UCAST_ENTRY = (1 << 5),
  SWITCH_PORT_SC_MCAST_ENTRY = (1 << 6),
  SWITCH_PORT_SC_BCAST_ENTRY = (1 << 7),
  SWITCH_PORT_SC_STATS_UCAST_GREEN_ENTRY = (1 << 8),
  SWITCH_PORT_SC_STATS_UCAST_RED_ENTRY = (1 << 9),
  SWITCH_PORT_SC_STATS_MCAST_GREEN_ENTRY = (1 << 10),
  SWITCH_PORT_SC_STATS_MCAST_RED_ENTRY = (1 << 11),
  SWITCH_PORT_SC_STATS_BCAST_GREEN_ENTRY = (1 << 12),
  SWITCH_PORT_SC_STATS_BCAST_RED_ENTRY = (1 << 13),
  SWITCH_PORT_INGRESS_MIRROR_ENTRY = (1 << 14),
  SWITCH_PORT_EGRESS_MIRROR_ENTRY = (1 << 15),
  SWITCH_PORT_INGRESS_PORT_YID_ENTRY = (1 << 16),
  SWITCH_PORT_VLAN_XLATE_ENTRY = (1 << 17),
  SWITCH_PORT_QINQ_XLATE_ENTRY = (1 << 18),
  SWITCH_PORT_BD_XLATE_ENTRY = (1 << 19),
  SWITCH_PORT_NOP_XLATE_ENTRY = (1 << 20),
  SWITCH_PORT_DROP_STATS_ENTRY = (1 << 21),
  SWITCH_PORT_ENTRY_MAX
} switch_port_pd_entry_t;

#define SWITCH_ID_FROM_PORT_LAG_INDEX(port_lag_index) \
  (port_lag_index & ((1 << SWITCH_PORT_LAG_INDEX_WIDTH) - 1)

#define SWITCH_COMPUTE_PORT_LAG_INDEX(handle, port_lag_index_type) \
  (handle_to_id(handle) | (port_lag_index_type << SWITCH_PORT_LAG_INDEX_WIDTH))

#define SWITCH_PORT_LAG_INDEX_GET_TYPE(port_lag_index) \
  ((port_lag_index >> SWITCH_PORT_LAG_INDEX_WIDTH))

#ifdef __cplusplus
}
#endif

#endif /** __SWITCH_PORT_INT_H__ */
