// Copyright 2018-present Barefoot Networks, Inc.
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#ifndef STRATUM_HAL_LIB_BAREFOOT_BF_CHASSIS_MANAGER_H_
#define STRATUM_HAL_LIB_BAREFOOT_BF_CHASSIS_MANAGER_H_

#include <map>
#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/memory/memory.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "stratum/glue/integral_types.h"
#include "stratum/hal/lib/barefoot/bf_sde_interface.h"
#include "stratum/hal/lib/common/gnmi_events.h"
#include "stratum/hal/lib/common/utils.h"
#include "stratum/hal/lib/common/writer_interface.h"
#include "stratum/lib/channel/channel.h"

#define GNMI_CONFIG_PORT_TYPE 0x01
#define GNMI_CONFIG_DEVICE_TYPE 0x02
#define GNMI_CONFIG_QUEUE_COUNT 0x04
#define GNMI_CONFIG_SOCKET_PATH 0x08
#define GNMI_CONFIG_HOST_NAME 0x10

#define GNMI_CONFIG_TDI (GNMI_CONFIG_PORT_TYPE | GNMI_CONFIG_DEVICE_TYPE | \
                         GNMI_CONFIG_QUEUE_COUNT | GNMI_CONFIG_SOCKET_PATH | \
                         GNMI_CONFIG_HOST_NAME)

namespace stratum {
namespace hal {
//namespace barefoot {
//using namespace ::stratum::barefoot;
using namespace ::stratum::hal;
using namespace ::stratum::hal::barefoot;

// Lock which protects chassis state across the entire switch.
extern absl::Mutex chassis_lock;

class BfChassisManager {
 public:
  virtual ~BfChassisManager();

  virtual ::util::Status PushChassisConfig(const ChassisConfig& config)
      EXCLUSIVE_LOCKS_REQUIRED(chassis_lock);

  virtual ::util::Status VerifyChassisConfig(const ChassisConfig& config)
      SHARED_LOCKS_REQUIRED(chassis_lock);

  virtual ::util::Status Shutdown() LOCKS_EXCLUDED(chassis_lock);

  virtual ::util::Status RegisterEventNotifyWriter(
      const std::shared_ptr<WriterInterface<GnmiEventPtr>>& writer)
      LOCKS_EXCLUDED(gnmi_event_lock_);

  virtual ::util::Status UnregisterEventNotifyWriter()
      LOCKS_EXCLUDED(gnmi_event_lock_);

  virtual ::util::StatusOr<DataResponse> GetPortData(
      const DataRequest::Request& request) SHARED_LOCKS_REQUIRED(chassis_lock);

  virtual ::util::StatusOr<absl::Time> GetPortTimeLastChanged(uint64 node_id,
                                                              uint32 port_id)
      SHARED_LOCKS_REQUIRED(chassis_lock);

  virtual ::util::Status GetPortCounters(uint64 node_id, uint32 port_id,
                                         PortCounters* counters)
      SHARED_LOCKS_REQUIRED(chassis_lock);

  virtual ::util::Status ReplayPortsConfig(uint64 node_id)
      EXCLUSIVE_LOCKS_REQUIRED(chassis_lock);

//  virtual ::util::Status GetFrontPanelPortInfo(uint64 node_id, uint32 port_id,
//                                               FrontPanelPortInfo* fp_port_info)
//      SHARED_LOCKS_REQUIRED(chassis_lock);

  virtual ::util::StatusOr<std::map<uint64, int>> GetNodeIdToUnitMap() const
      SHARED_LOCKS_REQUIRED(chassis_lock);

  virtual ::util::StatusOr<int> GetUnitFromNodeId(uint64 node_id) const
      SHARED_LOCKS_REQUIRED(chassis_lock);

  // Factory function for creating the instance of the class.
  static std::unique_ptr<BfChassisManager> CreateInstance(
      OperationMode mode,
      BfSdeInterface* bf_sde_interface);

  bool ValidateOnetimeConfig(uint64 node_id, uint32 port_id,
                             SetRequest::Request::Port::ValueCase config);

  ::util::Status ValidateAndAdd(uint64 node_id, uint32 port_id,
                                const SingletonPort& singleton_port,
                                SetRequest::Request::Port::ValueCase change_field);

  // BfChassisManager is neither copyable nor movable.
  BfChassisManager(const BfChassisManager&) = delete;
  BfChassisManager& operator=(const BfChassisManager&) = delete;
  BfChassisManager(BfChassisManager&&) = delete;
  BfChassisManager& operator=(BfChassisManager&&) = delete;


 protected:
  // Default constructor. To be called by the Mock class instance only.
  BfChassisManager();

 private:
  // ReaderArgs encapsulates the arguments for a Channel reader thread.
  template <typename T>
  struct ReaderArgs {
    BfChassisManager* manager;
    std::unique_ptr<ChannelReader<T>> reader;
  };

  struct PortConfig {
    // ADMIN_STATE_UNKNOWN indicate that something went wrong during the port
    // configuration, and the port add wasn't event attempted or failed.
    AdminState admin_state;
    absl::optional<uint64> speed_bps;  // empty if port add failed
    absl::optional<int32> mtu;         // empty if MTU configuration failed
    absl::optional<TriState> autoneg;  // empty if Autoneg configuration failed
    absl::optional<FecMode> fec_mode;  // empty if port add failed
    // empty if loopback mode configuration failed
    absl::optional<LoopbackState> loopback_mode;
    // empty if no shaping config given

    SWBackendPortType port_type;
    SWBackendDeviceType device_type;
    int32 queues;
    std::string socket_path;
    std::string host_name;

    PortConfig() : admin_state(ADMIN_STATE_UNKNOWN),
                   port_type(PORT_TYPE_NONE),
                   device_type(DEVICE_TYPE_NONE),
                   queues(0) {}
  };

  // Maximum depth of port status change event channel.
  static constexpr int kMaxPortStatusEventDepth = 1024;
  static constexpr int kMaxXcvrEventDepth = 1024;

  // Private constructor. Use CreateInstance() to create an instance of this
  // class.
  BfChassisManager(OperationMode mode,
                   BfSdeInterface* bf_sde_interface);

  ::util::StatusOr<const PortConfig*> GetPortConfig(uint64 node_id,
                                                    uint32 port_id) const
      SHARED_LOCKS_REQUIRED(chassis_lock);

  // Returns the state of a port given its ID and the ID of its node.
  ::util::StatusOr<PortState> GetPortState(uint64 node_id, uint32 port_id) const
      SHARED_LOCKS_REQUIRED(chassis_lock);

  // Returns the SDK port number for the given port. Also called SDN or data
  // plane port.
  ::util::StatusOr<uint32> GetSdkPortId(uint64 node_id, uint32 port_id) const
      SHARED_LOCKS_REQUIRED(chassis_lock);

  // Cleans up the internal state. Resets all the internal port maps and
  // deletes the pointers.
  void CleanupInternalState() EXCLUSIVE_LOCKS_REQUIRED(chassis_lock);

  // helper to add / configure / enable a port with BfSdeInterface
  ::util::Status AddPortHelper(uint64 node_id, int unit, uint32 port_id,
                               const SingletonPort& singleton_port,
                               PortConfig* config);

  // helper to update port configuration with BfSdeInterface
  ::util::Status UpdatePortHelper(uint64 node_id, int unit, uint32 port_id,
                                  const SingletonPort& singleton_port,
                                  const PortConfig& config_old,
                                  PortConfig* config);

  // Determines the mode of operation:
  // - OPERATION_MODE_STANDALONE: when Stratum stack runs independently and
  // therefore needs to do all the SDK initialization itself.
  // - OPERATION_MODE_COUPLED: when Stratum stack runs as part of Sandcastle
  // stack, coupled with the rest of stack processes.
  // - OPERATION_MODE_SIM: when Stratum stack runs in simulation mode.
  // Note that this variable is set upon initialization and is never changed
  // afterwards.
  OperationMode mode_;

  bool initialized_ GUARDED_BY(chassis_lock);

  // WriterInterface<GnmiEventPtr> object for sending event notifications.
  mutable absl::Mutex gnmi_event_lock_;
  std::shared_ptr<WriterInterface<GnmiEventPtr>> gnmi_event_writer_
      GUARDED_BY(gnmi_event_lock_);

  // Map from unit number to the node ID as specified by the config.
  std::map<int, uint64> unit_to_node_id_ GUARDED_BY(chassis_lock);

  // Map from node ID to unit number.
  std::map<uint64, int> node_id_to_unit_ GUARDED_BY(chassis_lock);

  // Map from node ID to another map from port ID to PortState representing
  // the state of the singleton port uniquely identified by (node ID, port ID).
  std::map<uint64, std::map<uint32, PortState>>
      node_id_to_port_id_to_port_state_ GUARDED_BY(chassis_lock);

  // Map from node ID to another map from port ID to timestamp when the port
  // last changed state.
  std::map<uint64, std::map<uint32, absl::Time>>
      node_id_to_port_id_to_time_last_changed_ GUARDED_BY(chassis_lock);

  // Map from node ID to another map from port ID to port configuration.
  // We may change this once missing "get" methods get added to BfSdeInterface,
  // as we would be able to rely on BfSdeInterface to query config parameters,
  // instead of maintaining a "consistent" view in this map.
  std::map<uint64, std::map<uint32, PortConfig>>
      node_id_to_port_id_to_port_config_ GUARDED_BY(chassis_lock);

  // Map from node ID to another map from port ID to PortKey corresponding
  // to the singleton port uniquely identified by (node ID, port ID). This map
  // is updated as part of each config push.
  std::map<uint64, std::map<uint32, PortKey>>
      node_id_to_port_id_to_singleton_port_key_ GUARDED_BY(chassis_lock);

  // Map from node ID to another map from (SDN) port ID to SDK port ID.
  // SDN port IDs are used in Stratum and by callers to P4Runtime and gNMI,
  // and SDK port IDs are used in calls to the BF SDK. This map is updated
  // as part of each config push.
  std::map<uint64, std::map<uint32, uint32>> node_id_to_port_id_to_sdk_port_id_
      GUARDED_BY(chassis_lock);

  // Map from node ID to another map from SDK port ID to (SDN) port ID.
  // This contains the inverse mapping of: node_id_to_port_id_to_sdk_port_id_
  // This map is updated as part of each config push.
  std::map<uint64, std::map<uint32, uint32>> node_id_to_sdk_port_id_to_port_id_
      GUARDED_BY(chassis_lock);

  std::map<uint64, std::map<uint32, uint32>> node_id_port_id_to_backend_
      GUARDED_BY(chassis_lock);

  // Pointer to a BfSdeInterface implementation that wraps all the SDE calls.
  BfSdeInterface* bf_sde_interface_;  // not owned by this class.

  friend class BfChassisManagerTest;
};

//}  // namespace barefoot
}  // namespace hal
}  // namespace stratum

#endif  // STRATUM_HAL_LIB_BAREFOOT_BF_CHASSIS_MANAGER_H_
