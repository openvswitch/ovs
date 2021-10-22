// Copyright 2018-present Barefoot Networks, Inc.
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#include "bf_chassis_manager.h"

#include <map>
#include <memory>
#include <set>
#include <utility>

#include "absl/base/thread_annotations.h"
#include "absl/memory/memory.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "absl/types/optional.h"
#include "stratum/glue/integral_types.h"
#include "stratum/hal/lib/common/constants.h"
#include "stratum/hal/lib/common/gnmi_events.h"
#include "stratum/hal/lib/common/utils.h"
#include "stratum/hal/lib/common/writer_interface.h"
#include "stratum/lib/channel/channel.h"
#include "stratum/lib/constants.h"
#include "stratum/lib/macros.h"
#include "stratum/lib/utils.h"
#include "stratum/glue/logging.h"
//#include "stratum/glue/init_google.h"
//#include "glog/logging.h"

namespace stratum {
namespace hal {
//namespace barefoot {

using namespace ::stratum::hal::barefoot;

using PortStatusEvent = BfSdeInterface::PortStatusEvent;

ABSL_CONST_INIT absl::Mutex chassis_lock(absl::kConstInit);

/* static */
constexpr int BfChassisManager::kMaxPortStatusEventDepth;
/* static */
constexpr int BfChassisManager::kMaxXcvrEventDepth;

BfChassisManager::BfChassisManager(OperationMode mode,
                                   BfSdeInterface* bf_sde_interface)
    : mode_(mode),
      initialized_(false),
      gnmi_event_writer_(nullptr),
      unit_to_node_id_(),
      node_id_to_unit_(),
      node_id_to_port_id_to_port_state_(),
      node_id_to_port_id_to_time_last_changed_(),
      node_id_to_port_id_to_port_config_(),
      node_id_to_port_id_to_singleton_port_key_(),
      node_id_to_port_id_to_sdk_port_id_(),
      node_id_to_sdk_port_id_to_port_id_(),
      node_id_port_id_to_backend_(),
      bf_sde_interface_(ABSL_DIE_IF_NULL(bf_sde_interface)) {}

BfChassisManager::BfChassisManager()
    : mode_(OPERATION_MODE_STANDALONE),
      initialized_(false),
      gnmi_event_writer_(nullptr),
      unit_to_node_id_(),
      node_id_to_unit_(),
      node_id_to_port_id_to_port_state_(),
      node_id_to_port_id_to_time_last_changed_(),
      node_id_to_port_id_to_port_config_(),
      node_id_to_port_id_to_singleton_port_key_(),
      node_id_to_port_id_to_sdk_port_id_(),
      node_id_to_sdk_port_id_to_port_id_(),
      node_id_port_id_to_backend_(),
      bf_sde_interface_(nullptr) {}

BfChassisManager::~BfChassisManager() = default;

bool
BfChassisManager::ValidateOnetimeConfig(uint64 node_id, uint32 port_id,
                                        SetRequest::Request::Port::ValueCase config) {

  uint32 validate = node_id_port_id_to_backend_[node_id][port_id];
  switch (config) {
    case SetRequest::Request::Port::ValueCase::kPortType:
      if (validate & GNMI_CONFIG_PORT_TYPE) {
          return true;
      }
      break;

    case SetRequest::Request::Port::ValueCase::kDeviceType:
      if (validate & GNMI_CONFIG_DEVICE_TYPE) {
          return true;
      }
      break;

    case SetRequest::Request::Port::ValueCase::kQueueCount:
      if (validate & GNMI_CONFIG_QUEUE_COUNT) {
          return true;
      }
      break;

    case SetRequest::Request::Port::ValueCase::kSockPath:
      if (validate & GNMI_CONFIG_SOCKET_PATH) {
          return true;
      }
      break;

    case SetRequest::Request::Port::ValueCase::kHostConfig:
      if (validate & GNMI_CONFIG_HOST_NAME) {
          return true;
      }
      break;

    default:
      break;
  }

  return false;
}

::util::Status BfChassisManager::ValidateAndAdd(uint64 node_id, uint32 port_id,
                                                const SingletonPort& singleton_port,
                                                SetRequest::Request::Port::ValueCase change_field) {
  auto unit = node_id_to_unit_[node_id];
  uint32 sdk_port_id = node_id_to_port_id_to_sdk_port_id_[node_id][port_id];
  auto& config = node_id_to_port_id_to_port_config_[node_id][port_id];
  uint32 validate = node_id_port_id_to_backend_[node_id][port_id];
  const auto& config_params = singleton_port.config_params();

  switch (change_field) {
    case SetRequest::Request::Port::ValueCase::kPortType:
      validate |= GNMI_CONFIG_PORT_TYPE;
      config.port_type = config_params.type();
      LOG(INFO) << "ValidateAndAdd::kPortType = " << config_params.type();
      break;

    case SetRequest::Request::Port::ValueCase::kDeviceType:
      validate |= GNMI_CONFIG_DEVICE_TYPE;
      config.device_type = config_params.device_type();
      LOG(INFO) << "ValidateAndAdd::kDeviceType = " << config_params.device_type();
      break;

    case SetRequest::Request::Port::ValueCase::kQueueCount:
      validate |= GNMI_CONFIG_QUEUE_COUNT;
      config.queues = config_params.queues();
      LOG(INFO) << "ValidateAndAdd::kQueueCount = " << config_params.queues();
      break;

    case SetRequest::Request::Port::ValueCase::kSockPath:
      validate |= GNMI_CONFIG_SOCKET_PATH;
      config.socket_path = config_params.socket();
      LOG(INFO) << "ValidateAndAdd::kSockPath = " << config_params.socket();
      break;

    case SetRequest::Request::Port::ValueCase::kHostConfig:
      validate |= GNMI_CONFIG_HOST_NAME;
      config.host_name = config_params.host_name();
      LOG(INFO) << "ValidateAndAdd::kHostConfig = " << config_params.host_name();
      break;

    default:
      break;
  }

  node_id_port_id_to_backend_[node_id][port_id] = validate;
  if (validate == GNMI_CONFIG_TDI) {
      // Required parameters are configured
      LOG(INFO) << "Required parameters are configured, configure port via TDI";
      LOG(INFO) << "SDK_PORT ID while validating = " << sdk_port_id;
      RETURN_IF_ERROR(AddPortHelper(node_id, unit, sdk_port_id, singleton_port, &config));
  }
  google::FlushLogFiles(google::INFO);
  return ::util::OkStatus();
}

::util::Status BfChassisManager::AddPortHelper(
    uint64 node_id, int unit, uint32 sdk_port_id,
    const SingletonPort& singleton_port /* desired config */,
    /* out */ PortConfig* config /* new config */) {
  config->admin_state = ADMIN_STATE_UNKNOWN;
  // SingletonPort ID is the SDN/Stratum port ID
  uint32 port_id = singleton_port.id();
  std::string port_name = singleton_port.name();

  const auto& config_params = singleton_port.config_params();

  if (config_params.admin_state() == ADMIN_STATE_UNKNOWN) {
    RETURN_ERROR(ERR_INVALID_PARAM)
        << "Invalid admin state for port " << port_id << " in node " << node_id
        << " (SDK Port " << sdk_port_id << ").";
  }
  if (config_params.admin_state() == ADMIN_STATE_DIAG) {
    RETURN_ERROR(ERR_UNIMPLEMENTED)
        << "Unsupported 'diags' admin state for port " << port_id << " in node "
        << node_id << " (SDK Port " << sdk_port_id << ").";
  }

  config->speed_bps = singleton_port.speed_bps();
  config->admin_state = ADMIN_STATE_DISABLED;
  config->fec_mode = config_params.fec_mode();
  LOG(INFO) << "Adding port " << port_id << " in node " << node_id
            << " (SDK Port " << sdk_port_id << ").";
  BfSdeInterface::PortConfigParams bf_sde_wrapper_config = {config->port_type,
                                                            config->device_type,
                                                            config->queues,
                                                            config->socket_path,
                                                            config->host_name,
                                                            port_name};

  RETURN_IF_ERROR(bf_sde_interface_->AddPort(
#ifdef P4TOFINO
      unit, sdk_port_id, singleton_port.speed_bps(),
#else
      unit, sdk_port_id, singleton_port.speed_bps(), bf_sde_wrapper_config,
#endif
      config_params.fec_mode()));

  if (config_params.mtu() != 0) {
    RETURN_IF_ERROR(
        bf_sde_interface_->SetPortMtu(unit, sdk_port_id, config_params.mtu()));
  }
  config->mtu = config_params.mtu();
  if (config_params.autoneg() != TRI_STATE_UNKNOWN) {
    RETURN_IF_ERROR(bf_sde_interface_->SetPortAutonegPolicy(
        unit, sdk_port_id, config_params.autoneg()));
  }
  config->autoneg = config_params.autoneg();

  if (config_params.loopback_mode() != LOOPBACK_STATE_UNKNOWN) {
    LOG(INFO) << "Setting port " << port_id << " to loopback mode "
              << config_params.loopback_mode() << " (SDK Port " << sdk_port_id
              << ").";
    RETURN_IF_ERROR(bf_sde_interface_->SetPortLoopbackMode(
        unit, sdk_port_id, config_params.loopback_mode()));
  }
  config->loopback_mode = config_params.loopback_mode();

  if (config_params.admin_state() == ADMIN_STATE_ENABLED) {
    LOG(INFO) << "Enabling port " << port_id << " in node " << node_id
              << " (SDK Port " << sdk_port_id << ").";
    RETURN_IF_ERROR(bf_sde_interface_->EnablePort(unit, sdk_port_id));
    config->admin_state = ADMIN_STATE_ENABLED;
  }

  return ::util::OkStatus();
}

::util::Status BfChassisManager::UpdatePortHelper(
    uint64 node_id, int unit, uint32 sdk_port_id,
    const SingletonPort& singleton_port /* desired config */,
    const PortConfig& config_old /* current config */,
    /* out */ PortConfig* config /* new config */) {
  *config = config_old;
  // SingletonPort ID is the SDN/Stratum port ID
  uint32 port_id = singleton_port.id();

  if (!bf_sde_interface_->IsValidPort(unit, sdk_port_id)) {
    config->admin_state = ADMIN_STATE_UNKNOWN;
    config->speed_bps.reset();
    config->fec_mode.reset();
    RETURN_ERROR(ERR_INTERNAL)
        << "Port " << port_id << " in node " << node_id << " is not valid"
        << " (SDK Port " << sdk_port_id << ").";
  }

  const auto& config_params = singleton_port.config_params();
  if (singleton_port.speed_bps() != config_old.speed_bps) {
    RETURN_IF_ERROR(bf_sde_interface_->DisablePort(unit, sdk_port_id));
    RETURN_IF_ERROR(bf_sde_interface_->DeletePort(unit, sdk_port_id));

    ::util::Status status =
        AddPortHelper(node_id, unit, sdk_port_id, singleton_port, config);
    if (status.ok()) {
      return ::util::OkStatus();
    } else {
      // Revert to the old port configuration
      //   -- make a singleton_port from config_old
      //   -- call AddPortHelper with "old" singleton_port
      SingletonPort port_old =
          BuildSingletonPort(singleton_port.slot(), singleton_port.port(),
                             singleton_port.channel(), *config_old.speed_bps);
      port_old.mutable_config_params()->set_admin_state(config_old.admin_state);
      if (config_old.autoneg)
        port_old.mutable_config_params()->set_autoneg(*config_old.autoneg);
      if (config_old.mtu)
        port_old.mutable_config_params()->set_mtu(*config_old.mtu);
      if (config_old.fec_mode)
        port_old.mutable_config_params()->set_fec_mode(*config_old.fec_mode);
      AddPortHelper(node_id, unit, sdk_port_id, port_old, config);
      RETURN_ERROR(ERR_INVALID_PARAM)
          << "Could not add port " << port_id << " with new speed "
          << singleton_port.speed_bps() << " to BF SDE"
          << " (SDK Port " << sdk_port_id << ").";
    }
  }
  // same for FEC mode
  if (config_params.fec_mode() != config_old.fec_mode) {
    RETURN_ERROR(ERR_UNIMPLEMENTED)
        << "The FEC mode for port " << port_id << " in node " << node_id
        << " has changed; you need to delete the port and add it again"
        << " (SDK Port " << sdk_port_id << ").";
  }

  if (config_params.admin_state() == ADMIN_STATE_UNKNOWN) {
    RETURN_ERROR(ERR_INVALID_PARAM)
        << "Invalid admin state for port " << port_id << " in node " << node_id
        << " (SDK Port " << sdk_port_id << ").";
  }
  if (config_params.admin_state() == ADMIN_STATE_DIAG) {
    RETURN_ERROR(ERR_UNIMPLEMENTED)
        << "Unsupported 'diags' admin state for port " << port_id << " in node "
        << node_id << " (SDK Port " << sdk_port_id << ").";
  }

  bool config_changed = false;

  if (config_params.mtu() != config_old.mtu) {
    VLOG(1) << "Mtu for port " << port_id << " in node " << node_id
            << " changed"
            << " (SDK Port " << sdk_port_id << ").";
    config->mtu.reset();
    RETURN_IF_ERROR(
        bf_sde_interface_->SetPortMtu(unit, sdk_port_id, config_params.mtu()));
    config->mtu = config_params.mtu();
    config_changed = true;
  }
  if (config_params.autoneg() != config_old.autoneg) {
    VLOG(1) << "Autoneg policy for port " << port_id << " in node " << node_id
            << " changed"
            << " (SDK Port " << sdk_port_id << ").";
    config->autoneg.reset();
    RETURN_IF_ERROR(bf_sde_interface_->SetPortAutonegPolicy(
        unit, sdk_port_id, config_params.autoneg()));
    config->autoneg = config_params.autoneg();
    config_changed = true;
  }
  if (config_params.loopback_mode() != config_old.loopback_mode) {
    config->loopback_mode.reset();
    RETURN_IF_ERROR(bf_sde_interface_->SetPortLoopbackMode(
        unit, sdk_port_id, config_params.loopback_mode()));
    config->loopback_mode = config_params.loopback_mode();
    config_changed = true;
  }

  bool need_disable = false, need_enable = false;
  if (config_params.admin_state() == ADMIN_STATE_DISABLED) {
    // if the new admin state is disabled, we need to disable the port if it was
    // previously enabled.
    need_disable = (config_old.admin_state != ADMIN_STATE_DISABLED);
  } else if (config_params.admin_state() == ADMIN_STATE_ENABLED) {
    // if the new admin state is enabled, we need to:
    //  * disable the port if there is a config chaned and the port was
    //    previously enabled
    //  * enable the port if it needs to be disabled first because of a config
    //    change if it is currently disabled
    need_disable =
        config_changed && (config_old.admin_state != ADMIN_STATE_DISABLED);
    need_enable =
        need_disable || (config_old.admin_state == ADMIN_STATE_DISABLED);
  }

  if (need_disable) {
    LOG(INFO) << "Disabling port " << port_id << " in node " << node_id
              << " (SDK Port " << sdk_port_id << ").";
    RETURN_IF_ERROR(bf_sde_interface_->DisablePort(unit, sdk_port_id));
    config->admin_state = ADMIN_STATE_DISABLED;
  }
  if (need_enable) {
    LOG(INFO) << "Enabling port " << port_id << " in node " << node_id
              << " (SDK Port " << sdk_port_id << ").";
    RETURN_IF_ERROR(bf_sde_interface_->EnablePort(unit, sdk_port_id));
    config->admin_state = ADMIN_STATE_ENABLED;
  }

  return ::util::OkStatus();
}

::util::Status BfChassisManager::PushChassisConfig(
    const ChassisConfig& config) {

  // new maps
  std::map<int, uint64> unit_to_node_id;
  std::map<uint64, int> node_id_to_unit;
  std::map<uint64, std::map<uint32, PortState>>
      node_id_to_port_id_to_port_state;
  std::map<uint64, std::map<uint32, absl::Time>>
      node_id_to_port_id_to_time_last_changed;
  std::map<uint64, std::map<uint32, PortConfig>>
      node_id_to_port_id_to_port_config;
  std::map<uint64, std::map<uint32, PortKey>>
      node_id_to_port_id_to_singleton_port_key;
  std::map<uint64, std::map<uint32, uint32>> node_id_to_port_id_to_sdk_port_id;
  std::map<uint64, std::map<uint32, uint32>> node_id_to_sdk_port_id_to_port_id;
  std::map<uint64, std::map<uint32, uint32>> node_id_port_id_to_backend;

  {
    int unit = 0;
    for (const auto& node : config.nodes()) {
      unit_to_node_id[unit] = node.id();
      node_id_to_unit[node.id()] = unit;
      unit++;
    }
  }

  for (const auto& singleton_port : config.singleton_ports()) {
    uint32 port_id = singleton_port.id();
    uint64 node_id = singleton_port.node();

    auto* unit = gtl::FindOrNull(node_id_to_unit, node_id);
    if (unit == nullptr) {
      RETURN_ERROR(ERR_INVALID_PARAM)
          << "Invalid ChassisConfig, unknown node id " << node_id
          << " for port " << port_id << ".";
    }
    node_id_port_id_to_backend[node_id][port_id] = 0;
    node_id_to_port_id_to_port_state[node_id][port_id] = PORT_STATE_UNKNOWN;
    node_id_to_port_id_to_time_last_changed[node_id][port_id] =
        absl::UnixEpoch();
    node_id_to_port_id_to_port_config[node_id][port_id] = PortConfig();
    PortKey singleton_port_key(singleton_port.slot(), singleton_port.port(),
                               singleton_port.channel());
    node_id_to_port_id_to_singleton_port_key[node_id][port_id] =
        singleton_port_key;

    // Translate the logical SDN port to SDK port (BF device port ID)
    ASSIGN_OR_RETURN(uint32 sdk_port, bf_sde_interface_->GetPortIdFromPortKey(
                                          *unit, singleton_port_key));
    node_id_to_port_id_to_sdk_port_id[node_id][port_id] = sdk_port;
    LOG(INFO) << "SDK_PORT = " << sdk_port << "for port_id = " << port_id;
    node_id_to_sdk_port_id_to_port_id[node_id][sdk_port] = port_id;

    PortKey port_group_key(singleton_port.slot(), singleton_port.port());
  }

  for (const auto& singleton_port : config.singleton_ports()) {
    uint32 port_id = singleton_port.id();
    uint64 node_id = singleton_port.node();
    // we checked that node_id was valid in the previous loop
    auto unit = node_id_to_unit[node_id];

    // TODO(antonin): we currently ignore slot
    // Stratum requires slot and port to be set. We use port and channel to
    // get Tofino device port (called SDK port ID).

    const PortConfig* config_old = nullptr;
    const auto* port_id_to_port_config_old =
        gtl::FindOrNull(node_id_to_port_id_to_port_config_, node_id);
    if (port_id_to_port_config_old != nullptr) {
      config_old = gtl::FindOrNull(*port_id_to_port_config_old, port_id);
    }

    auto& config = node_id_to_port_id_to_port_config[node_id][port_id];
    uint32 sdk_port_id = node_id_to_port_id_to_sdk_port_id[node_id][port_id];
    if (config_old == nullptr) {  // new port
      // if anything fails, config.admin_state will be set to
      // ADMIN_STATE_UNKNOWN (invalid)
      //RETURN_IF_ERROR(
      //    AddPortHelper(node_id, unit, sdk_port_id, singleton_port, &config));
      continue;
    } else {  // port already exists, config may have changed
      if (config_old->admin_state == ADMIN_STATE_UNKNOWN) {
        // something is wrong with the port, we make sure the port is deleted
        // first (and ignore the error status if there is one), then add the
        // port again.
        if (bf_sde_interface_->IsValidPort(unit, sdk_port_id)) {
          bf_sde_interface_->DeletePort(unit, sdk_port_id);
        }
        RETURN_IF_ERROR(
            AddPortHelper(node_id, unit, sdk_port_id, singleton_port, &config));
        continue;
      }

      // diff configs and apply necessary changes

      // sanity-check: if admin_state is not ADMIN_STATE_UNKNOWN, then the port
      // was added and the speed_bps was set.
      if (!config_old->speed_bps) {
        RETURN_ERROR(ERR_INTERNAL)
            << "Invalid internal state in BfChassisManager, "
            << "speed_bps field should contain a value";
      }

      // if anything fails, config.admin_state will be set to
      // ADMIN_STATE_UNKNOWN (invalid)
      RETURN_IF_ERROR(UpdatePortHelper(node_id, unit, sdk_port_id,
                                       singleton_port, *config_old, &config));
    }
  }

  // Clean up from old config.
  for (const auto& node_ports_old : node_id_to_port_id_to_port_config_) {
    auto node_id = node_ports_old.first;
    for (const auto& port_old : node_ports_old.second) {
      auto port_id = port_old.first;
      if (node_id_to_port_id_to_port_config.count(node_id) > 0 &&
          node_id_to_port_id_to_port_config[node_id].count(port_id) > 0) {
        continue;
      }
      auto unit = node_id_to_unit_[node_id];
      uint32 sdk_port_id = node_id_to_port_id_to_sdk_port_id_[node_id][port_id];
      // remove ports which are no longer present in the ChassisConfig
      // TODO(bocon): Collect these errors and keep trying to remove old ports
      LOG(INFO) << "Deleting port " << port_id << " in node " << node_id
                << " (SDK port " << sdk_port_id << ").";
      RETURN_IF_ERROR(bf_sde_interface_->DeletePort(unit, sdk_port_id));
    }
  }

  unit_to_node_id_ = unit_to_node_id;
  node_id_to_unit_ = node_id_to_unit;
  node_id_to_port_id_to_port_state_ = node_id_to_port_id_to_port_state;
  node_id_to_port_id_to_time_last_changed_ =
      node_id_to_port_id_to_time_last_changed;
  node_id_to_port_id_to_port_config_ = node_id_to_port_id_to_port_config;
  node_id_to_port_id_to_singleton_port_key_ =
      node_id_to_port_id_to_singleton_port_key;
  node_id_to_port_id_to_sdk_port_id_ = node_id_to_port_id_to_sdk_port_id;
  node_id_to_sdk_port_id_to_port_id_ = node_id_to_sdk_port_id_to_port_id;
  node_id_port_id_to_backend_ = node_id_port_id_to_backend;
  initialized_ = true;

  return ::util::OkStatus();
}

::util::Status BfChassisManager::VerifyChassisConfig(
    const ChassisConfig& config) {
  CHECK_RETURN_IF_FALSE(config.trunk_ports_size() == 0)
      << "Trunk ports are not supported on Tofino.";
  CHECK_RETURN_IF_FALSE(config.port_groups_size() == 0)
      << "Port groups are not supported on Tofino.";
  CHECK_RETURN_IF_FALSE(config.nodes_size() > 0)
      << "The config must contain at least one node.";

  // Find the supported Tofino chip types based on the given platform.
  CHECK_RETURN_IF_FALSE(config.has_chassis() && config.chassis().platform())
      << "Config needs a Chassis message with correct platform.";
  switch (config.chassis().platform()) {
    case PLT_GENERIC_BAREFOOT_TOFINO:
    case PLT_GENERIC_BAREFOOT_TOFINO2:
    case PLT_P4_SOFT_SWITCH:
      break;
    default:
      return MAKE_ERROR(ERR_INVALID_PARAM)
             << "Unsupported platform: "
             << Platform_Name(config.chassis().platform());
  }

  // Validate Node messages. Make sure there is no two nodes with the same id.
  std::map<uint64, int> node_id_to_unit;
  std::map<int, uint64> unit_to_node_id;
  for (const auto& node : config.nodes()) {
    CHECK_RETURN_IF_FALSE(node.slot() > 0)
        << "No positive slot in " << node.ShortDebugString();
    CHECK_RETURN_IF_FALSE(node.id() > 0)
        << "No positive ID in " << node.ShortDebugString();
    CHECK_RETURN_IF_FALSE(
        gtl::InsertIfNotPresent(&node_id_to_unit, node.id(), -1))
        << "The id for Node " << PrintNode(node) << " was already recorded "
        << "for another Node in the config.";
  }
  {
    int unit = 0;
    for (const auto& node : config.nodes()) {
      unit_to_node_id[unit] = node.id();
      node_id_to_unit[node.id()] = unit;
      ++unit;
    }
  }

  // Go over all the singleton ports in the config:
  // 1- Validate the basic singleton port properties.
  // 2- Make sure there is no two ports with the same (slot, port, channel).
  // 3- Make sure for each (slot, port) pair, the channels of all the ports
  //    are valid. This depends on the port speed.
  // 4- Make sure no singleton port has the reserved CPU port ID. CPU port is
  //    a special port and is not in the list of singleton ports. It is
  //    configured separately.
  // 5- Make sure IDs of the singleton ports are unique per node.
  std::map<uint64, std::set<uint32>> node_id_to_port_ids;
  std::set<PortKey> singleton_port_keys;
  for (const auto& singleton_port : config.singleton_ports()) {
    // TODO(max): enable once we decoupled port ids from sdk ports.
    // CHECK_RETURN_IF_FALSE(singleton_port.id() > 0)
    //     << "No positive ID in " << PrintSingletonPort(singleton_port) << ".";
    CHECK_RETURN_IF_FALSE(singleton_port.id() != kCpuPortId)
        << "SingletonPort " << PrintSingletonPort(singleton_port)
        << " has the reserved CPU port ID (" << kCpuPortId << ").";
    CHECK_RETURN_IF_FALSE(singleton_port.slot() > 0)
        << "No valid slot in " << singleton_port.ShortDebugString() << ".";
    CHECK_RETURN_IF_FALSE(singleton_port.port() > 0)
        << "No valid port in " << singleton_port.ShortDebugString() << ".";
    CHECK_RETURN_IF_FALSE(singleton_port.speed_bps() > 0)
        << "No valid speed_bps in " << singleton_port.ShortDebugString() << ".";
    PortKey singleton_port_key(singleton_port.slot(), singleton_port.port(),
                               singleton_port.channel());
    CHECK_RETURN_IF_FALSE(!singleton_port_keys.count(singleton_port_key))
        << "The (slot, port, channel) tuple for SingletonPort "
        << PrintSingletonPort(singleton_port)
        << " was already recorded for another SingletonPort in the config.";
    singleton_port_keys.insert(singleton_port_key);
    CHECK_RETURN_IF_FALSE(singleton_port.node() > 0)
        << "No valid node ID in " << singleton_port.ShortDebugString() << ".";
    CHECK_RETURN_IF_FALSE(node_id_to_unit.count(singleton_port.node()))
        << "Node ID " << singleton_port.node() << " given for SingletonPort "
        << PrintSingletonPort(singleton_port)
        << " has not been given to any Node in the config.";
    CHECK_RETURN_IF_FALSE(
        !node_id_to_port_ids[singleton_port.node()].count(singleton_port.id()))
        << "The id for SingletonPort " << PrintSingletonPort(singleton_port)
        << " was already recorded for another SingletonPort for node with ID "
        << singleton_port.node() << ".";
    node_id_to_port_ids[singleton_port.node()].insert(singleton_port.id());
  }

  std::map<uint64, std::map<uint32, PortKey>>
      node_id_to_port_id_to_singleton_port_key;

  for (const auto& singleton_port : config.singleton_ports()) {
    uint32 port_id = singleton_port.id();
    uint64 node_id = singleton_port.node();

    PortKey singleton_port_key(singleton_port.slot(), singleton_port.port(),
                               singleton_port.channel());
    node_id_to_port_id_to_singleton_port_key[node_id][port_id] =
        singleton_port_key;

    // Make sure that the port exists by getting the SDK port ID.
    const int* unit = gtl::FindOrNull(node_id_to_unit, node_id);
    CHECK_RETURN_IF_FALSE(unit != nullptr)
        << "Node " << node_id << " not found for port " << port_id << ".";
    RETURN_IF_ERROR(
        bf_sde_interface_->GetPortIdFromPortKey(*unit, singleton_port_key)
            .status());
  }

  // If the class is initialized, we also need to check if the new config will
  // require a change in the port layout. If so, report reboot required.
  if (initialized_) {
    if (node_id_to_port_id_to_singleton_port_key !=
        node_id_to_port_id_to_singleton_port_key_) {
      RETURN_ERROR(ERR_REBOOT_REQUIRED)
          << "The switch is already initialized, but we detected the newly "
          << "pushed config requires a change in the port layout. The stack "
          << "needs to be rebooted to finish config push.";
    }

    if (node_id_to_unit != node_id_to_unit_) {
      RETURN_ERROR(ERR_REBOOT_REQUIRED)
          << "The switch is already initialized, but we detected the newly "
          << "pushed config requires a change in node_id_to_unit. The stack "
          << "needs to be rebooted to finish config push.";
    }
  }

  return ::util::OkStatus();
}

::util::Status BfChassisManager::RegisterEventNotifyWriter(
    const std::shared_ptr<WriterInterface<GnmiEventPtr>>& writer) {
  absl::WriterMutexLock l(&gnmi_event_lock_);
  gnmi_event_writer_ = writer;
  return ::util::OkStatus();
}

::util::Status BfChassisManager::UnregisterEventNotifyWriter() {
  absl::WriterMutexLock l(&gnmi_event_lock_);
  gnmi_event_writer_ = nullptr;
  return ::util::OkStatus();
}

::util::StatusOr<const BfChassisManager::PortConfig*>
BfChassisManager::GetPortConfig(uint64 node_id, uint32 port_id) const {
  auto* port_id_to_config =
      gtl::FindOrNull(node_id_to_port_id_to_port_config_, node_id);
  CHECK_RETURN_IF_FALSE(port_id_to_config != nullptr)
      << "Node " << node_id << " is not configured or not known.";
  const PortConfig* config = gtl::FindOrNull(*port_id_to_config, port_id);
  CHECK_RETURN_IF_FALSE(config != nullptr)
      << "Port " << port_id << " is not configured or not known for node "
      << node_id << ".";
  return config;
}

::util::StatusOr<uint32> BfChassisManager::GetSdkPortId(uint64 node_id,
                                                        uint32 port_id) const {
  if (!initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }

  const auto* port_map =
      gtl::FindOrNull(node_id_to_port_id_to_sdk_port_id_, node_id);
  CHECK_RETURN_IF_FALSE(port_map != nullptr)
      << "Node " << node_id << " is not configured or not known.";

  const uint32* sdk_port_id = gtl::FindOrNull(*port_map, port_id);
  CHECK_RETURN_IF_FALSE(sdk_port_id != nullptr)
      << "Port " << port_id << " for node " << node_id
      << " is not configured or not known.";

  return *sdk_port_id;
}

::util::StatusOr<DataResponse> BfChassisManager::GetPortData(
    const DataRequest::Request& request) {
  if (!initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }
  DataResponse resp;
  using Request = DataRequest::Request;
  switch (request.request_case()) {
    case Request::kOperStatus: {
      ASSIGN_OR_RETURN(auto port_state,
                       GetPortState(request.oper_status().node_id(),
                                    request.oper_status().port_id()));
      resp.mutable_oper_status()->set_state(port_state);
      ASSIGN_OR_RETURN(absl::Time last_changed,
                       GetPortTimeLastChanged(request.oper_status().node_id(),
                                              request.oper_status().port_id()));
      resp.mutable_oper_status()->set_time_last_changed(
          absl::ToUnixNanos(last_changed));
      break;
    }
    case Request::kAdminStatus: {
      ASSIGN_OR_RETURN(auto* config,
                       GetPortConfig(request.admin_status().node_id(),
                                     request.admin_status().port_id()));
      resp.mutable_admin_status()->set_state(config->admin_state);
      break;
    }
    case Request::kMacAddress: {
      // TODO(unknown) Find out why the controller needs it.
      // Find MAC address of port located at:
      // - node_id: req.mac_address().node_id()
      // - port_id: req.mac_address().port_id()
      // and then write it into the response.
      resp.mutable_mac_address()->set_mac_address(kDummyMacAddress);
      break;
    }
    case Request::kPortSpeed: {
      ASSIGN_OR_RETURN(auto* config,
                       GetPortConfig(request.port_speed().node_id(),
                                     request.port_speed().port_id()));
      if (config->speed_bps)
        resp.mutable_port_speed()->set_speed_bps(*config->speed_bps);
      break;
    }
    case Request::kNegotiatedPortSpeed: {
      ASSIGN_OR_RETURN(
          auto* config,
          GetPortConfig(request.negotiated_port_speed().node_id(),
                        request.negotiated_port_speed().port_id()));
      if (!config->speed_bps) break;
      ASSIGN_OR_RETURN(auto port_state,
                       GetPortState(request.negotiated_port_speed().node_id(),
                                    request.negotiated_port_speed().port_id()));
      if (port_state != PORT_STATE_UP) break;
      resp.mutable_negotiated_port_speed()->set_speed_bps(*config->speed_bps);
      break;
    }
    case DataRequest::Request::kLacpRouterMac: {
      // Find LACP System ID MAC address of port located at:
      // - node_id: req.lacp_router_mac().node_id()
      // - port_id: req.lacp_router_mac().port_id()
      // and then write it into the response.
      resp.mutable_lacp_router_mac()->set_mac_address(kDummyMacAddress);
      break;
    }
    case Request::kPortCounters: {
      RETURN_IF_ERROR(GetPortCounters(request.port_counters().node_id(),
                                      request.port_counters().port_id(),
                                      resp.mutable_port_counters()));
      break;
    }
    case Request::kAutonegStatus: {
      ASSIGN_OR_RETURN(auto* config,
                       GetPortConfig(request.autoneg_status().node_id(),
                                     request.autoneg_status().port_id()));
      if (config->autoneg)
        resp.mutable_autoneg_status()->set_state(*config->autoneg);
      break;
    }
    case Request::kFrontPanelPortInfo: {
      break;
    }
    case Request::kFecStatus: {
      ASSIGN_OR_RETURN(auto* config,
                       GetPortConfig(request.fec_status().node_id(),
                                     request.fec_status().port_id()));
      if (config->fec_mode)
        resp.mutable_fec_status()->set_mode(*config->fec_mode);
      break;
    }
    case Request::kLoopbackStatus: {
      ASSIGN_OR_RETURN(auto* config,
                       GetPortConfig(request.loopback_status().node_id(),
                                     request.loopback_status().port_id()));
      if (config->loopback_mode)
        resp.mutable_loopback_status()->set_state(*config->loopback_mode);
      break;
    }
    case Request::kSdnPortId: {
      ASSIGN_OR_RETURN(auto sdk_port_id,
                       GetSdkPortId(request.sdn_port_id().node_id(),
                                    request.sdn_port_id().port_id()));
      resp.mutable_sdn_port_id()->set_port_id(sdk_port_id);
      break;
    }
    case Request::kForwardingViability: {
      // Find current port forwarding viable state for port located at:
      // - node_id: req.forwarding_viable().node_id()
      // - port_id: req.forwarding_viable().port_id()
      // and then write it into the response.
      resp.mutable_forwarding_viability()->set_state(
          TRUNK_MEMBER_BLOCK_STATE_UNKNOWN);
      break;
    }
    case DataRequest::Request::kHealthIndicator: {
      // Find current port health indicator (LED) for port located at:
      // - node_id: req.health_indicator().node_id()
      // - port_id: req.health_indicator().port_id()
      // and then write it into the response.
      resp.mutable_health_indicator()->set_state(HEALTH_STATE_UNKNOWN);
      break;
    }
    default:
      RETURN_ERROR(ERR_INTERNAL) << "Not supported yet";
  }
  return resp;
}

::util::StatusOr<PortState> BfChassisManager::GetPortState(
    uint64 node_id, uint32 port_id) const {
  if (!initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }
  ASSIGN_OR_RETURN(auto unit, GetUnitFromNodeId(node_id));

  auto* port_id_to_port_state =
      gtl::FindOrNull(node_id_to_port_id_to_port_state_, node_id);
  CHECK_RETURN_IF_FALSE(port_id_to_port_state != nullptr)
      << "Node " << node_id << " is not configured or not known.";
  const PortState* port_state_ptr =
      gtl::FindOrNull(*port_id_to_port_state, port_id);
  // TODO(antonin): Once we implement PushChassisConfig, port_state_ptr should
  // never be NULL
  if (port_state_ptr != nullptr && *port_state_ptr != PORT_STATE_UNKNOWN) {
    return *port_state_ptr;
  }

  // If state is unknown, query the state
  LOG(INFO) << "Querying state of port " << port_id << " in node " << node_id
            << ".";
  ASSIGN_OR_RETURN(auto sdk_port_id, GetSdkPortId(node_id, port_id));
  ASSIGN_OR_RETURN(auto port_state,
                   bf_sde_interface_->GetPortState(unit, sdk_port_id));
  LOG(INFO) << "State of port " << port_id << " in node " << node_id
            << " (SDK port " << sdk_port_id
            << "): " << PrintPortState(port_state);
  return port_state;
}

::util::StatusOr<absl::Time> BfChassisManager::GetPortTimeLastChanged(
    uint64 node_id, uint32 port_id) {
  if (!initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }

  CHECK_RETURN_IF_FALSE(
      node_id_to_port_id_to_time_last_changed_.count(node_id));
  CHECK_RETURN_IF_FALSE(
      node_id_to_port_id_to_time_last_changed_[node_id].count(port_id));
  return node_id_to_port_id_to_time_last_changed_[node_id][port_id];
}

::util::Status BfChassisManager::GetPortCounters(uint64 node_id, uint32 port_id,
                                                 PortCounters* counters) {
  if (!initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }
  ASSIGN_OR_RETURN(auto unit, GetUnitFromNodeId(node_id));
  ASSIGN_OR_RETURN(auto sdk_port_id, GetSdkPortId(node_id, port_id));
  return bf_sde_interface_->GetPortCounters(unit, sdk_port_id, counters);
}

::util::StatusOr<std::map<uint64, int>> BfChassisManager::GetNodeIdToUnitMap()
    const {
  if (!initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }
  return node_id_to_unit_;
}

::util::Status BfChassisManager::ReplayPortsConfig(uint64 node_id) {
  if (!initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }
  ASSIGN_OR_RETURN(auto unit, GetUnitFromNodeId(node_id));

  for (auto& p : node_id_to_port_id_to_port_state_[node_id])
    p.second = PORT_STATE_UNKNOWN;

  for (auto& p : node_id_to_port_id_to_time_last_changed_[node_id]) {
    p.second = absl::UnixEpoch();
  }

  LOG(INFO) << "Replaying ports for node " << node_id << ".";

  auto replay_one_port = [node_id, unit, this](
                             uint32 port_id, const PortConfig& config,
                             PortConfig* config_new) -> ::util::Status {
    VLOG(1) << "Replaying port " << port_id << " in node " << node_id << ".";

    if (config.admin_state == ADMIN_STATE_UNKNOWN) {
      LOG(WARNING) << "Port " << port_id << " in node " << node_id
                   << " was not configured properly, so skipping replay.";
      return ::util::OkStatus();
    }

    if (!config.speed_bps) {
      RETURN_ERROR(ERR_INTERNAL)
          << "Invalid internal state in BfChassisManager, "
          << "speed_bps field should contain a value";
    }
    if (!config.fec_mode) {
      RETURN_ERROR(ERR_INTERNAL)
          << "Invalid internal state in BfChassisManager, "
          << "fec_mode field should contain a value";
    }

    ASSIGN_OR_RETURN(auto sdk_port_id, GetSdkPortId(node_id, port_id));
    RETURN_IF_ERROR(bf_sde_interface_->AddPort(
        unit, sdk_port_id, *config.speed_bps, *config.fec_mode));
    config_new->speed_bps = *config.speed_bps;
    config_new->admin_state = ADMIN_STATE_DISABLED;
    config_new->fec_mode = *config.fec_mode;

    if (config.mtu) {
      RETURN_IF_ERROR(
          bf_sde_interface_->SetPortMtu(unit, sdk_port_id, *config.mtu));
      config_new->mtu = *config.mtu;
    }
    if (config.autoneg) {
      RETURN_IF_ERROR(bf_sde_interface_->SetPortAutonegPolicy(unit, sdk_port_id,
                                                              *config.autoneg));
      config_new->autoneg = *config.autoneg;
    }
    if (config.loopback_mode) {
      RETURN_IF_ERROR(bf_sde_interface_->SetPortLoopbackMode(
          unit, sdk_port_id, *config.loopback_mode));
      config_new->loopback_mode = *config.loopback_mode;
    }

    if (config.admin_state == ADMIN_STATE_ENABLED) {
      VLOG(1) << "Enabling port " << port_id << " in node " << node_id
              << " (SDK port " << sdk_port_id << ").";
      RETURN_IF_ERROR(bf_sde_interface_->EnablePort(unit, sdk_port_id));
      config_new->admin_state = ADMIN_STATE_ENABLED;
    }

    return ::util::OkStatus();
  };

  ::util::Status status = ::util::OkStatus();  // errors to keep track of.

  for (auto& p : node_id_to_port_id_to_port_config_[node_id]) {
    uint32 port_id = p.first;
    PortConfig config_new;
    APPEND_STATUS_IF_ERROR(status,
                           replay_one_port(port_id, p.second, &config_new));
    p.second = config_new;
  }

  return status;
}

std::unique_ptr<BfChassisManager> BfChassisManager::CreateInstance(
    OperationMode mode,
    BfSdeInterface* bf_sde_interface) {
  return absl::WrapUnique(
      new BfChassisManager(mode, bf_sde_interface));
}

::util::StatusOr<int> BfChassisManager::GetUnitFromNodeId(
    uint64 node_id) const {
  if (!initialized_) {
    return MAKE_ERROR(ERR_NOT_INITIALIZED) << "Not initialized!";
  }
  const int* unit = gtl::FindOrNull(node_id_to_unit_, node_id);
  CHECK_RETURN_IF_FALSE(unit != nullptr)
      << "Node " << node_id << " is not configured or not known.";

  return *unit;
}

void BfChassisManager::CleanupInternalState() {
  unit_to_node_id_.clear();
  node_id_to_unit_.clear();
  node_id_to_port_id_to_port_state_.clear();
  node_id_to_port_id_to_time_last_changed_.clear();
  node_id_to_port_id_to_port_config_.clear();
  node_id_to_port_id_to_singleton_port_key_.clear();
  node_id_to_port_id_to_sdk_port_id_.clear();
  node_id_to_sdk_port_id_to_port_id_.clear();
  node_id_port_id_to_backend_.clear();
}

::util::Status BfChassisManager::Shutdown() {
  ::util::Status status = ::util::OkStatus();
  {
    absl::ReaderMutexLock l(&chassis_lock);
    if (!initialized_) return status;
  }
  // It is fine to release the chassis lock here (it is actually needed to call
  // UnregisterEventWriters or there would be a deadlock). Because initialized_
  // is set to true, RegisterEventWriters cannot be called.
  absl::WriterMutexLock l(&chassis_lock);
  initialized_ = false;
  CleanupInternalState();
  return status;
}

//}  // namespace barefoot
}  // namespace hal
}  // namespace stratum
