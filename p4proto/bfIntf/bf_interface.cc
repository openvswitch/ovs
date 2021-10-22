// Copyright 2018-2019 Barefoot Networks, Inc.
// Copyright 2020-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

/*
INFO: From Compiling stratum/lib/barefoot/bf_interface.cc:
In file included from stratum/lib/barefoot/bf_interface.cc:10:0:
./stratum/glue/init_google.h:13:6: warning: "GOOGLE_BASE_HAS_INITGOOGLE" is not
defined [-Wundef] #if !GOOGLE_BASE_HAS_INITGOOGLE
      ^~~~~~~~~~~~~~~~~~~~~~~~~~
*/

#include <absl/strings/str_format.h>
#include <absl/strings/string_view.h>

#include "stratum/glue/init_google.h"
#include "stratum/glue/logging.h"
#include "stratum/glue/status/status.h"
#include "stratum/hal/lib/barefoot/bf_sde_interface.h"
#include "stratum/hal/lib/barefoot/bf_sde_wrapper.h"
#include "stratum/hal/lib/barefoot/bfrt_action_profile_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_constants.h"
#include "stratum/hal/lib/barefoot/bfrt_counter_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_node.h"
#include "stratum/hal/lib/barefoot/bfrt_packetio_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_pre_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_table_manager.h"
#include "bf_chassis_manager.h"
#include "bf_interface.h"

#include "stratum/hal/lib/common/common.pb.h"
#include "stratum/lib/utils.h"
#include <string>
extern "C" {
#include "bf_types/bf_types.h"
#include "bf_types/bf_types.h"
#ifdef P4TOFINO
#include "tofino/bf_pal/bf_pal_port_intf.h"
#else
#include "bf_pal/bf_pal_port_intf.h"
#endif
}

#if 0
DEFINE_string(chassis_config_file, "/root/dpdk_chassis_config.pb.txt",
              "The latest verified ChassisConfig proto pushed to the switch. "
              "This proto is (re-)generated based on the pushed YANG proto and "
              "includes the overall running config at any point of time. "
              "Default is empty and it is expected to be explicitly given by "
              "flags.");
#endif


namespace stratum {
namespace barefoot {

using namespace ::stratum::hal;
using namespace ::stratum::hal::barefoot;

namespace {

::absl::Status ConvertStatusToAbsl(const ::util::Status& status) {
  if (status.ok()) return ::absl::OkStatus();
  // TODO(bocon): ensure code conversion matches
  return ::absl::Status(static_cast<::absl::StatusCode>(status.error_code()),
                        status.error_message());
}

}  // namespace

::absl::Status BfInterface::InitSde(const std::string& bf_sde_install,
                                    const std::string& bf_switchd_cfg,
                                    bool bf_switchd_background) {

  util::Status status = ::util::OkStatus();

  auto bf_sde_wrapper = BfSdeWrapper::CreateSingleton();
  bf_sde_wrapper->InitializeSde(bf_sde_install,
  bf_switchd_cfg, bf_switchd_background);
  if (!status.ok()) {
      return absl::InternalError(
          absl::StrFormat("Error when starting switchd"));
  }

  // TODO(antonin): The SDE expects 0-based device ids, so we instantiate
  // components with "device_id" instead of "node_id".
  int device_id = 0;

  auto result = bf_sde_wrapper->IsSoftwareModel(device_id);
  bool is_sw_model;
  if (result.ok())
    is_sw_model = result.ValueOrDie();
  else
    return ConvertStatusToAbsl(result.status());
  const OperationMode mode =
      is_sw_model ? OPERATION_MODE_SIM : OPERATION_MODE_STANDALONE;
  LOG(INFO) << "Detected is_sw_model: " << is_sw_model;
  LOG(INFO) << "SDE version: " << bf_sde_wrapper->GetSdeVersion();

  bfrt_table_manager_ =
      BfrtTableManager::CreateInstance(mode, bf_sde_wrapper, device_id);
  bfrt_action_profile_manager_ =
      BfrtActionProfileManager::CreateInstance(bf_sde_wrapper, device_id);
  bfrt_packetio_manager_ =
      BfrtPacketioManager::CreateInstance(bf_sde_wrapper, device_id);
  bfrt_pre_manager_ = BfrtPreManager::CreateInstance(bf_sde_wrapper, device_id);
  bfrt_counter_manager_ =
      BfrtCounterManager::CreateInstance(bf_sde_wrapper, device_id);
  bfrt_node_ = BfrtNode::CreateInstance(
      bfrt_table_manager_.get(), bfrt_action_profile_manager_.get(),
      bfrt_packetio_manager_.get(), bfrt_pre_manager_.get(),
      bfrt_counter_manager_.get(), bf_sde_wrapper, device_id);
  bf_chassis_manager_ =
      BfChassisManager::CreateInstance(mode, bf_sde_wrapper);

  return absl::OkStatus();
}

BfInterface* BfInterface::singleton_ = nullptr;
ABSL_CONST_INIT absl::Mutex BfInterface::init_lock_(absl::kConstInit);

BfInterface* BfInterface::CreateSingleton() {
  absl::WriterMutexLock l(&init_lock_);
  if (!singleton_) {
    singleton_ = new BfInterface();
  }

  return singleton_;
}

BfInterface* BfInterface::GetSingleton() {
  absl::ReaderMutexLock l(&init_lock_);
  return singleton_;
}

}  // namespace barefoot
}  // namespace stratum

using ::stratum::barefoot::BfInterface;

// A macro that converts an absl::Status to an int and returns it.
#define RETURN_STATUS(status) return static_cast<int>(status.code())

int bf_p4_init(const char* bf_sde_install, const char* bf_switchd_cfg,
               bool bf_switchd_background) {
  // Check if the SDE has already been initialized; presumably if the singleton
  // has been created.
  if (BfInterface::GetSingleton() != nullptr) return -1;
  RETURN_STATUS(BfInterface::CreateSingleton()->InitSde(
      bf_sde_install, bf_switchd_cfg, bf_switchd_background));
  return 0;
}

int bf_p4_destroy() {
  // TODO(bocon): Free bf_interface_ and teardown SDE
  return 0;
}

int bf_p4_add_port(uint64_t device, int64_t port,
                   port_properties_t *port_props)
{
#ifndef P4TOFINO
    auto port_attrs = absl::make_unique<port_attributes_t>();
#endif
#ifdef DPDK_PLATFORM
    int port_type = 3; //BF_DPDK_SOURCE
    int port_dir_type = 0; //PM_PORT_DIR_DEFAULT
    int port_in_id = port;
    int port_out_id = port;
    char port_dir[PIPE_NAME_LEN] = "PM_PORT_DIR_DEFAULT";
    char pipe_name[PIPE_NAME_LEN] = "pipe";
    char mempool_name[MEMPOOL_NAME_LEN] = "MEMPOOL0";
#endif

#ifndef P4TOFINO
    /* Make sure attributes structure is initialized to empty values */
    memset((void*)port_attrs.get(), 0, sizeof(port_attributes_t));

    strncpy(port_attrs->port_name, port_props->port_name, PORT_NAME_LEN);
#endif
#ifdef DPDK_PLATFORM
    strncpy(port_attrs->mempool_name, mempool_name, MEMPOOL_NAME_LEN);
    strncpy(port_attrs->pipe_name, pipe_name, PIPE_NAME_LEN);

    port_attrs->port_dir = static_cast<bf_pm_port_dir_e>(port_dir_type);
    port_attrs->port_type = static_cast<dpdk_port_type_t>(port_type);

    LOG(INFO) << "bf_pal_port_add() Args: DevId " << static_cast<bf_dev_id_t>(device)
        << " Port Id:" << static_cast<bf_dev_port_t>(port)
        << " name: " << port_attrs->port_name
        << " pipe_name: " << port_attrs->pipe_name
        << " mempool_name: " << port_attrs->mempool_name
        << " mtu: " << port_attrs->tap.mtu;
#else
    // TODO - Need to uncomment the line after SDE updates the interface file.
    //strncpy(port_attrs->mac, port_props->mac_in_use, MAC_STRING_LEN);
    LOG(INFO) << "bf_pal_port_add() Args: DevId " << static_cast<bf_dev_id_t>(device)
              << " Port Id:" << static_cast<bf_dev_port_t>(port)
              << " name: " << port_props->port_name;
#endif
#ifndef P4TOFINO
        bf_pal_port_add(static_cast<bf_dev_id_t>(device),
                        static_cast<bf_dev_port_t>(port),
                        port_attrs.get());
#endif
    return 0;
}
