// Copyright 2021-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#ifndef STRATUM_LIB_BAREFOOT_BF_INTERFACE_H_
#define STRATUM_LIB_BAREFOOT_BF_INTERFACE_H_

// Define C functions to access BfInterface C++ class.
#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#define PORT_NAME_LEN 64
#define MAC_STRING_LEN 32

// Type for the binary representation of a Protobuf message.
typedef void* PackedProtobuf;

typedef enum port_type_t {
        TAP_PORT,
        LINK_PORT,
        SOURCE_PORT,
        SINK_PORT,
        ETHER_PORT,
        VIRTUAL_PORT
} port_type_t;

typedef struct port_properties_t {
        char port_name[PORT_NAME_LEN];         /*!< Port Name */
        char mac_in_use[MAC_STRING_LEN];       /*!< MAC in string format */
        uint32_t port_id;
        uint32_t port_in_id;       /*!< Port ID for Pipeline in Input Direction */
        uint32_t port_out_id;   /*!< Port ID for Pipeline in Output Direction */
        port_type_t port_type;            /*!< Port Type */
} port_properties_t;

int bf_p4_init(const char* bf_sde_install, const char* bf_switchd_cfg,
               bool bf_switchd_background);
int bf_p4_add_port(uint64_t device, int64_t port,
                   port_properties_t *port_props);

#ifdef __cplusplus
}  // extern "C"
#endif

// Define BfInterface C++ class.

#ifdef __cplusplus

#include <vector>
#include <absl/status/status.h>
#include <absl/synchronization/mutex.h>

#include "p4/v1/p4runtime.pb.h"
#include "stratum/hal/lib/barefoot/bf_sde_interface.h"
#include "stratum/hal/lib/barefoot/bf_sde_wrapper.h"
#include "stratum/hal/lib/barefoot/bfrt_action_profile_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_constants.h"
#include "stratum/hal/lib/barefoot/bfrt_counter_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_node.h"
#include "stratum/hal/lib/barefoot/bfrt_packetio_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_pre_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_table_manager.h"
#include "stratum/hal/lib/barefoot/bfrt_switch.h"
#include "bf_chassis_manager.h"

namespace stratum {
namespace barefoot {

using namespace ::stratum::hal;
using namespace ::stratum::hal::barefoot;

// TODO(bocon): The "BfSdeInterface" class in HAL implements a shim layer
// around the Barefoot
class BfInterface {
 public:
  ::absl::Status InitSde(const std::string& bf_sde_install,
                         const std::string& bf_switchd_cfg,
                         bool bf_switchd_background);

  // Creates the singleton instance. Expected to be called once to initialize
  // the instance.
  static BfInterface* CreateSingleton() LOCKS_EXCLUDED(init_lock_);

  // Return the singleton instance to be used in the SDE callbacks.
  static BfInterface* GetSingleton() LOCKS_EXCLUDED(init_lock_);

  // BfRt Managers.
  std::unique_ptr<BfrtTableManager> bfrt_table_manager_;
  std::unique_ptr<BfrtActionProfileManager> bfrt_action_profile_manager_;
  std::unique_ptr<BfrtPacketioManager> bfrt_packetio_manager_;
  std::unique_ptr<BfrtPreManager> bfrt_pre_manager_;
  std::unique_ptr<BfrtCounterManager> bfrt_counter_manager_;
  // TODO: We are going to extend bfrt_node[] as an array
  std::unique_ptr<BfrtNode> bfrt_node_;
  //TODO: Linking device_id_to_bfrt_node_ to point to proper bfrt_node_.
  std::map<int, BfrtNode*> device_id_to_bfrt_node_;
  std::unique_ptr<BfChassisManager> bf_chassis_manager_;

 protected:

 protected:
  // RW mutex lock for protecting the singleton instance initialization and
  // reading it back from other threads. Unlike other singleton classes, we
  // use RW lock as we need the pointer to class to be returned.
  static absl::Mutex init_lock_;

  // The singleton instance.
  static BfInterface* singleton_ GUARDED_BY(init_lock_);
};

}  // namespace barefoot
}  // namespace stratum

#endif  //  __cplusplus

#endif  // STRATUM_LIB_BAREFOOT_BF_INTERFACE_H_
