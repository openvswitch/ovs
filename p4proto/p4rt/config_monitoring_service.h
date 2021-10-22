// Copyright 2018 Google LLC
// Copyright 2018-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#ifndef STRATUM_HAL_LIB_COMMON_CONFIG_MONITORING_SERVICE_H_
#define STRATUM_HAL_LIB_COMMON_CONFIG_MONITORING_SERVICE_H_

#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "p4/gnmi/gnmi.grpc.pb.h"
#include "p4/gnmi/gnmi.pb.h"
#include "grpcpp/grpcpp.h"
#include "stratum/glue/integral_types.h"
#include "stratum/glue/status/status.h"
#include "stratum/hal/lib/common/common.pb.h"
#include "stratum/hal/lib/common/error_buffer.h"
#include "gnmi_publisher.h"
#include "bfIntf/bf_chassis_manager.h"
#include "stratum/lib/security/auth_policy_checker.h"

namespace stratum {
namespace hal {

using ServerSubscribeReaderWriter =
    ::grpc::ServerReaderWriter<::gnmi::SubscribeResponse,
                               ::gnmi::SubscribeRequest>;
using ServerSubscribeReaderWriterInterface =
    ::grpc::ServerReaderWriterInterface<::gnmi::SubscribeResponse,
                                        ::gnmi::SubscribeRequest>;

// The "ConfigMonitoringService" class implements ::gnmi::gNMI::Service. It
// handles all the RPCs that are part of the gRPC Network Management Interface
// (gNMI) which are in charge of configuration and monitoring/telemetry.
class ConfigMonitoringService final : public ::gnmi::gNMI::Service {
 public:
  ConfigMonitoringService(OperationMode mode, BfChassisManager* bf_chassis_manager,
                          AuthPolicyChecker* auth_policy_checker,
                          ErrorBuffer* error_buffer);
  ~ConfigMonitoringService() override;

  // Sets up the service in coldboot and warmboot mode. In the coldboot mode,
  // the function initializes the class and pushes the saved chassis config to
  // the switch. In the warmboot mode, it only restores the internal state of
  // the class.
  ::util::Status Setup(bool warmboot) LOCKS_EXCLUDED(config_lock_);

  // Tears down the class. Called in both warmboot or coldboot mode. It will
  // not alter any state on the hardware when called.
  ::util::Status Teardown() LOCKS_EXCLUDED(config_lock_);

  // Public helper function called in Setup(). It deserializes the contents
  // of the FLAGS_chassis_config_file file and calls PushChassisConfig().
  ::util::Status PushSavedChassisConfig(bool warmboot);

  // Public helper function that is called to perform actual config push. It is
  // called by PushSavedChassisConfig(). It takes ownership of the 'config'
  // pointer and passes it to 'running_chassis_config_'.
  ::util::Status PushChassisConfig(bool warmboot,
                                   std::unique_ptr<ChassisConfig> config)
      LOCKS_EXCLUDED(config_lock_);

  // Verifies platform independent properties of the given ChassisConfig proto.
  // It is called by PushChassisConfig at the beginning and by Set operations to
  // verify the new configuration.
  ::util::Status VerifyChassisConfig(const ChassisConfig& config);

  // Returns the set of capabilities that is supported by the switch.
  ::grpc::Status Capabilities(::grpc::ServerContext* context,
                              const ::gnmi::CapabilityRequest* req,
                              ::gnmi::CapabilityResponse* resp) override
      LOCKS_EXCLUDED(config_lock_);

  // Modify the state/config on the switch. The paths to modify along with the
  // new values that the client wishes to set the value to are given in the
  // request.
  ::grpc::Status Set(::grpc::ServerContext* context,
                     const ::gnmi::SetRequest* req,
                     ::gnmi::SetResponse* resp) override
      LOCKS_EXCLUDED(config_lock_);

  // Returns snapshots a subset of the config/state tree as specified by the
  // paths included in the request.
  ::grpc::Status Get(::grpc::ServerContext* context,
                     const ::gnmi::GetRequest* req,
                     ::gnmi::GetResponse* resp) override
      LOCKS_EXCLUDED(config_lock_);

  // Subscribe allows a client to request the switch to send it values
  // of particular paths within the config/state tree. These values may be
  // streamed at a particular cadence (STREAM), sent one off on a long-lived
  // channel (POLL), or sent as a one-off retrieval (ONCE).
  ::grpc::Status Subscribe(::grpc::ServerContext* context,
                           ServerSubscribeReaderWriter* stream) override
      LOCKS_EXCLUDED(config_lock_);

  // ConfigMonitoringService is neither copyable nor movable.
  ConfigMonitoringService(const ConfigMonitoringService&) = delete;
  ConfigMonitoringService& operator=(const ConfigMonitoringService&) = delete;

 private:
  // The actual method that implements 'Capabilites' the allows a client to
  // request the switch to send models it supported.
  // This is implemented this way to enable unit tests of the Capabilites
  // method.
  ::grpc::Status DoCapabilities(::grpc::ServerContext* context,
                                const ::gnmi::CapabilityRequest* req,
                                ::gnmi::CapabilityResponse* resp);
  // The actual method that implements 'Subscribe' that allows a client to
  // request the switch to send it values of particular paths within the
  // config/state tree. These values may be streamed at a particular cadence
  // (STREAM), sent one off on a long-lived channel (POLL), or sent as a one-off
  // retrieval (ONCE). This is implemented this way to enable unit tests of the
  // Subscribe method whose 'stream' parameter type is marked 'final' and
  // therefore cannot be mocked.
  ::grpc::Status DoSubscribe(GnmiPublisher* publisher,
                             ::grpc::ServerContext* context,
                             ServerSubscribeReaderWriterInterface* stream)
      LOCKS_EXCLUDED(config_lock_);

  // The actual method that implements 'Get' that allows a client to
  // request the switch to send it values of particular paths within the
  // config/state tree. These values are sent as a one-off
  // retrieval. This is implemented this way to enable unit tests of the
  // Get method.
  ::grpc::Status DoGet(::grpc::ServerContext* context,
                       const ::gnmi::GetRequest* req, ::gnmi::GetResponse* resp)
      LOCKS_EXCLUDED(config_lock_);

  // The actual method that implements 'Set' that allows a client to
  // request the switch to change values of particular paths within the
  // config/state tree. This is implemented this way to enable unit tests of the
  // Set method.
  ::grpc::Status DoSet(::grpc::ServerContext* context,
                       const ::gnmi::SetRequest* req, ::gnmi::SetResponse* resp)
      LOCKS_EXCLUDED(config_lock_);

  // Mutex lock for protecting the internal chassis config pushed to the switch.
  mutable absl::Mutex config_lock_;

  // Hold the ChassisConfig which is currently running on the switch.
  std::unique_ptr<ChassisConfig> running_chassis_config_
      GUARDED_BY(config_lock_);

  // Determines the mode of operation:
  // - OPERATION_MODE_STANDALONE: when Stratum stack runs independently and
  // therefore needs to do all the SDK initialization itself.
  // - OPERATION_MODE_COUPLED: when Stratum stack runs as part of Sandcastle
  // stack, coupled with the rest of stack processes.
  // - OPERATION_MODE_SIM: when Stratum stack runs in simulation mode.
  // Note that this variable is set upon initialization and is never changed
  // afterwards.
  OperationMode mode_;

  // Pointer to AuthPolicyChecker. Not owned by this class.
  AuthPolicyChecker* auth_policy_checker_;

  // Pointer to ErrorBuffer to save any critical errors we encounter. Not owned
  // by this class.
  ErrorBuffer* error_buffer_;

  // An object handling gNMI Subscribe, Set and Get requests.
  GnmiPublisher gnmi_publisher_;

  friend class ConfigMonitoringServiceTest;
};

}  // namespace hal
}  // namespace stratum

#endif  // STRATUM_HAL_LIB_COMMON_CONFIG_MONITORING_SERVICE_H_
