// Copyright 2018 Google LLC
// Copyright 2018-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#include <string>
#include <utility>

#include <absl/container/flat_hash_set.h>
#include <absl/memory/memory.h>
#include <absl/synchronization/mutex.h>
#include <absl/time/clock.h>
#include <gflags/gflags.h>
#include <google/protobuf/any.pb.h>

#include "config_monitoring_service.h"
#include "stratum/glue/gtl/map_util.h"
#include "stratum/glue/gtl/stl_util.h"
#include "stratum/glue/logging.h"
#include "stratum/glue/status/status_macros.h"
#include "stratum/lib/macros.h"
#include "stratum/lib/utils.h"
#include "stratum/public/lib/error.h"

#include "gnmi_publisher.h"
#include "bfIntf/bf_interface.h"

DEFINE_string(openconfig_chassis_config_file, "/usr/share/stratum/dpdk_vhost_config.pb.txt",
              "The latest verified ChassisConfig proto pushed to the switch. "
              "This proto is (re-)generated based on the pushed YANG proto and "
              "includes the overall running config at any point of time. "
              "Default is empty and it is expected to be explicitly given by "
              "flags.");
DEFINE_string(gnmi_capabilities_file, "/etc/stratum/gnmi_caps.pb.txt",
              "Path to the file containing the gNMI capabilities proto.");

namespace stratum {
namespace hal {

using namespace ::stratum::barefoot;

ConfigMonitoringService::ConfigMonitoringService(
    OperationMode mode, BfChassisManager* bf_chassis_manager,
    AuthPolicyChecker* auth_policy_checker, ErrorBuffer* error_buffer)
    : running_chassis_config_(nullptr),
      mode_(mode),
      auth_policy_checker_(ABSL_DIE_IF_NULL(auth_policy_checker)),
      error_buffer_(ABSL_DIE_IF_NULL(error_buffer)),
      gnmi_publisher_(bf_chassis_manager) {
  if (TimerDaemon::Start() != ::util::OkStatus()) {
    LOG(ERROR) << "Could not start the timer subsystem.";
  }
}

ConfigMonitoringService::~ConfigMonitoringService() {
  if (TimerDaemon::Stop() != ::util::OkStatus()) {
    LOG(ERROR) << "Could not stop the timer subsystem.";
  }
}

::util::Status ConfigMonitoringService::Setup(bool warmboot) {
  ::util::Status status = gnmi_publisher_.RegisterEventWriter();
                       //bf_chassis_manager_->RegisterEventNotifyWriter(writer);
  if (!status.ok()) {
    error_buffer_->AddError(
        status, "Could not start the gNMI notification subsystem: ", GTL_LOC);
    return status;
  }

  // If we are coupled mode and are coldbooting, we do not do anything here.
  // TODO(unknown): This will be removed when we completely move to
  // standalone mode.
  if (!warmboot && mode_ == OPERATION_MODE_COUPLED) {
    LOG(INFO) << "Skipped pushing the saved chassis config in coupled mode "
              << "when coldbooting.";
    return ::util::OkStatus();
  }

  return PushSavedChassisConfig(warmboot);
}

::util::Status ConfigMonitoringService::Teardown() {
  absl::WriterMutexLock l(&config_lock_);
  running_chassis_config_ = nullptr;

  if (gnmi_publisher_.UnregisterEventWriter() != ::util::OkStatus()) {
    return MAKE_ERROR(ERR_INTERNAL)
           << "Could not stop the gNMI notification subsystem.";
  }

  return ::util::OkStatus();
}

::util::Status ConfigMonitoringService::PushSavedChassisConfig(bool warmboot) {
  // Try to read the saved chassis config and push it to the switch. The
  // config push will initialize the switch if it is done for the first time.
  LOG(INFO) << "Pushing the saved chassis config read from "
            << FLAGS_openconfig_chassis_config_file << "...";
  auto config = absl::make_unique<ChassisConfig>();
  ::util::Status status =
      ReadProtoFromTextFile(FLAGS_openconfig_chassis_config_file, config.get());
  if (!status.ok()) {
    if (!warmboot && status.error_code() == ERR_FILE_NOT_FOUND) {
      // Not a critical error. If coldboot, we don't even return error.
      LOG(WARNING) << "No saved chassis config found in "
                   << FLAGS_openconfig_chassis_config_file
                   << ". This is normal when the switch is just installed.";
      return ::util::OkStatus();
    }
    error_buffer_->AddError(status,
                            "Could not read saved chassis config: ", GTL_LOC);
    return status;
  }

  return PushChassisConfig(warmboot, std::move(config));
}

::util::Status ConfigMonitoringService::PushChassisConfig(
    bool warmboot, std::unique_ptr<ChassisConfig> config) {
  absl::WriterMutexLock l(&config_lock_);
  RETURN_IF_ERROR(VerifyChassisConfig(*config));
  // Push the config to hardware only if it is a coltboot setup.
  if (!warmboot) {

    ::util::Status status = BfInterface::GetSingleton()->bf_chassis_manager_->PushChassisConfig(*config);
    if (!status.ok()) {
      error_buffer_->AddError(status,
                              "Pushing saved chassis config failed: ", GTL_LOC);
      return status;
    }

    status = BfInterface::GetSingleton()->bfrt_node_->PushChassisConfig(*config, BfInterface::GetSingleton()->bfrt_node_->node_id_);
    if (!status.ok()) {
      error_buffer_->AddError(status,
                              "Pushing saved chassis config failed: ", GTL_LOC);
      return status;
    }
  }

  // Save running_chassis_config_ after everything went OK.
  running_chassis_config_ = std::move(config);

  // Notify the gNMI GnmiPublisher that the config has changed.
  RETURN_IF_ERROR(gnmi_publisher_.HandleChange(
      ConfigHasBeenPushedEvent(*running_chassis_config_)));

  return ::util::OkStatus();
}

namespace {
// Helper function to determine whether all protobuf messages in a container
// have an unique name field.
template <typename T>
bool ContainsUniqueNames(const T& values) {
  absl::flat_hash_set<std::string> unique_names;
  for (const auto& e : values) {
    if (e.name().empty()) continue;
    if (!gtl::InsertIfNotPresent(&unique_names, e.name())) {
      return false;
    }
  }
  return true;
}
}  // namespace

::util::Status ConfigMonitoringService::VerifyChassisConfig(
    const ChassisConfig& config) {
  // Validate the names of the components, if given.
  CHECK_RETURN_IF_FALSE(ContainsUniqueNames(config.nodes()));
  CHECK_RETURN_IF_FALSE(ContainsUniqueNames(config.singleton_ports()));
  CHECK_RETURN_IF_FALSE(ContainsUniqueNames(config.trunk_ports()));
  CHECK_RETURN_IF_FALSE(ContainsUniqueNames(config.port_groups()));
  CHECK_RETURN_IF_FALSE(
      ContainsUniqueNames(config.optical_network_interfaces()));

  return ::util::OkStatus();
}

::grpc::Status ConfigMonitoringService::Capabilities(
    ::grpc::ServerContext* context, const ::gnmi::CapabilityRequest* req,
    ::gnmi::CapabilityResponse* resp) {
  RETURN_IF_NOT_AUTHORIZED(auth_policy_checker_, ConfigMonitoringService,
                           Capabilities, context);
  return DoCapabilities(context, req, resp);
}

::grpc::Status ConfigMonitoringService::DoCapabilities(
    ::grpc::ServerContext* context, const ::gnmi::CapabilityRequest* req,
    ::gnmi::CapabilityResponse* resp) {
  // TODO(Yi): Use auto generated file or code.
  ::util::Status status;
  if (!(status = ReadProtoFromTextFile(FLAGS_gnmi_capabilities_file, resp))
           .ok()) {
    return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                          status.error_message());
  }
  return ::grpc::Status::OK;
}

::grpc::Status ConfigMonitoringService::Set(::grpc::ServerContext* context,
                                            const ::gnmi::SetRequest* req,
                                            ::gnmi::SetResponse* resp) {
  RETURN_IF_NOT_AUTHORIZED(auth_policy_checker_, ConfigMonitoringService, Set,
                           context);
  return DoSet(context, req, resp);
}

::grpc::Status ConfigMonitoringService::DoSet(::grpc::ServerContext* context,
                                              const ::gnmi::SetRequest* req,
                                              ::gnmi::SetResponse* resp) {
  absl::WriterMutexLock l(&config_lock_);

  CopyOnWriteChassisConfig config(running_chassis_config_.get());

  for (const auto& path : req->delete_()) {
    VLOG(1) << "SET(DELETE): " << path.ShortDebugString();
    ::util::Status status;
    ::gnmi::TypedValue val;
    if (!(status = gnmi_publisher_.HandleDelete(path, &config)).ok()) {
      // Something went wrong. Abort the whole gNMI SET operation.
      return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                            status.error_message());
    }
    // Add to response object in SetResponse
    ::gnmi::UpdateResult* res = resp->add_response();
    res->mutable_path()->CopyFrom(path);
    res->set_op(::gnmi::UpdateResult_Operation::UpdateResult_Operation_DELETE);
  }
  for (const auto& replace : req->replace()) {
    const auto& path = replace.path();
    VLOG(1) << "SET(REPLACE): " << path.ShortDebugString();
    ::util::Status status;
    if (!(status = gnmi_publisher_.HandleReplace(path, replace.val(), &config))
             .ok()) {
      return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                            status.error_message());
    }
    // Add to response object in SetResponse
    ::gnmi::UpdateResult* res = resp->add_response();
    res->mutable_path()->CopyFrom(replace.path());
    res->set_op(::gnmi::UpdateResult_Operation::UpdateResult_Operation_REPLACE);
  }
  for (const auto& update : req->update()) {
    const auto& path = update.path();
    VLOG(1) << "SET(UPDATE): " << path.ShortDebugString();
    ::util::Status status;
    if (!(status = gnmi_publisher_.HandleUpdate(path, update.val(), &config))
             .ok()) {
      return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                            status.error_message());
    }
    // Add to response object in SetResponse
    ::gnmi::UpdateResult* res = resp->add_response();
    res->mutable_path()->CopyFrom(update.path());
    res->set_op(::gnmi::UpdateResult_Operation::UpdateResult_Operation_UPDATE);
  }

  if (config.HasBeenChanged()) {
    // ChassisConfig has changed, so, we need to push it now!
    ::util::Status status = VerifyChassisConfig(*config);
    if (!status.ok()) {
      return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                            status.error_message());
    }

#if 0
    // TODO, check when we support config reply
    status = BfInterface::GetSingleton()->bf_chassis_manager_->PushChassisConfig(*config);
    if (!status.ok()) {
      error_buffer_->AddError(status,
                              "Pushing saved chassis config failed: ", GTL_LOC);
      return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                            status.error_message());
    }
#endif
    status = BfInterface::GetSingleton()->bfrt_node_->PushChassisConfig(*config,BfInterface::GetSingleton()->bfrt_node_->node_id_);
    if (!status.ok()) {
      error_buffer_->AddError(status,
                              "Pushing chassis config failed: ", GTL_LOC);
      return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                            status.error_message());
    }
 }

  // Add data to SetResponse Object
  resp->mutable_prefix()->CopyFrom(req->prefix());
  resp->mutable_extension()->CopyFrom(req->extension());
  resp->set_timestamp(absl::GetCurrentTimeNanos());
  return ::grpc::Status::OK;
}

::grpc::Status ConfigMonitoringService::Get(::grpc::ServerContext* context,
                                            const ::gnmi::GetRequest* req,
                                            ::gnmi::GetResponse* resp) {
  RETURN_IF_NOT_AUTHORIZED(auth_policy_checker_, ConfigMonitoringService, Get,
                           context);
  return DoGet(context, req, resp);
}

::grpc::Status ConfigMonitoringService::DoGet(::grpc::ServerContext* context,
                                              const ::gnmi::GetRequest* req,
                                              ::gnmi::GetResponse* resp) {
  absl::ReaderMutexLock l(&config_lock_);
  if (running_chassis_config_ == nullptr) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "No valid chassis config has been pushed so far.");
  }
  if (req->encoding() != ::gnmi::Encoding::PROTO) {
    // Unsupported case!
    return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                          "Get response can only be encoded as PROTO.");
  }

  for (const auto& path : req->path()) {
    VLOG(1) << "GET: " << path.ShortDebugString();
    if (path == GetPath()()) {
      // Special case - whole configuration.
      if (req->type() != ::gnmi::GetRequest::CONFIG) {
        // Unsupported case!
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT,
                              "Get '/' can be done for CONFIG elements only.");
      }
      auto* notification = resp->add_notification();
      // TODO(unknown): Set correct timestamp.
      notification->set_timestamp(0ll);
      // Prepare the update information.
      auto* update = notification->add_update();
      *update->mutable_path() = path;
      // TODO P4-OVS openconfig
#if 0
      // Convert the configuration from the internal format.
      ::util::StatusOr<openconfig::Device> out =
           OpenconfigConverter::ChassisConfigToOcDevice(
               *running_chassis_config_);
      if (out.ok()) {
        // Serialize the proto and add it to the response.
      update->mutable_val()->mutable_any_val()->PackFrom(out.ValueOrDie());
        return ::grpc::Status::OK;
      } else {
        return ::grpc::Status(ToGrpcCode(out.status().CanonicalCode()),
                              out.status().error_message());
      }
#else
      return ::grpc::Status::OK;
#endif
    } else {
      // Process the get request.
      SubscriptionHandle h;
      // An in-place stream that saves contents of the `update` field of the
      // `msg` PROTOBUF to the response that will be sent to the controller.
      InlineGnmiSubscribeStream stream(
          [resp](const ::gnmi::SubscribeResponse& msg) -> bool {
            // If msg has empty update, it might be a sync_response for
            // GetRequest
            if (!msg.has_update()) return msg.sync_response();
            *resp->add_notification() = msg.update();
            return true;
          });
      // Check if the path is supported.
      ::util::Status status;
      if ((status = gnmi_publisher_.SubscribePoll(path, &stream, &h)).ok()) {
        // Get the value(s) represented by the path.
        if (!(status = gnmi_publisher_.HandlePoll(h)).ok()) {
          return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                                status.error_message());
        }
      } else {
        return ::grpc::Status(ToGrpcCode(status.CanonicalCode()),
                              status.error_message());
      }
    }
  }
  return ::grpc::Status::OK;
}

::grpc::Status ConfigMonitoringService::Subscribe(
    ::grpc::ServerContext* context, ServerSubscribeReaderWriter* stream) {
  RETURN_IF_NOT_AUTHORIZED(auth_policy_checker_, ConfigMonitoringService,
                           Subscribe, context);
  return DoSubscribe(&gnmi_publisher_, context, stream);
}

namespace {

// A helper method that logs an error message and then sends the same message to
// the client.
void ReportError(const std::string& msg,
                 ServerSubscribeReaderWriterInterface* stream) {
  LOG(ERROR) << msg;
  // Report error to the remote side.
  ::gnmi::Error error;
  // TODO(unknown): make the error code an input parameter.
  error.set_code(1);
  error.set_message(msg);
  ::gnmi::SubscribeResponse resp;
  *resp.mutable_error() = error;
  stream->Write(resp, ::grpc::WriteOptions());
}

constexpr int kThousandMilliseconds = 1000 /* milliseconds */;

::util::Status HandleInitialSubscribeRequest(
    GnmiPublisher* publisher, ::grpc::ServerContext* context,
    ServerSubscribeReaderWriterInterface* stream,
    PathToHandleMap* subscriptions, PathToHandleMap* polls) {
  // Setting send_sync_response to `true` triggers sending a notification to the
  // client that all nodes have been processed. It is required by the gNMI spec
  // for initial ON_CHANGE values and the ONCE operation.
  bool send_sync_response = false;
  ::util::Status status;
  ::gnmi::SubscribeRequest req;
  if (!stream->Read(&req)) {
    // The client called WritesDone() or the stream has been closed.
    // Report error to the remote side.
    ReportError("No subscription request received.", stream);
    return MAKE_ERROR(ERR_INVALID_PARAM) << "No subscription request received.";
  }
  if (!req.has_subscribe()) {
    // The request did not contain actual subscribe request.
    // Report error to the remote side.
    ReportError("No valid subscription request received.", stream);
    return MAKE_ERROR(ERR_INVALID_PARAM)
           << "No valid subscription request received.";
  }

  std::string uri = context->peer();  // remote connection uri
  LOG(INFO) << "Initial Subscribe request from " << uri << " over stream "
            << stream << ".";
  VLOG(1) << "SubscribeRequest: " << req.ShortDebugString();
  int problems_found = 0;
  for (::gnmi::Subscription subscription : req.subscribe().subscription()) {
    // Note that 'subscription' is a non-const copy of the one stored in the
    // 'req' request. It has to be non-const in case it is a TARGET_DEFINED
    // subscription mode request that has to me modified/augmented before bein
    // processed further down the loop.
    SubscriptionHandle h;
    if (req.subscribe().mode() == ::gnmi::SubscriptionList::STREAM) {
      // A stream subscribe request.
      if (gtl::FindOrNull(*subscriptions, subscription.path()) != nullptr) {
        // An attempt to subscribe second time to the same path found!
        // Report error to the remote side.
        ReportError("Duplicated subscription received.", stream);
        ++problems_found;
        continue;
      }
      if (subscription.mode() == ::gnmi::SubscriptionMode::TARGET_DEFINED) {
        // The client has left the decision to us, so, let's modify the
        // subscription request to be what is defined for this path.
        if (publisher->UpdateSubscriptionWithTargetSpecificModeSpecification(
                subscription.path(), &subscription) != ::util::OkStatus()) {
          // An error was reported.
          ReportError("Error reported while converting TARGET_DEFINED request.",
                      stream);
          ++problems_found;
          continue;
        }
      }
      if (subscription.mode() == ::gnmi::SubscriptionMode::SAMPLE) {
        uint64 sample_interval = subscription.sample_interval() == 0
                                     ? kThousandMilliseconds
                                     : subscription.sample_interval();
        uint64 heartbeat_interval = subscription.heartbeat_interval() == 0
                                        ? kThousandMilliseconds
                                        : subscription.heartbeat_interval();
        if (!subscription.suppress_redundant()) {
          status = publisher->SubscribePeriodic(
              Periodic(sample_interval), subscription.path(), stream, &h);
        } else {
          status = publisher->SubscribePeriodic(
              PeriodicWithHeartbeat(sample_interval, heartbeat_interval),
              subscription.path(), stream, &h);
        }
        if (status == ::util::OkStatus()) {
          // A handle has to be saved, so, later we know what to unsubscribe.
          (*subscriptions)[subscription.path()] = h;
        } else {
          // Report error.
          ReportError(status.ToString(), stream);
          ++problems_found;
        }
      } else if (subscription.mode() == ::gnmi::SubscriptionMode::ON_CHANGE) {
        if ((status = publisher->SubscribeOnChange(subscription.path(), stream,
                                                   &h)) == ::util::OkStatus()) {
          // A handle has to be saved, so, later we know what to unsubscribe.
          (*subscriptions)[subscription.path()] = h;
          // In ON_CHANGE subscription mode, before any updates can be sent, the
          // switch has to sent the current state of the leaf/node, so, prepare
          // and transmit the data.
          if (publisher->SubscribePoll(subscription.path(), stream, &h) !=
              ::util::OkStatus()) {
            // Report error.
            ReportError("Path supports ON_CHANGE but not POLL.", stream);
            ++problems_found;
          } else {
            if (publisher->HandlePoll(h) != ::util::OkStatus()) {
              ReportError("Error while executing initial state of ON_CHANGE.",
                          stream);
              ++problems_found;
            } else {
              // Set a flag to trigger sending a notification to the client that
              // all nodes have been processed.
              send_sync_response = true;
            }
          }
        } else {
          // Report error.
          ReportError(status.ToString(), stream);
          ++problems_found;
        }
      }
    } else if (req.subscribe().mode() == ::gnmi::SubscriptionList::POLL) {
      // A poll subscribe request.
      VLOG(1) << "poll ";
      if (gtl::FindOrNull(*polls, subscription.path()) != nullptr) {
        // An attempt to subscribe second time to the same path found!
        // Report error to the remote side.
        ReportError("Duplicated subscription received.", stream);
        ++problems_found;
        continue;
      }
      if (publisher->SubscribePoll(subscription.path(), stream, &h) ==
          ::util::OkStatus()) {
        // A handle has to be saved, so, later we know what to unsubscribe
        // from.
        (*polls)[subscription.path()] = h;
      } else {
        // Report error.
        ReportError("Unsupported path.", stream);
        ++problems_found;
      }
    } else if (req.subscribe().mode() == ::gnmi::SubscriptionList::ONCE) {
      VLOG(1) << "one-shot ";
      // A one-shot request.
      if (publisher->SubscribePoll(subscription.path(), stream, &h) ==
          ::util::OkStatus()) {
        // Prepare and transmit the data.
        if (publisher->HandlePoll(h) != ::util::OkStatus()) {
          ReportError("Error while executing ONCE.", stream);
          ++problems_found;
        } else {
          send_sync_response = true;
        }
      } else {
        // Report error.
        ReportError("Unsupported path.", stream);
        ++problems_found;
      }
    } else {
      // Un-supported case!
      // Report error.
      ReportError("Unsupported subscribe mode.", stream);
      ++problems_found;
    }
  }
  if (send_sync_response &&
      publisher->SendSyncResponse(stream) != ::util::OkStatus()) {
    ReportError("Error sending sync_response.", stream);
    ++problems_found;
  }

  // TODO(unknown): Find out what to do if one (or more) of many subscription
  // paths is unsupported. For now this functions returns OK and expect the
  // remote end to close the connection.
  return ::util::OkStatus();
}

}  // namespace

::grpc::Status ConfigMonitoringService::DoSubscribe(
    GnmiPublisher* publisher, ::grpc::ServerContext* context,
    ServerSubscribeReaderWriterInterface* stream) {
  PathToHandleMap subscriptions;
  PathToHandleMap polls;
  ::util::Status status;
  // First process the subscription request. According to the spec there can be
  // only one!
  if ((status = HandleInitialSubscribeRequest(publisher, context, stream,
                                              &subscriptions, &polls)) !=
      ::util::OkStatus()) {
    return ::grpc::Status(::grpc::StatusCode::INTERNAL, status.ToString());
  }

  std::string uri = context->peer();  // remote connection uri
  // Now the only valid requests can be either POLL or ALIAS.
  ::gnmi::SubscribeRequest req;
  while (true) {
    if (stream->Read(&req)) {
      // All good! The message has been received! Let's process it!
      LOG(INFO) << "Subscribe request from " << uri << " over stream " << stream
                << ".";
      VLOG(1) << "SubscribeRequest: " << req.ShortDebugString();
      if (req.has_subscribe()) {
        // Invalid type of request at this stage! Such message is valid only
        // once at the very beginning.
        // Report error to the remote side.
        ReportError(
            "Invalid subscription request received. Only one per call "
            "allowed.",
            stream);
      } else if (req.has_poll()) {
        // A poll request. Get updates on all subscribed paths.
        VLOG(1) << "poll";
        for (const auto& mapping : polls) {
          if (publisher->HandlePoll(mapping.second) != ::util::OkStatus()) {
            ReportError("Error while executing POLL.", stream);
          }
        }
      } else if (req.has_aliases()) {
        // Received aliases to be created.
        ReportError("Received an alias request. Unsupported.", stream);
      } else {
        // Empty request!?
        ReportError("Received an empty request.", stream);
      }
    } else {
      // The client called WritesDone() or the stream has been closed.
      // Now the infinite loop should be stopped - no more requests will be
      // received.
      LOG(INFO) << "Subscribe stream " << stream << " from " << uri
                << " has been closed.";
      break;
    }
  }

  // Unsubscribe and delete all subscriptions and polls. This stops scheduled
  // timers and prevents access to freed gRPC resources.
  for (auto& subscription : subscriptions) {
    publisher->UnSubscribe(subscription.second);
  }
  subscriptions.clear();
  polls.clear();

  return ::grpc::Status::OK;
}

}  // namespace hal
}  // namespace stratum
