// Copyright 2018 Google LLC
// Copyright 2018-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#include <absl/strings/str_split.h>
#include <gflags/gflags.h>

#include "p4_service.h"
#include "config_monitoring_service.h"
#include "p4_service_interface.h"
#include "bfIntf/bf_interface.h"


const char bf_sde_install[] = "/usr";
const char bf_switchd_cfg[] = "/usr/share/stratum/target_skip_p4_no_bsp.conf";
const bool bf_switchd_background = false;

DEFINE_string(external_p4server_urls, kExternalP4serverUrls,
              "Comma-separated list of URLs for server to listen to for "
              "external calls from SDN controller, etc.");
DEFINE_string(local_p4server_url, kLocalP4serverUrl,
              "URL for listening to local calls from p4server stub.");
DEFINE_int32(grpc_keepalive_time_ms, 600000, "grpc keep alive time");
DEFINE_int32(grpc_keepalive_timeout_ms, 20000,
             "grpc keep alive timeout period");
DEFINE_int32(grpc_keepalive_min_ping_interval, 10000,
             "grpc keep alive minimum ping interval");
DEFINE_int32(grpc_keepalive_permit, 1, "grpc keep alive permit");
DEFINE_uint32(grpc_max_recv_msg_size, 256 * 1024 * 1024,
              "grpc server max receive message size (0 = gRPC default).");
DEFINE_uint32(grpc_max_send_msg_size, 0,
              "grpc server max send message size (0 = gRPC default).");


::grpc::ServerBuilder builder;
std::unique_ptr<::grpc::Server> external_server_ = NULL;
std::unique_ptr<::stratum::hal::P4Service> p4_service_ = NULL;
std::unique_ptr<::stratum::hal::ConfigMonitoringService>
                                    config_monitoring_service_ = NULL;

using namespace ::stratum::barefoot;
BfInterface* bfIntf;

/* Set the channel arguments to match the defualt keep-alive parameters set by
 * the google3 side net/grpc clients. */
void SetGrpcServerKeepAliveArgs(::grpc::ServerBuilder* builder) {
    builder->AddChannelArgument(GRPC_ARG_KEEPALIVE_TIME_MS,
                                FLAGS_grpc_keepalive_time_ms);
    builder->AddChannelArgument(GRPC_ARG_KEEPALIVE_TIMEOUT_MS,
                                FLAGS_grpc_keepalive_timeout_ms);
    builder->AddChannelArgument(
        GRPC_ARG_HTTP2_MIN_RECV_PING_INTERVAL_WITHOUT_DATA_MS,
        FLAGS_grpc_keepalive_min_ping_interval);
    builder->AddChannelArgument(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS,
                                FLAGS_grpc_keepalive_permit);
}

extern "C" {
/* An API that does initialization and adds listen port(s) to the server. */
enum status_code p4_server_init(const char* port_details)
{
    enum status_code status = SUCCESS;
    const std::vector<std::string> external_p4server_urls =
        absl::StrSplit(port_details, ',');

    SetGrpcServerKeepAliveArgs(&builder);
    builder.AddListeningPort(FLAGS_local_p4server_url,
                             ::grpc::InsecureServerCredentials());

    for (const auto& url : external_p4server_urls) {
      builder.AddListeningPort(url,
                      ::grpc::InsecureServerCredentials());
    }
    if (FLAGS_grpc_max_recv_msg_size > 0) {
      builder.SetMaxReceiveMessageSize(FLAGS_grpc_max_recv_msg_size);
      builder.AddChannelArgument<int>(GRPC_ARG_MAX_METADATA_SIZE,
                                      FLAGS_grpc_max_recv_msg_size);
    }
    if (FLAGS_grpc_max_send_msg_size > 0) {
      builder.SetMaxSendMessageSize(FLAGS_grpc_max_send_msg_size);
    }

    google::InitGoogleLogging("p4server_test");

    LOG(INFO) << "P4 server: listen port created ...";
    return status;
}

/* An API that does  P4 service registration and starts the P4 server.
 * This API also instantiates the BfInterface singletion class for
 * interacting with the southbond interface of the Bfnode C wrapper library. */
enum status_code p4_server_run(void)
{
    enum status_code status = SUCCESS;

    // Assumption: BfInterface is already created and Init() by P4-proto module.
    bfIntf = ::stratum::barefoot::BfInterface::GetSingleton();
    if(bfIntf == nullptr) {
       return  NULL_BFINTF;
    }

    // Create the Auth policy checker instance
    auto auth_policy_checker = ::stratum::AuthPolicyChecker::CreateInstance();

    auto error_buffer = new ErrorBuffer();

    p4_service_ = absl::make_unique<::stratum::hal::P4Service>(
                        stratum::hal::OPERATION_MODE_STANDALONE,
                        auth_policy_checker.get(), error_buffer);

    if (p4_service_ == nullptr) {
      LOG(ERROR) << "Failed to Initialize the P4 service.";
      return NULL_SERVICE;
    }

    builder.RegisterService(p4_service_.get());

    config_monitoring_service_ =
                              absl::make_unique<::stratum::hal::ConfigMonitoringService>(
                                        stratum::hal::OPERATION_MODE_STANDALONE,
                                        BfInterface::GetSingleton()->bf_chassis_manager_.get(),
                                        auth_policy_checker.get(),
                                        error_buffer);
    if (config_monitoring_service_ == nullptr) {
      LOG(ERROR) << "Failed to Initialize the config monitoring service.";
      return NULL_SERVICE;
    }

    config_monitoring_service_->Setup(false);
    builder.RegisterService(config_monitoring_service_.get());

    LOG(INFO) << "P4 server: P4 service registered.";

    external_server_ = builder.BuildAndStart();
    if (external_server_ == nullptr) {
      LOG(ERROR) << "Failed to start the server.";
      return NO_SERVER;
    }

    LOG(INFO) << "P4 server: server started successfully.";

    external_server_->Wait();
    return status;
}

/* An API that does the server shutdown and teardown of the P4 service. */
enum status_code p4_server_shutdown(void)
{
    ::util::Status u_status = ::util::OkStatus();
    enum status_code status = SUCCESS;

    if (external_server_ == nullptr) {
      LOG(INFO) << "No active server present; Not possible to shutdown";
      return NO_SERVER;
    }
    external_server_->Shutdown(std::chrono::system_clock::now());

    if (p4_service_ == nullptr) {
      LOG(INFO) << "Failed to teardown the P4 service.";
      return NULL_SERVICE;
    }

    u_status = p4_service_->Teardown();

    if (!u_status.ok()) {
        LOG(ERROR) << u_status;
        status = FAILED_TO_TEARDOWN;
    }

    return status;
}

}
