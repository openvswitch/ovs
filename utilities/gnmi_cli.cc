// Copyright 2019-present Open Networking Foundation
// SPDX-License-Identifier: Apache-2.0

#include <csignal>
#include <iostream>
#include <memory>
#include <regex>  // NOLINT
#include <string>
#include <vector>

#include "gflags/gflags.h"
#include "gnmi/gnmi.grpc.pb.h"
#include "grpcpp/grpcpp.h"
#include "grpcpp/security/credentials.h"
#include "openvswitch/ofp-parse.h"
#include "util.h"

const char kUsage[] =
    R"USAGE(usage: gnmi-cli [--help] [Options] {get,set,cap,sub-onchange,sub-sample} parameters

Basic gNMI CLI

positional arguments:
  {get,set,cap,sub-onchange,sub-sample}         gNMI command
  parameter                                     gNMI config parameters

optional arguments:
  --help            show this help message and exit

parameters:
  "device:<type>,name=<name>,<key:value>"

example:
   gnmi-cli set "device:<type>,name=<name>,<key:value>,<key:value>,..."
   gnmi-cli get "device:<type>,name=<name>,key"
)USAGE";

#define GNMI_PREDICT_ERROR(x) (__builtin_expect(false || (x), false))

#define PRINT_MSG(msg, prompt)                   \
  do {                                           \
    std::cout << prompt << std::endl;            \
    std::cout << msg.DebugString() << std::endl; \
  } while (0)

#define RETURN_IF_GRPC_ERROR(expr)                                             \
  do {                                                                         \
    const ::grpc::Status _grpc_status = (expr);                                \
    if (GNMI_PREDICT_ERROR(!_grpc_status.ok())) {                              \
      std::cout << "Return grpc errno ("<< _grpc_status.error_code() <<        \
                   "), Reason: "<<_grpc_status.error_message() << std::endl;   \
      return 0;                                                                \
    }                                                                          \
  } while (0)

#define MAX_STR_LENGTH 128

// FIXME: For now it is connecting to localhost and later it has to be fixed
// to support any host, by providing an CLI options to the user.
DEFINE_string(grpc_addr, "127.0.0.1:9339", "gNMI server address");

DEFINE_uint64(interval, 5000, "Subscribe poll interval in ms");
DEFINE_bool(replace, false, "Use replace instead of update");
DEFINE_string(get_type, "ALL", "The gNMI get request type");

DEFINE_string(root_node, "/interfaces/", "The gNMI root node name");
DEFINE_string(device_key, "device", "The gNMI cli device key");
DEFINE_string(device_type_virtual_interface, "virtual-interface",
               "The gNMI cli device type");

DEFINE_string(name_key, "name", "The gNMI cli name key");
DEFINE_string(subtree_config, "config", "The gNMI path subtree of type config");

namespace gnmi {

void add_path_elem(std::string elem_name, std::string elem_kv,
                   ::gnmi::PathElem* elem) {
  elem->set_name(elem_name);
  if (!elem_kv.empty()) {
    std::regex ex("\\[([^=]+)=([^\\]]+)\\]");
    std::smatch sm;
    std::regex_match(elem_kv, sm, ex);
    (*elem->mutable_key())[sm.str(1)] = sm.str(2);
  }
}

void build_gnmi_path(std::string path_str, ::gnmi::Path* path) {
  std::regex ex("/([^/\\[]+)(\\[([^=]+=[^\\]]+)\\])?");
  std::sregex_iterator iter(path_str.begin(), path_str.end(), ex);
  std::sregex_iterator end;
  while (iter != end) {
    std::smatch sm = *iter;
    auto* elem = path->add_elem();
    add_path_elem(sm.str(1), sm.str(2), elem);
    iter++;
  }
}

::gnmi::GetRequest build_gnmi_get_req(std::string path) {
  ::gnmi::GetRequest req;
  build_gnmi_path(path, req.add_path());
  req.set_encoding(::gnmi::PROTO);
  ::gnmi::GetRequest::DataType data_type;
  if (!::gnmi::GetRequest::DataType_Parse(FLAGS_get_type, &data_type)) {
    std::cout << "Invalid gNMI get data type: " << FLAGS_get_type
              << " , use ALL as data type." << std::endl;
    data_type = ::gnmi::GetRequest::ALL;
  }
  req.set_type(data_type);
  return req;
}

::gnmi::SetRequest build_gnmi_set_req(std::string path, std::string val) {
  ::gnmi::SetRequest req;
  ::gnmi::Update* update;
  char *check;

  if (FLAGS_replace) {
    update = req.add_replace();
  } else {
    update = req.add_update();
  }
  build_gnmi_path(path, update->mutable_path());
  strtol (val.c_str(),&check,10);
  if (*check) {
    update->mutable_val()->set_string_val(val);
  } else {
    update->mutable_val()->set_int_val(stoull(val));
  }
  return req;
}

::gnmi::SetRequest build_gnmi_del_req(std::string path) {
  ::gnmi::SetRequest req;
  auto* del = req.add_delete_();
  build_gnmi_path(path, del);
  return req;
}

::gnmi::SubscribeRequest build_gnmi_sub_onchange_req(std::string path) {
  ::gnmi::SubscribeRequest sub_req;
  auto* sub_list = sub_req.mutable_subscribe();
  sub_list->set_mode(::gnmi::SubscriptionList::STREAM);
  sub_list->set_updates_only(true);
  auto* sub = sub_list->add_subscription();
  sub->set_mode(::gnmi::ON_CHANGE);
  build_gnmi_path(path, sub->mutable_path());
  return sub_req;
}

::gnmi::SubscribeRequest build_gnmi_sub_sample_req(
    std::string path, ::google::protobuf::uint64 interval) {
  ::gnmi::SubscribeRequest sub_req;
  auto* sub_list = sub_req.mutable_subscribe();
  sub_list->set_mode(::gnmi::SubscriptionList::STREAM);
  sub_list->set_updates_only(true);
  auto* sub = sub_list->add_subscription();
  sub->set_mode(::gnmi::SAMPLE);
  sub->set_sample_interval(interval);
  build_gnmi_path(path, sub->mutable_path());
  return sub_req;
}

bool extract_interface_node(char **path, char *node_path) {
  char *key =  NULL;
  char *value =  NULL;
  int found_node = 0;

  while(ofputil_parse_key_value(path, &key, &value)) {
      if (strcmp(key, FLAGS_device_key.c_str()) == 0) {
          snprintf(node_path+strlen(node_path),
                   strlen(FLAGS_device_type_virtual_interface.c_str())+1, "%s",
                   FLAGS_device_type_virtual_interface.c_str());
          found_node += 1;
      }
      if (strcmp(key, FLAGS_name_key.c_str()) == 0) {
          // Hardcoded lenght of "[name=]/"
          snprintf(node_path+strlen(node_path), strlen(value)+9,
                   "[name=%s]/", value);
          found_node += 1;
      }
      if (found_node == 2)
          return 0;
  }
  return -1;
}

void traverse_params(char **path, char *node_path, char *config_value, bool &flag) {
  char *key =  NULL;
  char *value =  NULL;

  if(ofputil_parse_key_value(path, &key, &value)) {
      if ((value != NULL) && value[0] != '\0') {
          // This should be executed for a <key=value> pair, specifically for
          // SET operation.
          snprintf(node_path+strlen(node_path),
                   strlen(FLAGS_subtree_config.c_str())+strlen(key)+2,
                   "%s/%s", FLAGS_subtree_config.c_str(), key);
          strcpy(config_value, value);
          return;
      } else if (key != NULL && key[0] != '\0') {
          // This should be executed for a <key>, specifically for
          // GET operation.
          snprintf(node_path+strlen(node_path),
                   strlen(FLAGS_subtree_config.c_str())+strlen(key)+2,
                   "%s/%s", FLAGS_subtree_config.c_str(), key);
          return;
      }
  }
  flag = false;
  return;
}

::grpc::ClientReaderWriterInterface<
    ::gnmi::SubscribeRequest, ::gnmi::SubscribeResponse>* stream_reader_writer;

int Main(int argc, char** argv) {
  if (argc < 2) {
    std::cout << kUsage << std::endl;
    std::cout << "Invalid number of arguments.";
    return 0;
  }
  ::grpc::Status status;
  std::shared_ptr<::grpc::ChannelCredentials> channel_credentials =
      ::grpc::InsecureChannelCredentials();
  auto channel = ::grpc::CreateChannel(FLAGS_grpc_addr, channel_credentials);
  std::string cmd = std::string(argv[1]);

  if (cmd == "cap") {
    auto stub = ::gnmi::gNMI::NewStub(channel);
    ::grpc::ClientContext ctx;
    ::gnmi::CapabilityRequest req;
    //PRINT_MSG(req, "REQUEST");
    ::gnmi::CapabilityResponse resp;
    RETURN_IF_GRPC_ERROR(stub->Capabilities(&ctx, req, &resp));
    PRINT_MSG(resp, "RESPONSE");
    return 0;
  }

  if (argc < 3) {
    std::cout << "Missing path for " << cmd << " request.";
    return 0;
  }

  char *path = argv[2];
  char buffer[MAX_STR_LENGTH];
  bool params = true;

  ovs_strzcpy(buffer, FLAGS_root_node.c_str(), MAX_STR_LENGTH);
  if (extract_interface_node(&path, buffer)) {
    std::cout << "Couldnt extract device and name information";
    return 0;
  }

  if (cmd == "get") {
    auto stub = ::gnmi::gNMI::NewStub(channel);
    ::grpc::ClientContext ctx;
    char path1[MAX_STR_LENGTH] = {0};
    char config_value[MAX_STR_LENGTH] = {0};

    strcpy(path1, buffer);
    traverse_params(&path, path1, config_value, params);
    ::gnmi::GetRequest req = build_gnmi_get_req(path1);
    ::gnmi::GetResponse resp;
    RETURN_IF_GRPC_ERROR(stub->Get(&ctx, req, &resp));
    PRINT_MSG(resp, "Get Response from Server");
  } else if (cmd == "set") {
    while(params) {
      char path1[MAX_STR_LENGTH] = {0};
      char config_value[MAX_STR_LENGTH] = {0};

      strcpy(path1, buffer);
      traverse_params(&path, path1, config_value, params);
      if (params) {
        auto stub = ::gnmi::gNMI::NewStub(channel);
        ::grpc::ClientContext ctx;
        ::gnmi::SetRequest req = build_gnmi_set_req(path1, config_value);
        ::gnmi::SetResponse resp;
        RETURN_IF_GRPC_ERROR(stub->Set(&ctx, req, &resp));
      }
    }
    std::cout << "Set request, successful...!!!" << std::endl;
  } else if (cmd == "del") {
    auto stub = ::gnmi::gNMI::NewStub(channel);
    ::grpc::ClientContext ctx;
    ::gnmi::SetRequest req = build_gnmi_del_req(path);
    ::gnmi::SetResponse resp;
    RETURN_IF_GRPC_ERROR(stub->Set(&ctx, req, &resp));
    PRINT_MSG(resp, "RESPONSE");
  } else if (cmd == "sub-onchange") {
    auto stub = ::gnmi::gNMI::NewStub(channel);
    ::grpc::ClientContext ctx;
    auto stream_reader_writer_ptr = stub->Subscribe(&ctx);
    stream_reader_writer = stream_reader_writer_ptr.get();
    ::gnmi::SubscribeRequest req = build_gnmi_sub_onchange_req(path);
    // CHECK_RETURN_IF_FALSE(stream_reader_writer->Write(req))
    stream_reader_writer->Write(req);
     //   << "Can not write request.";
    ::gnmi::SubscribeResponse resp;
    while (stream_reader_writer->Read(&resp)) {
      PRINT_MSG(resp, "RESPONSE");
    }
    RETURN_IF_GRPC_ERROR(stream_reader_writer->Finish());
  } else if (cmd == "sub-sample") {
    auto stub = ::gnmi::gNMI::NewStub(channel);
    ::grpc::ClientContext ctx;
    auto stream_reader_writer_ptr = stub->Subscribe(&ctx);
    stream_reader_writer = stream_reader_writer_ptr.get();
    ::gnmi::SubscribeRequest req =
        build_gnmi_sub_sample_req(path, FLAGS_interval);
    //CHECK_RETURN_IF_FALSE(stream_reader_writer->Write(req))
    stream_reader_writer->Write(req);
    //    << "Can not write request.";
    ::gnmi::SubscribeResponse resp;
    while (stream_reader_writer->Read(&resp)) {
      PRINT_MSG(resp, "RESPONSE");
    }
    RETURN_IF_GRPC_ERROR(stream_reader_writer->Finish());
  } else {
    std::cout << "Unknown command: " << cmd;
  }

  return 0;
}

void HandleSignal(int signal) {
  (void)signal;
  // Terminate the stream
  if (stream_reader_writer != nullptr) {
    stream_reader_writer->WritesDone();
  }
}

}  // namespace gnmi

int main(int argc, char** argv) {
  ::gflags::SetUsageMessage(kUsage);
  return gnmi::Main(argc, argv);
}
