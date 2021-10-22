// Copyright 2018 Google LLC
// Copyright 2018-present Open Networking Foundation
// Copyright(c) 2021 Intel Corporation.
// SPDX-License-Identifier: Apache-2.0

#ifndef P4SERVER_P4_SERVICE_INTERFACE_H_
#define P4SERVER_P4_SERVICE_INTERFACE_H_

#ifdef  __cplusplus
extern "C" {
#endif

enum status_code {
  SUCCESS = 0,
  NULL_SERVICE = 1,
  NO_SERVER = 2,
  NULL_BFINTF = 3,
  FAILED_TO_TEARDOWN = 4,
};

/* An API that does initialization and adds listen port(s) to the server. */
enum status_code p4_server_init(const char* port_details);

/* An API that does  P4 service registration and starts the P4 server.
 * This API also instantiates the BfInterface singletion class for
 * interacting with the southbond interface of the Bfnode C wrapper library. */
enum status_code p4_server_run(void);

/* An API that does the server shutdown and teardown of the P4 service. */
enum status_code p4_server_shutdown(void);

#ifdef  __cplusplus
}
#endif

#endif  // P4SERVER_P4_SERVICE_INTERFACE_H_
