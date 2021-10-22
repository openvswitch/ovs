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

#ifndef __SWITCHLINK_H__
#define __SWITCHLINK_H__

#include <stdlib.h>
#define switchlink_malloc(x, c) malloc(x *c)
#define switchlink_free(x) free(x)

#define SWITCHLINK_LOG_ERR 1
#define SWITCHLINK_LOG_WARN 2
#define SWITCHLINK_LOG_INFO 3
#define SWITCHLINK_LOG_DEBUG 4

#define NL_LOG_DEBUG(_x) \
  if (g_log_level >= SWITCHLINK_LOG_DEBUG) printf _x
#define NL_LOG_INFO(_x) \
  if (g_log_level >= SWITCHLINK_LOG_INFO) printf _x
#define NL_LOG_WARN(_x) \
  if (g_log_level >= SWITCHLINK_LOG_WARN) printf _x
#define NL_LOG_ERROR(_x) \
  if (g_log_level >= SWITCHLINK_LOG_ERR) printf _x

typedef uint64_t switchlink_handle_t;
typedef uint8_t switchlink_mac_addr_t[6];
typedef struct switchlink_ip_addr_ {
  uint8_t family;
  uint8_t prefix_len;
  union {
    struct in_addr v4addr;
    struct in6_addr v6addr;
  } ip;
} switchlink_ip_addr_t;

extern uint8_t g_log_level;
extern switchlink_handle_t g_default_vrf_h;
extern switchlink_handle_t g_default_bridge_h;
extern switchlink_handle_t g_default_stp_h;
extern switchlink_handle_t g_cpu_rx_nhop_h;

extern struct nl_sock *switchlink_get_nl_sock();

/* P4-OVS: Define a flag for P4-OVS ?*/
void *switchlink_init(void *);

#define SWITCHLINK_DEFAULT_VRF_ID 1

#endif /* __SWITCHLINK_H__ */
