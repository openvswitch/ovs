/*
 * Copyright (c) 2011, 2013 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NETDEV_LINUX_H
#define NETDEV_LINUX_H 1

#include <stdint.h>
#include <stdbool.h>

/* These functions are Linux specific, so they should be used directly only by
 * Linux-specific code. */

struct netdev;

int netdev_linux_ethtool_set_flag(struct netdev *netdev, uint32_t flag,
                                  const char *flag_name, bool enable);
int linux_get_ifindex(const char *netdev_name);

#define LINUX_FLOW_OFFLOAD_API                                  \
            netdev_tc_flow_flush,                               \
            netdev_tc_flow_dump_create,                         \
            netdev_tc_flow_dump_destroy,                        \
            netdev_tc_flow_dump_next,                           \
            netdev_tc_flow_put,                                 \
            netdev_tc_flow_get,                                 \
            netdev_tc_flow_del,                                 \
            netdev_tc_init_flow_api

#endif /* netdev-linux.h */
