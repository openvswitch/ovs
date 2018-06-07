/*
 * Copyright (c) 2016 Mellanox Technologies, Ltd.
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

#ifndef NETDEV_TC_OFFLOADS_H
#define NETDEV_TC_OFFLOADS_H 1

#include "netdev-provider.h"

int netdev_tc_flow_flush(struct netdev *);
int netdev_tc_flow_dump_create(struct netdev *, struct netdev_flow_dump **);
int netdev_tc_flow_dump_destroy(struct netdev_flow_dump *);
bool netdev_tc_flow_dump_next(struct netdev_flow_dump *, struct match *,
                              struct nlattr **actions,
                              struct dpif_flow_stats *,
                              struct dpif_flow_attrs *,
                              ovs_u128 *ufid,
                              struct ofpbuf *rbuffer,
                              struct ofpbuf *wbuffer);
int netdev_tc_flow_put(struct netdev *, struct match *,
                       struct nlattr *actions, size_t actions_len,
                       const ovs_u128 *, struct offload_info *,
                       struct dpif_flow_stats *);
int netdev_tc_flow_get(struct netdev *, struct match *,
                       struct nlattr **actions, const ovs_u128 *,
                       struct dpif_flow_stats *,
                       struct dpif_flow_attrs *, struct ofpbuf *);
int netdev_tc_flow_del(struct netdev *, const ovs_u128 *,
                        struct dpif_flow_stats *);
int netdev_tc_init_flow_api(struct netdev *);

#endif /* netdev-tc-offloads.h */
