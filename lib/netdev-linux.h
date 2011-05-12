/*
 * Copyright (c) 2011 Nicira Networks.
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

/* These functions are Linux specific, so they should be used directly only by
 * Linux-specific code. */

struct netdev_stats;
struct rtnl_link_stats;
struct rtnl_link_stats64;

void netdev_stats_from_rtnl_link_stats(struct netdev_stats *dst,
                                       const struct rtnl_link_stats *src);
void netdev_stats_from_rtnl_link_stats64(struct netdev_stats *dst,
                                         const struct rtnl_link_stats64 *src);
void netdev_stats_to_rtnl_link_stats64(struct rtnl_link_stats64 *dst,
                                       const struct netdev_stats *src);

#endif /* netdev-linux.h */
