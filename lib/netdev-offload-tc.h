/*
 * Copyright (c) 2025 Red Hat, Inc.
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

#ifndef NETDEV_OFFLOAD_TC_H
#define NETDEV_OFFLOAD_TC_H

/* Forward declarations of private structures. */
struct dpif_offload;
struct netdev;

/* Netdev-specific offload functions.  These should only be used by the
 * associated dpif offload provider. */
int netdev_offload_tc_flow_flush(struct netdev *);
void dpif_offload_tc_meter_init(void);
int dpif_offload_tc_meter_set(const struct dpif_offload *, ofproto_meter_id,
                              struct ofputil_meter_config *);
int dpif_offload_tc_meter_get(const struct dpif_offload *, ofproto_meter_id,
                              struct ofputil_meter_stats *);
int dpif_offload_tc_meter_del(const struct dpif_offload *, ofproto_meter_id,
                              struct ofputil_meter_stats *);
uint64_t dpif_offload_tc_flow_count(const struct dpif_offload *);

#endif /* NETDEV_OFFLOAD_TC_H */
