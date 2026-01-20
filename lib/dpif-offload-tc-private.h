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

#ifndef DPIF_OFFLOAD_TC_PRIVATE_H
#define DPIF_OFFLOAD_TC_PRIVATE_H

/* Forward declarations of private structures. */
struct dpif_offload;
struct netdev;

/* Per Netdev flow dump structure. */
struct netdev_tc_flow_dump {
    struct nl_dump *nl_dump;
    struct netdev *netdev;
    odp_port_t port;
    bool terse;
};

/* Flow offloading. */
struct tc_offload_info {
    bool recirc_id_shared_with_tc;  /* Indicates whether tc chains will be in
                                     * sync with datapath recirc ids. */

    bool tc_modify_flow; /* Indicates tc modified the flow. */
    bool tc_modify_flow_deleted; /* Indicate the tc modify flow put success
                                  * to delete the original flow. */
};

/* Netdev-specific offload functions.  These should only be used by the
 * associated dpif offload provider. */
int tc_netdev_init(struct netdev *);
int tc_netdev_flow_flush(struct netdev *);
int tc_netdev_flow_dump_create(struct netdev *, struct netdev_tc_flow_dump **,
                               bool terse);
int tc_netdev_flow_dump_destroy(struct netdev_tc_flow_dump *);
bool tc_netdev_flow_dump_next(struct netdev_tc_flow_dump *, struct match *,
                              struct nlattr **actions,
                              struct dpif_flow_stats *,
                              struct dpif_flow_attrs *, ovs_u128 *ufid,
                              struct ofpbuf *rbuffer, struct ofpbuf *wbuffer);
int tc_netdev_flow_put(struct dpif *, struct netdev *, struct match *,
                       struct nlattr *actions, size_t actions_len,
                       const ovs_u128 *ufid, struct tc_offload_info *,
                       struct dpif_flow_stats *);
int tc_netdev_flow_del(const ovs_u128 *ufid, struct dpif_flow_stats *);
int tc_netdev_flow_get(struct netdev *, struct match *,
                       struct nlattr **actions, const ovs_u128 *ufid,
                       struct dpif_flow_stats *, struct dpif_flow_attrs *,
                       struct ofpbuf *);

void tc_meter_init(void);
int tc_meter_set(const struct dpif_offload *, ofproto_meter_id,
                              struct ofputil_meter_config *);
int tc_meter_get(const struct dpif_offload *, ofproto_meter_id,
                              struct ofputil_meter_stats *);
int tc_meter_del(const struct dpif_offload *, ofproto_meter_id,
                              struct ofputil_meter_stats *);
uint64_t tc_flow_count(const struct dpif_offload *);
odp_port_t tc_get_port_id_by_ifindex(const struct dpif_offload *, int ifindex);

#endif /* DPIF_OFFLOAD_TC_PRIVATE_H */
