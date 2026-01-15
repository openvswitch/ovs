/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016 Nicira, Inc.
 * Copyright (c) 2019 Samsung Electronics Co.,Ltd.
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

#ifndef NETDEV_FLOW_API_PROVIDER_H
#define NETDEV_FLOW_API_PROVIDER_H 1

#include "flow.h"
#include "netdev-offload.h"
#include "openvswitch/netdev.h"
#include "openvswitch/types.h"
#include "packets.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct netdev_flow_api {
    char *type;

    /* Flow dumping interface.
     *
     * This is the back-end for the flow dumping interface described in
     * dpif.h.  Please read the comments there first, because this code
     * closely follows it.
     *
     * On success returns 0 and allocates data, on failure returns
     * positive errno. */
    int (*flow_dump_create)(struct netdev *, struct netdev_flow_dump **dump,
                            bool terse);
    int (*flow_dump_destroy)(struct netdev_flow_dump *);

    /* Returns true if there are more flows to dump.
     * 'rbuffer' is used as a temporary buffer and needs to be pre allocated
     * by the caller.  While there are more flows the same 'rbuffer'
     * should be provided. 'wbuffer' is used to store dumped actions and needs
     * to be pre allocated by the caller. */
    bool (*flow_dump_next)(struct netdev_flow_dump *, struct match *,
                           struct nlattr **actions,
                           struct dpif_flow_stats *stats,
                           struct dpif_flow_attrs *attrs, ovs_u128 *ufid,
                           struct ofpbuf *rbuffer, struct ofpbuf *wbuffer);

    /* Offload the given flow on netdev.
     * To modify a flow, use the same ufid.
     * 'actions' are in netlink format, as with struct dpif_flow_put.
     * 'info' is extra info needed to offload the flow.
     * 'stats' is populated according to the rules set out in the description
     * above 'struct dpif_flow_put'.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*flow_put)(struct netdev *, struct match *, struct nlattr *actions,
                    size_t actions_len, const ovs_u128 *ufid,
                    struct offload_info *info, struct dpif_flow_stats *);

    /* Queries a flow specified by ufid on netdev.
     * Fills output buffer as 'wbuffer' in flow_dump_next, which
     * needs to be be pre allocated.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*flow_get)(struct netdev *, struct match *, struct nlattr **actions,
                    const ovs_u128 *ufid, struct dpif_flow_stats *,
                    struct dpif_flow_attrs *, struct ofpbuf *wbuffer);

    /* Delete a flow specified by ufid from netdev.
     * 'stats' is populated according to the rules set out in the description
     * above 'struct dpif_flow_del'.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*flow_del)(struct netdev *, const ovs_u128 *ufid,
                    struct dpif_flow_stats *);

    /* Get the number of flows offloaded to netdev.
     * 'n_flows' is an array of counters, one per offload thread.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*flow_get_n_flows)(struct netdev *, uint64_t *n_flows);

    /* Recover the packet state (contents and data) for continued processing
     * in software.
     * Return 0 if successful, otherwise returns a positive errno value and
     * takes ownership of a packet if errno != EOPNOTSUPP. */
    int (*hw_miss_packet_recover)(struct netdev *, struct dp_packet *);

    /* Offloads or modifies the offloaded meter in HW with the given 'meter_id'
     * and the configuration in 'config'. On failure, a non-zero error code is
     * returned.
     *
     * The meter id specified through 'config->meter_id' is ignored. */
    int (*meter_set)(ofproto_meter_id meter_id,
                     struct ofputil_meter_config *config);

    /* Queries HW for meter stats with the given 'meter_id'. Store the stats
     * of dropped packets to band 0. On failure, a non-zero error code is
     * returned.
     *
     * Note that the 'stats' structure is already initialized, and only the
     * available statistics should be incremented, not replaced. Those fields
     * are packet_in_count, byte_in_count and band[]->byte_count and
     * band[]->packet_count. */
    int (*meter_get)(ofproto_meter_id meter_id,
                     struct ofputil_meter_stats *stats);

    /* Removes meter 'meter_id' from HW. Store the stats of dropped packets to
     * band 0. On failure, a non-zero error code is returned.
     *
     * 'stats' may be passed in as NULL if no stats are needed, See the above
     * function for additional details on the 'stats' usage. */
    int (*meter_del)(ofproto_meter_id meter_id,
                     struct ofputil_meter_stats *stats);

    /* Initializies the netdev flow api.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*init_flow_api)(struct netdev *);

    /* Uninitializes the netdev flow api. */
    void (*uninit_flow_api)(struct netdev *);
};

int netdev_register_flow_api_provider(const struct netdev_flow_api *);
int netdev_unregister_flow_api_provider(const char *type);
bool netdev_flow_api_equals(const struct netdev *, const struct netdev *);

#ifdef __linux__
extern const struct netdev_flow_api netdev_offload_tc;
#endif

#ifdef DPDK_NETDEV
extern const struct netdev_flow_api netdev_offload_dpdk;
#endif

#ifdef  __cplusplus
}
#endif

#endif /* NETDEV_FLOW_API_PROVIDER_H */
