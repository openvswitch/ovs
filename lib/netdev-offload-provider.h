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

    /* Initializies the netdev flow api.
     * Return 0 if successful, otherwise returns a positive errno value. */
    int (*init_flow_api)(struct netdev *);

    /* Uninitializes the netdev flow api. */
    void (*uninit_flow_api)(struct netdev *);
};

int netdev_register_flow_api_provider(const struct netdev_flow_api *);
int netdev_unregister_flow_api_provider(const char *type);

#ifdef __linux__
extern const struct netdev_flow_api netdev_offload_tc;
#endif

#ifdef  __cplusplus
}
#endif

#endif /* NETDEV_FLOW_API_PROVIDER_H */
