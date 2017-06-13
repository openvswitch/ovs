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

#include <config.h>
#include "netdev-tc-offloads.h"
#include <errno.h>
#include <linux/if_ether.h>
#include "openvswitch/hmap.h"
#include "openvswitch/match.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/thread.h"
#include "openvswitch/types.h"
#include "openvswitch/vlog.h"
#include "netdev-provider.h"
#include "netlink.h"
#include "netlink-socket.h"
#include "odp-netlink.h"
#include "unaligned.h"
#include "util.h"
#include "hash.h"
#include "dpif.h"
#include "tc.h"

VLOG_DEFINE_THIS_MODULE(netdev_tc_offloads);

int
netdev_tc_flow_flush(struct netdev *netdev OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_dump_create(struct netdev *netdev,
                           struct netdev_flow_dump **dump_out)
{
    struct netdev_flow_dump *dump = xzalloc(sizeof *dump);

    dump->netdev = netdev_ref(netdev);

    *dump_out = dump;

    return 0;
}

int
netdev_tc_flow_dump_destroy(struct netdev_flow_dump *dump)
{
    netdev_close(dump->netdev);
    free(dump);

    return 0;
}

bool
netdev_tc_flow_dump_next(struct netdev_flow_dump *dump OVS_UNUSED,
                         struct match *match OVS_UNUSED,
                         struct nlattr **actions OVS_UNUSED,
                         struct dpif_flow_stats *stats OVS_UNUSED,
                         ovs_u128 *ufid OVS_UNUSED,
                         struct ofpbuf *rbuffer OVS_UNUSED,
                         struct ofpbuf *wbuffer OVS_UNUSED)
{
    return false;
}

int
netdev_tc_flow_put(struct netdev *netdev OVS_UNUSED,
                   struct match *match OVS_UNUSED,
                   struct nlattr *actions OVS_UNUSED,
                   size_t actions_len OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct offload_info *info OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_get(struct netdev *netdev OVS_UNUSED,
                   struct match *match OVS_UNUSED,
                   struct nlattr **actions OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED,
                   struct ofpbuf *buf OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_flow_del(struct netdev *netdev OVS_UNUSED,
                   const ovs_u128 *ufid OVS_UNUSED,
                   struct dpif_flow_stats *stats OVS_UNUSED)
{
    return EOPNOTSUPP;
}

int
netdev_tc_init_flow_api(struct netdev *netdev OVS_UNUSED)
{
    return 0;
}
