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

static struct vlog_rate_limit error_rl = VLOG_RATE_LIMIT_INIT(60, 5);

static struct hmap ufid_tc = HMAP_INITIALIZER(&ufid_tc);
static struct ovs_mutex ufid_lock = OVS_MUTEX_INITIALIZER;

/**
 * struct ufid_tc_data - data entry for ufid_tc hmap.
 * @ufid_node: Element in @ufid_tc hash table by ufid key.
 * @tc_node: Element in @ufid_tc hash table by prio/handle/ifindex key.
 * @ufid: ufid assigned to the flow
 * @prio: tc priority
 * @handle: tc handle
 * @ifindex: netdev ifindex.
 * @netdev: netdev associated with the tc rule
 */
struct ufid_tc_data {
    struct hmap_node ufid_node;
    struct hmap_node tc_node;
    ovs_u128 ufid;
    uint16_t prio;
    uint32_t handle;
    int ifindex;
    struct netdev *netdev;
};

/* Remove matching ufid entry from ufid_tc hashmap. */
static void
del_ufid_tc_mapping(const ovs_u128 *ufid)
{
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_tc_data *data;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, ufid_node, ufid_hash, &ufid_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            break;
        }
    }

    if (!data) {
        ovs_mutex_unlock(&ufid_lock);
        return;
    }

    hmap_remove(&ufid_tc, &data->ufid_node);
    hmap_remove(&ufid_tc, &data->tc_node);
    netdev_close(data->netdev);
    free(data);
    ovs_mutex_unlock(&ufid_lock);
}

/* Add ufid entry to ufid_tc hashmap.
 * If entry exists already it will be replaced. */
static void OVS_UNUSED
add_ufid_tc_mapping(const ovs_u128 *ufid, int prio, int handle,
                    struct netdev *netdev, int ifindex)
{
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    size_t tc_hash = hash_int(hash_int(prio, handle), ifindex);
    struct ufid_tc_data *new_data = xzalloc(sizeof *new_data);

    del_ufid_tc_mapping(ufid);

    new_data->ufid = *ufid;
    new_data->prio = prio;
    new_data->handle = handle;
    new_data->netdev = netdev_ref(netdev);
    new_data->ifindex = ifindex;

    ovs_mutex_lock(&ufid_lock);
    hmap_insert(&ufid_tc, &new_data->ufid_node, ufid_hash);
    hmap_insert(&ufid_tc, &new_data->tc_node, tc_hash);
    ovs_mutex_unlock(&ufid_lock);
}

/* Get ufid from ufid_tc hashmap.
 *
 * If netdev output param is not NULL then the function will return
 * associated netdev on success and a refcount is taken on that netdev.
 * The caller is then responsible to close the netdev.
 *
 * Returns handle if successful and fill prio and netdev for that ufid.
 * Otherwise returns 0.
 */
static int OVS_UNUSED
get_ufid_tc_mapping(const ovs_u128 *ufid, int *prio, struct netdev **netdev)
{
    size_t ufid_hash = hash_bytes(ufid, sizeof *ufid, 0);
    struct ufid_tc_data *data;
    int handle = 0;

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, ufid_node, ufid_hash, &ufid_tc) {
        if (ovs_u128_equals(*ufid, data->ufid)) {
            if (prio) {
                *prio = data->prio;
            }
            if (netdev) {
                *netdev = netdev_ref(data->netdev);
            }
            handle = data->handle;
            break;
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    return handle;
}

/* Find ufid entry in ufid_tc hashmap using prio, handle and netdev.
 * The result is saved in ufid.
 *
 * Returns true on success.
 */
static bool OVS_UNUSED
find_ufid(int prio, int handle, struct netdev *netdev, ovs_u128 *ufid)
{
    int ifindex = netdev_get_ifindex(netdev);
    struct ufid_tc_data *data;
    size_t tc_hash = hash_int(hash_int(prio, handle), ifindex);

    ovs_mutex_lock(&ufid_lock);
    HMAP_FOR_EACH_WITH_HASH(data, tc_node, tc_hash,  &ufid_tc) {
        if (data->prio == prio && data->handle == handle
            && data->ifindex == ifindex) {
            *ufid = data->ufid;
            break;
        }
    }
    ovs_mutex_unlock(&ufid_lock);

    return (data != NULL);
}

int
netdev_tc_flow_flush(struct netdev *netdev)
{
    int ifindex = netdev_get_ifindex(netdev);

    if (ifindex < 0) {
        VLOG_ERR_RL(&error_rl, "failed to get ifindex for %s: %s",
                    netdev_get_name(netdev), ovs_strerror(-ifindex));
        return -ifindex;
    }

    return tc_flush(ifindex);
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
