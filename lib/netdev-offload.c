/*
 * Copyright (c) 2008 - 2014, 2016, 2017 Nicira, Inc.
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

#include <config.h>

#include "netdev-offload.h"
#include "netdev-provider.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(netdev_offload);

/*
 * Get the value of the hw info parameter specified by type.
 * Returns the value on success (>= 0). Returns -1 on failure.
 */
int
netdev_get_hw_info(struct netdev *netdev, int type)
{
    int val = -1;

    switch (type) {
    case HW_INFO_TYPE_OOR:
        val = netdev->hw_info.oor;
        break;
    case HW_INFO_TYPE_PEND_COUNT:
        val = netdev->hw_info.pending_count;
        break;
    case HW_INFO_TYPE_OFFL_COUNT:
        val = netdev->hw_info.offload_count;
        break;
    default:
        break;
    }

    return val;
}

/*
 * Set the value of the hw info parameter specified by type.
 */
void
netdev_set_hw_info(struct netdev *netdev, int type, int val)
{
    switch (type) {
    case HW_INFO_TYPE_OOR:
        if (val == 0) {
            VLOG_DBG("Offload rebalance: netdev: %s is not OOR", netdev->name);
        }
        netdev->hw_info.oor = val;
        break;
    case HW_INFO_TYPE_PEND_COUNT:
        netdev->hw_info.pending_count = val;
        break;
    case HW_INFO_TYPE_OFFL_COUNT:
        netdev->hw_info.offload_count = val;
        break;
    default:
        break;
    }
}
