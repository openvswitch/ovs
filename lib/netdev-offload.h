/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef NETDEV_OFFLOAD_H
#define NETDEV_OFFLOAD_H 1

#include "openvswitch/netdev.h"
#include "ovs-atomic.h"
#include "ovs-rcu.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* Offload-capable (HW) netdev information */
struct netdev_hw_info {
    bool oor;                         /* Out of Offload Resources ? */
    /* Is hw_post_process() supported. */
    atomic_bool post_process_api_supported;
    int offload_count;                /* Offloaded flow count */
    int pending_count;                /* Pending (non-offloaded) flow count */
    OVSRCU_TYPE(void *) offload_data; /* Offload metadata. */
};

enum hw_info_type {
    HW_INFO_TYPE_OOR = 1,		/* OOR state */
    HW_INFO_TYPE_PEND_COUNT = 2,	/* Pending(non-offloaded) flow count */
    HW_INFO_TYPE_OFFL_COUNT = 3		/* Offloaded flow count */
};

int netdev_get_hw_info(struct netdev *, int);
void netdev_set_hw_info(struct netdev *, int, int);

#ifdef  __cplusplus
}
#endif

#endif /* netdev-offload.h */
