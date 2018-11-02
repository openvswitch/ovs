/*
 * Copyright (c) 2014, 2015, 2016 Nicira, Inc.
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

#ifndef NETDEV_DPDK_H
#define NETDEV_DPDK_H

#include <config.h>

#include "openvswitch/compiler.h"

struct dp_packet;

#ifdef DPDK_NETDEV

void netdev_dpdk_register(void);
void free_dpdk_buf(struct dp_packet *);

#else

static inline void
netdev_dpdk_register(void)
{
    /* Nothing */
}
static inline void
free_dpdk_buf(struct dp_packet *buf OVS_UNUSED)
{
    /* Nothing */
}

#endif

#endif /* netdev-dpdk.h */
