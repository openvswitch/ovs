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
#include "ofpbuf.h"

#ifdef DPDK_NETDEV

#include <rte_config.h>
#include <rte_eal.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_errno.h>
#include <rte_memzone.h>
#include <rte_memcpy.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_launch.h>
#include <rte_malloc.h>

int dpdk_init(int argc, char **argv);
void netdev_dpdk_register(void);
void free_dpdk_buf(struct ofpbuf *);
int pmd_thread_setaffinity_cpu(int cpu);

#else

static inline int
dpdk_init(int arg1 OVS_UNUSED, char **arg2 OVS_UNUSED)
{
    return 0;
}

static inline void
netdev_dpdk_register(void)
{
    /* Nothing */
}

static inline void
free_dpdk_buf(struct ofpbuf *buf OVS_UNUSED)
{
    /* Nothing */
}

static inline int
pmd_thread_setaffinity_cpu(int cpu OVS_UNUSED)
{
    return 0;
}

#endif /* DPDK_NETDEV */
#endif
