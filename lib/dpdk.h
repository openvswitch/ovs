/*
 * Copyright (c) 2016 Nicira, Inc.
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

#ifndef DPDK_H
#define DPDK_H

#include <stdbool.h>

#ifdef DPDK_NETDEV

#include <rte_config.h>
#include <rte_lcore.h>

#define NON_PMD_CORE_ID LCORE_ID_ANY

#else

#define NON_PMD_CORE_ID UINT32_MAX

#endif /* DPDK_NETDEV */

struct smap;
struct ovsrec_open_vswitch;

void dpdk_init(const struct smap *ovs_other_config);
void dpdk_set_lcore_id(unsigned cpu);
const char *dpdk_get_vhost_sock_dir(void);
bool dpdk_vhost_iommu_enabled(void);
void print_dpdk_version(void);
void dpdk_status(const struct ovsrec_open_vswitch *);
#endif /* dpdk.h */
