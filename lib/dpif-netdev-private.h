/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2015 Nicira, Inc.
 * Copyright (c) 2019 Intel Corporation.
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

#ifndef DPIF_NETDEV_PRIVATE_H
#define DPIF_NETDEV_PRIVATE_H 1

/* This header includes the various dpif-netdev components' header
 * files in the appropriate order. Unfortunately there is a strict
 * requirement in the include order due to dependences between components.
 * E.g:
 *  DFC/EMC/SMC requires the netdev_flow_key struct
 *  PMD thread requires DFC_flow struct
 *
 */
#include "dpif-netdev-private-flow.h"
#include "dpif-netdev-private-dpcls.h"
#include "dpif-netdev-private-dfc.h"
#include "dpif-netdev-private-thread.h"

/* Allow other implementations to lookup the DPCLS instances. */
struct dpcls *
dp_netdev_pmd_lookup_dpcls(struct dp_netdev_pmd_thread *pmd,
                           odp_port_t in_port);

/* Allow other implementations to execute actions on a batch. */
void
dp_netdev_batch_execute(struct dp_netdev_pmd_thread *pmd,
                        struct dp_packet_batch *packets,
                        struct dpcls_rule *rule,
                        uint32_t bytes,
                        uint16_t tcp_flags);

int
dp_netdev_hw_flow(const struct dp_netdev_pmd_thread *pmd,
                  struct dp_packet *packet,
                  struct dp_netdev_flow **flow);

#endif /* dpif-netdev-private.h */
