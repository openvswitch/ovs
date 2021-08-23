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
struct netdev;

#ifdef DPDK_NETDEV

#include <rte_flow.h>

void netdev_dpdk_register(void);
void free_dpdk_buf(struct dp_packet *);

bool netdev_dpdk_flow_api_supported(struct netdev *);

int
netdev_dpdk_rte_flow_destroy(struct netdev *netdev,
                             struct rte_flow *rte_flow,
                             struct rte_flow_error *error);
struct rte_flow *
netdev_dpdk_rte_flow_create(struct netdev *netdev,
                            const struct rte_flow_attr *attr,
                            const struct rte_flow_item *items,
                            const struct rte_flow_action *actions,
                            struct rte_flow_error *error);
int
netdev_dpdk_rte_flow_query_count(struct netdev *netdev,
                                 struct rte_flow *rte_flow,
                                 struct rte_flow_query_count *query,
                                 struct rte_flow_error *error);
int
netdev_dpdk_get_port_id(struct netdev *netdev);

#ifdef ALLOW_EXPERIMENTAL_API

int netdev_dpdk_rte_flow_tunnel_decap_set(struct netdev *,
                                          struct rte_flow_tunnel *,
                                          struct rte_flow_action **,
                                          uint32_t *num_of_actions,
                                          struct rte_flow_error *);
int netdev_dpdk_rte_flow_tunnel_match(struct netdev *,
                                      struct rte_flow_tunnel *,
                                      struct rte_flow_item **,
                                      uint32_t *num_of_items,
                                      struct rte_flow_error *);
int netdev_dpdk_rte_flow_get_restore_info(struct netdev *,
                                          struct dp_packet *,
                                          struct rte_flow_restore_info *,
                                          struct rte_flow_error *);
int netdev_dpdk_rte_flow_tunnel_action_decap_release(struct netdev *,
                                                     struct rte_flow_action *,
                                                     uint32_t num_of_actions,
                                                     struct rte_flow_error *);
int netdev_dpdk_rte_flow_tunnel_item_release(struct netdev *,
                                             struct rte_flow_item *,
                                             uint32_t num_of_items,
                                             struct rte_flow_error *);

#else

static inline void
set_error(struct rte_flow_error *error, enum rte_flow_error_type type)
{
    if (!error) {
        return;
    }
    error->type = type;
    error->cause = NULL;
    error->message = NULL;
}

static inline int
netdev_dpdk_rte_flow_tunnel_decap_set(
    struct netdev *netdev OVS_UNUSED,
    struct rte_flow_tunnel *tunnel OVS_UNUSED,
    struct rte_flow_action **actions OVS_UNUSED,
    uint32_t *num_of_actions OVS_UNUSED,
    struct rte_flow_error *error)
{
    set_error(error, RTE_FLOW_ERROR_TYPE_ACTION);
    return -1;
}

static inline int
netdev_dpdk_rte_flow_tunnel_match(struct netdev *netdev OVS_UNUSED,
                                  struct rte_flow_tunnel *tunnel OVS_UNUSED,
                                  struct rte_flow_item **items OVS_UNUSED,
                                  uint32_t *num_of_items OVS_UNUSED,
                                  struct rte_flow_error *error)
{
    set_error(error, RTE_FLOW_ERROR_TYPE_ITEM);
    return -1;
}

static inline int
netdev_dpdk_rte_flow_get_restore_info(
    struct netdev *netdev OVS_UNUSED,
    struct dp_packet *p OVS_UNUSED,
    struct rte_flow_restore_info *info OVS_UNUSED,
    struct rte_flow_error *error)
{
    set_error(error, RTE_FLOW_ERROR_TYPE_ATTR);
    return -1;
}

static inline int
netdev_dpdk_rte_flow_tunnel_action_decap_release(
    struct netdev *netdev OVS_UNUSED,
    struct rte_flow_action *actions OVS_UNUSED,
    uint32_t num_of_actions OVS_UNUSED,
    struct rte_flow_error *error)
{
    set_error(error, RTE_FLOW_ERROR_TYPE_NONE);
    return 0;
}

static inline int
netdev_dpdk_rte_flow_tunnel_item_release(
    struct netdev *netdev OVS_UNUSED,
    struct rte_flow_item *items OVS_UNUSED,
    uint32_t num_of_items OVS_UNUSED,
    struct rte_flow_error *error)
{
    set_error(error, RTE_FLOW_ERROR_TYPE_NONE);
    return 0;
}

#endif /* ALLOW_EXPERIMENTAL_API */

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
