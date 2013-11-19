/*
 * Copyright (c) 2010, 2011, 2013 Nicira, Inc.
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

#ifndef NETDEV_VPORT_H
#define NETDEV_VPORT_H 1

#include <stdbool.h>
#include <stddef.h>

struct dpif_linux_vport;
struct dpif_flow_stats;
struct netdev;
struct netdev_class;
struct netdev_stats;

void netdev_vport_tunnel_register(void);
void netdev_vport_patch_register(void);

bool netdev_vport_is_patch(const struct netdev *);
bool netdev_vport_is_layer3(const struct netdev *);

char *netdev_vport_patch_peer(const struct netdev *netdev);

void netdev_vport_inc_rx(const struct netdev *,
                         const struct dpif_flow_stats *);
void netdev_vport_inc_tx(const struct netdev *,
                         const struct dpif_flow_stats *);

const char *netdev_vport_class_get_dpif_port(const struct netdev_class *);

enum { NETDEV_VPORT_NAME_BUFSIZE = 16 };
const char *netdev_vport_get_dpif_port(const struct netdev *,
                                       char namebuf[], size_t bufsize);
char *netdev_vport_get_dpif_port_strdup(const struct netdev *);

#endif /* netdev-vport.h */
