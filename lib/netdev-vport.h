/*
 * Copyright (c) 2010 Nicira Networks.
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

#include "netdev-provider.h"
#include "packets.h"

int netdev_vport_do_ioctl(int cmd, void *arg);

int netdev_vport_set_etheraddr(struct netdev *,
                               const uint8_t mac[ETH_ADDR_LEN]);
int netdev_vport_get_etheraddr(const struct netdev *,
                               uint8_t mac[ETH_ADDR_LEN]);
int netdev_vport_get_mtu(const struct netdev *, int *mtup);
int netdev_vport_get_carrier(const struct netdev *, bool *carrier);
int netdev_vport_get_stats(const struct netdev *, struct netdev_stats *);
int netdev_vport_set_stats(struct netdev *, const struct netdev_stats *);
int netdev_vport_update_flags(struct netdev *, enum netdev_flags off,
                              enum netdev_flags on,
                              enum netdev_flags *old_flagsp);

int netdev_vport_poll_add(struct netdev *,
                          void (*cb)(struct netdev_notifier *), void *aux,
                          struct netdev_notifier **);
void netdev_vport_poll_remove(struct netdev_notifier *);
void netdev_vport_poll_notify(const struct netdev *);

#endif /* netdev-vport.h */
