/*
 * Copyright (c) 2009 Nicira Networks.
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

#ifndef NETDEV_LINUX_H
#define NETDEV_LINUX_H 1

/* These functions are specific to the Linux implementation of dpif and netdev.
 * They should only be used directly by Linux-specific code. */

#include "list.h"

struct linux_netdev_change {
    /* Copied from struct nlmsghdr. */
    int nlmsg_type;             /* e.g. RTM_NEWLINK, RTM_DELLINK. */

    /* Copied from struct ifinfomsg. */
    int ifi_index;              /* Index of network device. */

    /* Extracted from Netlink attributes. */
    const char *ifname;         /* Name of network device. */
    int master_ifindex;         /* Ifindex of datapath master (0 if none). */
};

typedef void linux_netdev_notify_func(const struct linux_netdev_change *,
                                      void *aux);

struct linux_netdev_notifier {
    struct list node;
    int error;
    linux_netdev_notify_func *cb;
    void *aux;
};

int linux_netdev_notifier_register(struct linux_netdev_notifier *,
                                   linux_netdev_notify_func *, void *aux);
void linux_netdev_notifier_unregister(struct linux_netdev_notifier *);
int linux_netdev_notifier_get_error(struct linux_netdev_notifier *);
int linux_netdev_notifier_peek_error(const struct linux_netdev_notifier *);
void linux_netdev_notifier_run(void);
void linux_netdev_notifier_wait(void);

#endif /* netdev-linux.h */
