/*
 * Copyright (c) 2010 Nicira Networks.
 * Distributed under the terms of the GNU GPL version 2.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

#ifndef VPORT_NETDEV_H
#define VPORT_NETDEV_H 1

#include <linux/netdevice.h>

#include "vport.h"

struct vport *netdev_get_vport(struct net_device *dev);

struct netdev_vport {
	struct net_device *dev;
};

static inline struct netdev_vport *
netdev_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}

int netdev_set_mtu(struct vport *, int mtu);
int netdev_set_addr(struct vport *, const unsigned char *addr);
const char *netdev_get_name(const struct vport *);
const unsigned char *netdev_get_addr(const struct vport *);
const char *netdev_get_config(const struct vport *);
struct kobject *netdev_get_kobj(const struct vport *);
int netdev_get_stats(const struct vport *, struct rtnl_link_stats64 *);
unsigned netdev_get_dev_flags(const struct vport *);
int netdev_is_running(const struct vport *);
unsigned char netdev_get_operstate(const struct vport *);
int netdev_get_ifindex(const struct vport *);
int netdev_get_iflink(const struct vport *);
int netdev_get_mtu(const struct vport *);

#endif /* vport_netdev.h */
