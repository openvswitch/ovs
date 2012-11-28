/*
 * Copyright (c) 2007-2011 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#ifndef VPORT_NETDEV_H
#define VPORT_NETDEV_H 1

#include <linux/netdevice.h>
#include <linux/rcupdate.h>

#include "vport.h"

struct vport *ovs_netdev_get_vport(struct net_device *dev);

struct netdev_vport {
	struct rcu_head rcu;

	struct net_device *dev;
};

static inline struct netdev_vport *
netdev_vport_priv(const struct vport *vport)
{
	return vport_priv(vport);
}

int ovs_netdev_set_addr(struct vport *, const unsigned char *addr);
const char *ovs_netdev_get_name(const struct vport *);
const unsigned char *ovs_netdev_get_addr(const struct vport *);
const char *ovs_netdev_get_config(const struct vport *);
struct kobject *ovs_netdev_get_kobj(const struct vport *);
unsigned ovs_netdev_get_dev_flags(const struct vport *);
int ovs_netdev_is_running(const struct vport *);
unsigned char ovs_netdev_get_operstate(const struct vport *);
int ovs_netdev_get_ifindex(const struct vport *);
int ovs_netdev_get_mtu(const struct vport *);

#endif /* vport_netdev.h */
