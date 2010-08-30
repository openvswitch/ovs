/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

/* Handle changes to managed devices */

#include <linux/netdevice.h>

#include "datapath.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

static int dp_device_event(struct notifier_block *unused, unsigned long event,
		void *ptr)
{
	struct net_device *dev = ptr;
	struct vport *vport;
	struct dp_port *p;
	struct datapath *dp;

	if (is_internal_dev(dev))
		vport = internal_dev_get_vport(dev);
	else
		vport = netdev_get_vport(dev);

	if (!vport)
		return NOTIFY_DONE;

	p = vport_get_dp_port(vport);

	if (!p)
		return NOTIFY_DONE;
	dp = p->dp;

	switch (event) {
	case NETDEV_UNREGISTER:
		mutex_lock(&dp->mutex);
		dp_detach_port(p, 1);
		mutex_unlock(&dp->mutex);
		break;

	case NETDEV_CHANGENAME:
		if (p->port_no != ODPP_LOCAL) {
			mutex_lock(&dp->mutex);
			dp_sysfs_del_if(p);
			dp_sysfs_add_if(p);
			mutex_unlock(&dp->mutex);
		}
		break;

	case NETDEV_CHANGEMTU:
		if (!is_internal_dev(dev))
			set_internal_devs_mtu(dp);
		break;
	}
	return NOTIFY_DONE;
}

struct notifier_block dp_device_notifier = {
	.notifier_call = dp_device_event
};
