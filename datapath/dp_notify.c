/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010, 2011 Nicira Networks.
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
	struct datapath *dp;

	if (is_internal_dev(dev))
		vport = internal_dev_get_vport(dev);
	else
		vport = netdev_get_vport(dev);

	if (!vport)
		return NOTIFY_DONE;

	dp = vport->dp;

	switch (event) {
	case NETDEV_UNREGISTER:
		if (!is_internal_dev(dev))
			dp_detach_port(vport);
		break;

	case NETDEV_CHANGENAME:
		if (vport->port_no != ODPP_LOCAL) {
			dp_sysfs_del_if(vport);
			dp_sysfs_add_if(vport);
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
