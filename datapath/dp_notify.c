/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

/* Handle changes to managed devices */

#include <linux/netdevice.h>

#include "datapath.h"
#include "dp_dev.h"

static int dp_device_event(struct notifier_block *unused, unsigned long event, 
		void *ptr) 
{
	struct net_device *dev = ptr;
	struct net_bridge_port *p;
	struct datapath *dp;

	if (is_dp_dev(dev)) {
		struct dp_dev *dp_dev = dp_dev_priv(dev);
		p = dp_dev->dp->ports[dp_dev->port_no];
	} else {
		p = dev->br_port;
	}
	if (!p)
		return NOTIFY_DONE;
	dp = p->dp;

	switch (event) {
	case NETDEV_UNREGISTER:
		mutex_lock(&dp->mutex);
		dp_del_port(p);
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
	}
	return NOTIFY_DONE;
}

struct notifier_block dp_device_notifier = {
	.notifier_call = dp_device_event
};
