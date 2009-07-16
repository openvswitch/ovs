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


static int dp_device_event(struct notifier_block *unused, unsigned long event, 
		void *ptr) 
{
	struct net_device *dev = ptr;
	struct net_bridge_port *p = dev->br_port;
	if (event == NETDEV_UNREGISTER && p) {
		struct datapath *dp = p->dp;
		mutex_lock(&dp->mutex);
		dp_del_port(p);
		mutex_unlock(&dp->mutex);
	}
	return NOTIFY_DONE;
}

struct notifier_block dp_device_notifier = {
	.notifier_call = dp_device_event
};
