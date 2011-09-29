/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008, 2009, 2010, 2011 Nicira Networks.
 *
 * Significant portions of this file may be copied from parts of the Linux
 * kernel, by Linus Torvalds and others.
 */

/* Handle changes to managed devices */

#include <linux/netdevice.h>
#include <net/genetlink.h>

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
		if (!is_internal_dev(dev)) {
			struct sk_buff *reply;

			reply = ovs_vport_cmd_build_info(vport, 0, 0,
							 OVS_VPORT_CMD_DEL);
			dp_detach_port(vport);
			if (IS_ERR(reply)) {
				netlink_set_err(INIT_NET_GENL_SOCK, 0,
						dp_vport_multicast_group.id,
						PTR_ERR(reply));
				break;
			}

			genl_notify(reply, dev_net(dev), 0,
				    dp_vport_multicast_group.id, NULL,
				    GFP_KERNEL);
		}
		break;

	case NETDEV_CHANGENAME:
		if (vport->port_no != OVSP_LOCAL) {
			dp_sysfs_del_if(vport);
			dp_sysfs_add_if(vport);
		}
		break;
	}
	return NOTIFY_DONE;
}

struct notifier_block dp_device_notifier = {
	.notifier_call = dp_device_event
};
