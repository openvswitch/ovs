/*
 * Distributed under the terms of the GNU GPL version 2.
 * Copyright (c) 2007, 2008 The Board of Trustees of The Leland 
 * Stanford Junior University
 */

/* Handle changes to managed devices */

#include <linux/netdevice.h>

#include "datapath.h"


static int dp_device_event(struct notifier_block *unused, unsigned long event, 
		void *ptr) 
{
	struct net_device *dev = ptr;
	struct net_bridge_port *p = dev->br_port;
	unsigned long int flags;
	uint32_t orig_status;


	/* Check if monitored port */
	if (!p)
		return NOTIFY_DONE;

	spin_lock_irqsave(&p->lock, flags);
	orig_status = p->status;

	switch (event) {
		case NETDEV_CHANGE:
			if (netif_carrier_ok(p->dev))
				p->status &= ~OFPPFL_LINK_DOWN;
			else
				p->status |= OFPPFL_LINK_DOWN;
			break;

		case NETDEV_DOWN:
			p->status |= OFPPFL_PORT_DOWN;
			break;

		case NETDEV_UP:
			p->status &= ~OFPPFL_PORT_DOWN;
			break;

		case NETDEV_UNREGISTER:
			/* xxx Make sure this is correct */
			spin_unlock_irqrestore(&p->lock, flags);
			dp_del_switch_port(p);
			return NOTIFY_DONE;
			break;
	}
	spin_unlock_irqrestore(&p->lock, flags);

	if (orig_status != p->status) 
		dp_send_port_status(p, OFPPR_MOD);

	return NOTIFY_DONE;
}

struct notifier_block dp_device_notifier = {
	.notifier_call = dp_device_event
};
