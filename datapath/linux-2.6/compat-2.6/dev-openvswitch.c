#ifndef HAVE_DEV_DISABLE_LRO

#include <linux/netdevice.h>

#ifdef NETIF_F_LRO
#include <linux/ethtool.h>

/**
 *	dev_disable_lro - disable Large Receive Offload on a device
 *	@dev: device
 *
 *	Disable Large Receive Offload (LRO) on a net device.  Must be
 *	called under RTNL.  This is needed if received packets may be
 *	forwarded to another interface.
 */
void dev_disable_lro(struct net_device *dev)
{
	if (dev->ethtool_ops && dev->ethtool_ops->get_flags &&
	    dev->ethtool_ops->set_flags) {
		u32 flags = dev->ethtool_ops->get_flags(dev);
		if (flags & ETH_FLAG_LRO) {
			flags &= ~ETH_FLAG_LRO;
			dev->ethtool_ops->set_flags(dev, flags);
		}
	}
	WARN_ON(dev->features & NETIF_F_LRO);
}
#else
void dev_disable_lro(struct net_device *dev) { }
#endif /* NETIF_F_LRO */

#endif /* HAVE_DEV_DISABLE_LRO */
