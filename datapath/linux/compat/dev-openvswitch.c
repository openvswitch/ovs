#include <linux/if_bridge.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <net/rtnetlink.h>

#ifndef HAVE_DEV_DISABLE_LRO

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

int rpl_rtnl_delete_link(struct net_device *dev)
{
	const struct rtnl_link_ops *ops;

	ops = dev->rtnl_link_ops;
	if (!ops || !ops->dellink)
		return -EOPNOTSUPP;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
	ops->dellink(dev);
#else
	{
		LIST_HEAD(list_kill);

		ops->dellink(dev, &list_kill);
		unregister_netdevice_many(&list_kill);
	}
#endif
	return 0;
}
