#include <linux/if_bridge.h>
#include <linux/netdevice.h>
#include <linux/version.h>

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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36) || \
    defined HAVE_RHEL_OVS_HOOK

static int nr_bridges;

#ifdef HAVE_RHEL_OVS_HOOK
int netdev_rx_handler_register(struct net_device *dev,
			       openvswitch_handle_frame_hook_t *hook,
			       void *rx_handler_data)
{
	nr_bridges++;
	rcu_assign_pointer(dev->ax25_ptr, rx_handler_data);

	if (nr_bridges == 1)
		rcu_assign_pointer(openvswitch_handle_frame_hook, hook);
	return 0;
}
#else

int netdev_rx_handler_register(struct net_device *dev,
			       struct sk_buff *(*hook)(struct net_bridge_port *p,
						       struct sk_buff *skb),
			       void *rx_handler_data)
{
	nr_bridges++;
	if (dev->br_port)
		return -EBUSY;

	rcu_assign_pointer(dev->br_port, rx_handler_data);

	if (nr_bridges == 1)
		br_handle_frame_hook = hook;
	return 0;
}
#endif

void netdev_rx_handler_unregister(struct net_device *dev)
{
	nr_bridges--;
#ifdef HAVE_RHEL_OVS_HOOK
	rcu_assign_pointer(dev->ax25_ptr, NULL);

	if (nr_bridges)
		return;

	rcu_assign_pointer(openvswitch_handle_frame_hook, NULL);
#else
	rcu_assign_pointer(dev->br_port, NULL);

	if (nr_bridges)
		return;

	br_handle_frame_hook = NULL;
#endif
}
#endif
