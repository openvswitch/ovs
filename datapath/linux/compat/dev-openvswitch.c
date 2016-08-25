#include <linux/if_bridge.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include <net/rtnetlink.h>

#include "gso.h"
#include "vport.h"
#include "vport-internal_dev.h"
#include "vport-netdev.h"

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
	LIST_HEAD(list_kill);

	ops = dev->rtnl_link_ops;
	if (!ops || !ops->dellink)
		return -EOPNOTSUPP;

	ops->dellink(dev, &list_kill);
	unregister_netdevice_many(&list_kill);

	return 0;
}
EXPORT_SYMBOL_GPL(rpl_rtnl_delete_link);

#ifndef USE_UPSTREAM_TUNNEL
int ovs_dev_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb)
{
	struct ip_tunnel_info *info;
	struct vport *vport;

	if (!SKB_SETUP_FILL_METADATA_DST(skb))
		return -ENOMEM;

	vport = ovs_netdev_get_vport(dev);
	if (!vport)
		return -EINVAL;

	if (!vport->ops->fill_metadata_dst)
		return -EINVAL;

	info = skb_tunnel_info(skb);
	if (!info)
		return -ENOMEM;
	if (unlikely(!(info->mode & IP_TUNNEL_INFO_TX)))
		return -EINVAL;

	return vport->ops->fill_metadata_dst(dev, skb);
}
EXPORT_SYMBOL_GPL(ovs_dev_fill_metadata_dst);
#endif
