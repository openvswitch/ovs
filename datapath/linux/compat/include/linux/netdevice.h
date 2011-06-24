#ifndef __LINUX_NETDEVICE_WRAPPER_H
#define __LINUX_NETDEVICE_WRAPPER_H 1

#include_next <linux/netdevice.h>

struct net;

#include <linux/version.h>
/* Before 2.6.21, struct net_device has a "struct class_device" member named
 * class_dev.  Beginning with 2.6.21, struct net_device instead has a "struct
 * device" member named dev.  Otherwise the usage of these members is pretty
 * much the same. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,21)
#define NETDEV_DEV_MEMBER class_dev
#else
#define NETDEV_DEV_MEMBER dev
#endif

#ifndef to_net_dev
#define to_net_dev(class) container_of(class, struct net_device, NETDEV_DEV_MEMBER)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
static inline
struct net *dev_net(const struct net_device *dev)
{
#ifdef CONFIG_NET_NS
	return dev->nd_net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
	return &init_net;
#else
	return NULL;
#endif
}

static inline
void dev_net_set(struct net_device *dev, const struct net *net)
{
#ifdef CONFIG_NET_NS
	dev->nd_dev = net;
#endif
}
#endif /* linux kernel < 2.6.26 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define NETIF_F_NETNS_LOCAL 0
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define proc_net init_net.proc_net
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
typedef int netdev_tx_t;
#endif

#ifndef for_each_netdev
/* Linux before 2.6.22 didn't have for_each_netdev at all. */
#define for_each_netdev(net, d) for (d = dev_base; d; d = d->next)
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* Linux 2.6.24 added a network namespace pointer to the macro. */
#undef for_each_netdev
#define for_each_netdev(net,d) list_for_each_entry(d, &dev_base_head, dev_list)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define net_xmit_eval(e)       ((e) == NET_XMIT_CN? 0 : (e))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
extern void unregister_netdevice_queue(struct net_device *dev,
					struct list_head *head);
extern void unregister_netdevice_many(struct list_head *head);
#endif

#ifndef HAVE_DEV_DISABLE_LRO
extern void dev_disable_lro(struct net_device *dev);
#endif

/* Linux 2.6.28 introduced dev_get_stats():
 * const struct net_device_stats *dev_get_stats(struct net_device *dev);
 *
 * Linux 2.6.36 changed dev_get_stats() to:
 * struct rtnl_link_stats64 *dev_get_stats(struct net_device *dev,
 *                                         struct rtnl_link_stats64 *storage);
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
#define dev_get_stats(dev, storage) rpl_dev_get_stats(dev, storage)
struct rtnl_link_stats64 *dev_get_stats(struct net_device *dev,
					struct rtnl_link_stats64 *storage);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define skb_checksum_help(skb) skb_checksum_help((skb), 0)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
static inline int netdev_rx_handler_register(struct net_device *dev,
					     void *rx_handler,
					     void *rx_handler_data)
{
	if (dev->br_port)
		return -EBUSY;
	rcu_assign_pointer(dev->br_port, rx_handler_data);
	return 0;
}
static inline void netdev_rx_handler_unregister(struct net_device *dev)
{
	rcu_assign_pointer(dev->br_port, NULL);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#undef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev, ops) \
	( (netdev)->ethtool_ops = (struct ethtool_ops *)(ops) )
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define dev_get_by_name(net, name) dev_get_by_name(name)
#define dev_get_by_index(net, ifindex) dev_get_by_index(ifindex)
#define __dev_get_by_name(net, name) __dev_get_by_name(name)
#define __dev_get_by_index(net, ifindex) __dev_get_by_index(ifindex)
#define dev_get_by_index_rcu(net, ifindex) dev_get_by_index_rcu(ifindex)
#endif

#ifndef HAVE_DEV_GET_BY_INDEX_RCU
static inline struct net_device *dev_get_by_index_rcu(struct net *net, int ifindex)
{
	struct net_device *dev;

	read_lock(&dev_base_lock);
	dev = __dev_get_by_index(net, ifindex);
	read_unlock(&dev_base_lock);

	return dev;
}
#endif

#ifndef NETIF_F_FSO
#define NETIF_F_FSO 0
#endif

#endif
