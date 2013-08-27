#ifndef __LINUX_NETDEVICE_WRAPPER_H
#define __LINUX_NETDEVICE_WRAPPER_H 1

#include_next <linux/netdevice.h>

struct net;

#include <linux/version.h>

#ifndef to_net_dev
#define to_net_dev(class) container_of(class, struct net_device, NETDEV_DEV_MEMBER)
#endif

#ifdef HAVE_RHEL_OVS_HOOK
extern struct sk_buff *(*openvswitch_handle_frame_hook)(struct sk_buff *skb);
extern int nr_bridges;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
extern void unregister_netdevice_queue(struct net_device *dev,
					struct list_head *head);
extern void unregister_netdevice_many(struct list_head *head);
#endif

#ifndef HAVE_DEV_DISABLE_LRO
extern void dev_disable_lro(struct net_device *dev);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36) || \
    defined HAVE_RHEL_OVS_HOOK
static inline int netdev_rx_handler_register(struct net_device *dev,
					     void *rx_handler,
					     void *rx_handler_data)
{
#ifdef HAVE_RHEL_OVS_HOOK
	rcu_assign_pointer(dev->ax25_ptr, rx_handler_data);
	nr_bridges++;
	rcu_assign_pointer(openvswitch_handle_frame_hook, rx_handler);
#else
	if (dev->br_port)
		return -EBUSY;
	rcu_assign_pointer(dev->br_port, rx_handler_data);
#endif
	return 0;
}
static inline void netdev_rx_handler_unregister(struct net_device *dev)
{
#ifdef HAVE_RHEL_OVS_HOOK
	rcu_assign_pointer(dev->ax25_ptr, NULL);

	if (--nr_bridges <= 0)
		rcu_assign_pointer(openvswitch_handle_frame_hook, NULL);
#else
	rcu_assign_pointer(dev->br_port, NULL);
#endif
}
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define skb_gso_segment rpl_skb_gso_segment
struct sk_buff *rpl_skb_gso_segment(struct sk_buff *skb, u32 features);

#define netif_skb_features rpl_netif_skb_features
u32 rpl_netif_skb_features(struct sk_buff *skb);

#define netif_needs_gso rpl_netif_needs_gso
static inline int rpl_netif_needs_gso(struct sk_buff *skb, int features)
{
	return skb_is_gso(skb) && (!skb_gso_ok(skb, features) ||
		unlikely(skb->ip_summed != CHECKSUM_PARTIAL));
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
typedef u32 netdev_features_t;
#endif

#ifndef HAVE___SKB_GSO_SEGMENT
static inline struct sk_buff *__skb_gso_segment(struct sk_buff *skb,
						netdev_features_t features,
						bool tx_path)
{
	return skb_gso_segment(skb, features);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)

/* XEN dom0 networking assumes dev->master is bond device
 * and it tries to access bond private structure from dev->master
 * ptr on receive path. This causes panic. Therefore it is better
 * not to backport this API.
 **/
static inline int netdev_master_upper_dev_link(struct net_device *dev,
					       struct net_device *upper_dev)
{
	return 0;
}

static inline void netdev_upper_dev_unlink(struct net_device *dev,
					   struct net_device *upper_dev)
{
}
#endif

#endif
