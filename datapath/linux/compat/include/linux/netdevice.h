#ifndef __LINUX_NETDEVICE_WRAPPER_H
#define __LINUX_NETDEVICE_WRAPPER_H 1

#include_next <linux/netdevice.h>
#include <linux/if_bridge.h>

struct net;

#include <linux/version.h>

#ifndef to_net_dev
#define to_net_dev(class) container_of(class, struct net_device, NETDEV_DEV_MEMBER)
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

#ifdef HAVE_RHEL_OVS_HOOK
typedef struct sk_buff *(openvswitch_handle_frame_hook_t)(struct sk_buff *skb);
extern openvswitch_handle_frame_hook_t *openvswitch_handle_frame_hook;

int netdev_rx_handler_register(struct net_device *dev,
			       openvswitch_handle_frame_hook_t *hook,
			       void *rx_handler_data);
#else

int netdev_rx_handler_register(struct net_device *dev,
			       struct sk_buff *(*netdev_hook)(struct net_bridge_port *p,
							     struct sk_buff *skb),
			       void *rx_handler_data);
#endif

void netdev_rx_handler_unregister(struct net_device *dev);
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

#ifndef HAVE_NETDEV_FEATURES_T
typedef u32 netdev_features_t;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define skb_gso_segment rpl_skb_gso_segment
struct sk_buff *rpl_skb_gso_segment(struct sk_buff *skb,
                                    netdev_features_t features);

#define netif_skb_features rpl_netif_skb_features
netdev_features_t rpl_netif_skb_features(struct sk_buff *skb);

#define netif_needs_gso rpl_netif_needs_gso
static inline int rpl_netif_needs_gso(struct sk_buff *skb, int features)
{
	return skb_is_gso(skb) && (!skb_gso_ok(skb, features) ||
		unlikely(skb->ip_summed != CHECKSUM_PARTIAL));
}
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

static inline struct net_device *netdev_master_upper_dev_get(struct net_device *dev)
{
	return NULL;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,37)
#define dev_queue_xmit rpl_dev_queue_xmit
int dev_queue_xmit(struct sk_buff *skb);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0)
static inline struct net_device *netdev_notifier_info_to_dev(void *info)
{
	return info;
}
#endif

#ifndef HAVE_PCPU_SW_NETSTATS

#include <linux/u64_stats_sync.h>

struct pcpu_sw_netstats {
	u64     rx_packets;
	u64     rx_bytes;
	u64     tx_packets;
	u64     tx_bytes;
	struct u64_stats_sync   syncp;
};
#endif

#endif
