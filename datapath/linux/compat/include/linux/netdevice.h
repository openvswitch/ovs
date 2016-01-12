#ifndef __LINUX_NETDEVICE_WRAPPER_H
#define __LINUX_NETDEVICE_WRAPPER_H 1

#include_next <linux/netdevice.h>
#include <linux/if_bridge.h>

struct net;

#include <linux/version.h>

#ifndef IFF_TX_SKB_SHARING
#define IFF_TX_SKB_SHARING 0
#endif

#ifndef IFF_OVS_DATAPATH
#define IFF_OVS_DATAPATH 0
#else
#define HAVE_OVS_DATAPATH
#endif

#ifndef IFF_LIVE_ADDR_CHANGE
#define IFF_LIVE_ADDR_CHANGE 0
#endif

#ifndef IFF_NO_QUEUE
#define IFF_NO_QUEUE	0
#endif
#ifndef IFF_OPENVSWITCH
#define IFF_OPENVSWITCH 0
#endif

#ifndef to_net_dev
#define to_net_dev(class) container_of(class, struct net_device, NETDEV_DEV_MEMBER)
#endif

#ifndef HAVE_NET_NAME_UNKNOWN
#undef alloc_netdev
#define NET_NAME_UNKNOWN 0
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
        alloc_netdev_mq(sizeof_priv, name, setup, 1)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
#define unregister_netdevice_queue(dev, head)	unregister_netdevice(dev)
#define unregister_netdevice_many(head)
#endif

#ifndef HAVE_DEV_DISABLE_LRO
extern void dev_disable_lro(struct net_device *dev);
#endif

#if !defined HAVE_NETDEV_RX_HANDLER_REGISTER || \
    defined HAVE_RHEL_OVS_HOOK

#ifdef HAVE_RHEL_OVS_HOOK
typedef struct sk_buff *(openvswitch_handle_frame_hook_t)(struct sk_buff *skb);
extern openvswitch_handle_frame_hook_t *openvswitch_handle_frame_hook;

#define netdev_rx_handler_register rpl_netdev_rx_handler_register
int rpl_netdev_rx_handler_register(struct net_device *dev,
				   openvswitch_handle_frame_hook_t *hook,
				   void *rx_handler_data);
#else

#define netdev_rx_handler_register rpl_netdev_rx_handler_register
int rpl_netdev_rx_handler_register(struct net_device *dev,
				   struct sk_buff *(*netdev_hook)(struct net_bridge_port *p,
							   struct sk_buff *skb),
				   void *rx_handler_data);
#endif

#define netdev_rx_handler_unregister rpl_netdev_rx_handler_unregister
void rpl_netdev_rx_handler_unregister(struct net_device *dev);
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
#define OVS_USE_COMPAT_GSO_SEGMENTATION
#endif

#ifdef OVS_USE_COMPAT_GSO_SEGMENTATION
/* define compat version to handle MPLS segmentation offload. */
#define __skb_gso_segment rpl__skb_gso_segment
struct sk_buff *rpl__skb_gso_segment(struct sk_buff *skb,
				    netdev_features_t features,
				    bool tx_path);

#define skb_gso_segment rpl_skb_gso_segment
static inline
struct sk_buff *rpl_skb_gso_segment(struct sk_buff *skb, netdev_features_t features)
{
        return rpl__skb_gso_segment(skb, features, true);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,38)
#define netif_skb_features rpl_netif_skb_features
netdev_features_t rpl_netif_skb_features(struct sk_buff *skb);
#endif

#ifdef HAVE_NETIF_NEEDS_GSO_NETDEV
#define netif_needs_gso rpl_netif_needs_gso
static inline bool netif_needs_gso(struct sk_buff *skb,
				   netdev_features_t features)
{
	return skb_is_gso(skb) && (!skb_gso_ok(skb, features) ||
		unlikely((skb->ip_summed != CHECKSUM_PARTIAL) &&
			 (skb->ip_summed != CHECKSUM_UNNECESSARY)));
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,16,0)
#define dev_queue_xmit rpl_dev_queue_xmit
int rpl_dev_queue_xmit(struct sk_buff *skb);
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

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(8,0)
/* Use compat version for all redhas releases */
#undef netdev_alloc_pcpu_stats
#endif

#ifndef netdev_alloc_pcpu_stats
#define netdev_alloc_pcpu_stats(type)				\
({								\
	typeof(type) __percpu *pcpu_stats = alloc_percpu(type); \
	if (pcpu_stats) {					\
		int ____i;					\
		for_each_possible_cpu(____i) {			\
			typeof(type) *stat;			\
			stat = per_cpu_ptr(pcpu_stats, ____i);	\
			u64_stats_init(&stat->syncp);		\
		}						\
	}							\
	pcpu_stats;						\
})
#endif

#ifndef HAVE_DEV_RECURSION_LEVEL
static inline bool dev_recursion_level(void) { return false; }
#endif

#ifndef NET_NAME_USER
#define NET_NAME_USER 3
#endif

#ifndef HAVE_GRO_REMCSUM
struct gro_remcsum {
};

#define skb_gro_remcsum_init(grc)
#define skb_gro_remcsum_cleanup(a1, a2)
#else
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)

#define skb_gro_remcsum_process rpl_skb_gro_remcsum_process
static inline void *skb_gro_remcsum_process(struct sk_buff *skb, void *ptr,
					    unsigned int off, size_t hdrlen,
					    int start, int offset,
					    struct gro_remcsum *grc,
					    bool nopartial)
{
	__wsum delta;
	size_t plen = hdrlen + max_t(size_t, offset + sizeof(u16), start);

	BUG_ON(!NAPI_GRO_CB(skb)->csum_valid);

	if (!nopartial) {
		NAPI_GRO_CB(skb)->gro_remcsum_start = off + hdrlen + start;
		return ptr;
	}

	ptr = skb_gro_header_fast(skb, off);
	if (skb_gro_header_hard(skb, off + plen)) {
		ptr = skb_gro_header_slow(skb, off + plen, off);
		if (!ptr)
			return NULL;
	}

	delta = remcsum_adjust(ptr + hdrlen, NAPI_GRO_CB(skb)->csum,
			       start, offset);

	/* Adjust skb->csum since we changed the packet */
	NAPI_GRO_CB(skb)->csum = csum_add(NAPI_GRO_CB(skb)->csum, delta);

	grc->offset = off + hdrlen + offset;
	grc->delta = delta;

	return ptr;
}
#endif
#endif

#ifndef HAVE_RTNL_LINK_STATS64
#define dev_get_stats rpl_dev_get_stats
struct rtnl_link_stats64 *rpl_dev_get_stats(struct net_device *dev,
					struct rtnl_link_stats64 *storage);

#else
#define HAVE_DEV_TSTATS
#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)
#undef HAVE_DEV_TSTATS
#endif
#endif

#if RHEL_RELEASE_CODE < RHEL_RELEASE_VERSION(7,0)
/* Only required on RHEL 6. */
#define dev_get_stats dev_get_stats64
#endif

#ifndef netdev_dbg
#define netdev_dbg(__dev, format, args...)			\
do {								\
	printk(KERN_DEBUG "%s ", __dev->name);			\
	printk(KERN_DEBUG format, ##args);			\
} while (0)
#endif

#ifndef netdev_info
#define netdev_info(__dev, format, args...)			\
do {								\
	printk(KERN_INFO "%s ", __dev->name);			\
	printk(KERN_INFO format, ##args);			\
} while (0)

#endif

#endif /* __LINUX_NETDEVICE_WRAPPER_H */
