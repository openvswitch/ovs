#ifndef __NET_STT_H
#define __NET_STT_H  1

#include <linux/kconfig.h>
#include <linux/errno.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0) && IS_ENABLED(CONFIG_NETFILTER)
#include <net/ip_tunnels.h>
#define OVS_STT

struct stthdr {
	__u8		version;
	__u8		flags;
	__u8		l4_offset;
	__u8		reserved;
	__be16		mss;
	__be16		vlan_tci;
	__be64		key;
};

/* Padding after the end of the tunnel headers to provide alignment
 * for inner packet IP header after 14 byte Ethernet header.
 */
#define STT_ETH_PAD 2

#define STT_BASE_HLEN   (sizeof(struct stthdr) + STT_ETH_PAD)
#define STT_HEADER_LEN	(sizeof(struct tcphdr) + STT_BASE_HLEN)

static inline struct stthdr *stt_hdr(const struct sk_buff *skb)
{
	return (struct stthdr *)(skb_transport_header(skb) +
				 sizeof(struct tcphdr));
}

struct net_device *ovs_stt_dev_create_fb(struct net *net, const char *name,
				      u8 name_assign_type, u16 dst_port);

netdev_tx_t ovs_stt_xmit(struct sk_buff *skb);

int ovs_stt_init_module(void);

void ovs_stt_cleanup_module(void);
#else
static inline int ovs_stt_init_module(void)
{
	return 0;
}

static inline void ovs_stt_cleanup_module(void)
{}

static inline struct net_device *ovs_stt_dev_create_fb(struct net *net, const char *name,
				      u8 name_assign_type, u16 dst_port)
{
	return ERR_PTR(-EOPNOTSUPP);
}
static inline netdev_tx_t ovs_stt_xmit(struct sk_buff *skb)
{
	BUG();
	return NETDEV_TX_OK;
}
#endif

#define stt_dev_create_fb ovs_stt_dev_create_fb
#define stt_init_module ovs_stt_init_module
#define stt_cleanup_module ovs_stt_cleanup_module

#define stt_fill_metadata_dst ovs_stt_fill_metadata_dst
int ovs_stt_fill_metadata_dst(struct net_device *dev, struct sk_buff *skb);

#endif /*ifdef__NET_STT_H */
