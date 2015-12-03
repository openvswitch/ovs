#ifndef __LINUX_ETHERDEVICE_WRAPPER_H
#define __LINUX_ETHERDEVICE_WRAPPER_H 1

#include <linux/version.h>
#include_next <linux/etherdevice.h>

#ifndef HAVE_ETH_HW_ADDR_RANDOM
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
static inline void eth_hw_addr_random(struct net_device *dev)
{
	random_ether_addr(dev->dev_addr);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,4,0)
static inline void eth_hw_addr_random(struct net_device *dev)
{
	dev_hw_addr_random(dev, dev->dev_addr);
}
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
#define eth_mac_addr rpl_eth_mac_addr
static inline int eth_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;
#ifdef NET_ADDR_RANDOM
	dev->addr_assign_type &= ~NET_ADDR_RANDOM;
#endif
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	return 0;
}
#endif

#ifndef HAVE_ETHER_ADDR_COPY
static inline void ether_addr_copy(u8 *dst, const u8 *src)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	*(u32 *)dst = *(const u32 *)src;
	*(u16 *)(dst + 4) = *(const u16 *)(src + 4);
#else
	u16 *a = (u16 *)dst;
	const u16 *b = (const u16 *)src;

	a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
#endif
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
#define eth_proto_is_802_3 rpl_eth_proto_is_802_3
static inline bool eth_proto_is_802_3(__be16 proto)
{
#ifndef __BIG_ENDIAN
	/* if CPU is little endian mask off bits representing LSB */
	proto &= htons(0xFF00);
#endif
	/* cast both to u16 and compare since LSB can be ignored */
	return (__force u16)proto >= (__force u16)htons(ETH_P_802_3_MIN);
}
#endif

#define ether_addr_equal rpl_ether_addr_equal
static inline bool ether_addr_equal(const u8 *addr1, const u8 *addr2)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	u32 fold = ((*(const u32 *)addr1) ^ (*(const u32 *)addr2)) |
		   ((*(const u16 *)(addr1 + 4)) ^ (*(const u16 *)(addr2 + 4)));

	return fold == 0;
#else
	const u16 *a = (const u16 *)addr1;
	const u16 *b = (const u16 *)addr2;

	return ((a[0] ^ b[0]) | (a[1] ^ b[1]) | (a[2] ^ b[2])) == 0;
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
#define eth_gro_receive rpl_eth_gro_receive
struct sk_buff **rpl_eth_gro_receive(struct sk_buff **head,
				     struct sk_buff *skb);

#define eth_gro_complete rpl_eth_gro_complete
int rpl_eth_gro_complete(struct sk_buff *skb, int nhoff);
#endif

#endif
