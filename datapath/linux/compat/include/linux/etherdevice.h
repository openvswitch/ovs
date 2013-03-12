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

#endif
