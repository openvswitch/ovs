#ifndef __LINUX_IF_ETHER_WRAPPER_H
#define __LINUX_IF_ETHER_WRAPPER_H 1

#include_next <linux/if_ether.h>

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct ethhdr *eth_hdr(const struct sk_buff *skb)
{
	return (struct ethhdr *)skb_mac_header(skb);
}
#endif

#endif
