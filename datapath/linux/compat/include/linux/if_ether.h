#ifndef __LINUX_IF_ETHER_WRAPPER_H
#define __LINUX_IF_ETHER_WRAPPER_H 1

#include_next <linux/if_ether.h>

#ifndef ETH_MIN_MTU
#define ETH_MIN_MTU	68		/* Min IPv4 MTU per RFC791	*/
#endif

#ifndef ETH_MAX_MTU
#define ETH_MAX_MTU	0xFFFFU		/* 65535, same as IP_MAX_MTU	*/
#endif

#ifndef ETH_P_802_3_MIN
#define ETH_P_802_3_MIN        0x0600
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD    0x88A8          /* 802.1ad Service VLAN         */
#endif

#define inner_eth_hdr rpl_inner_eth_hdr
static inline struct ethhdr *inner_eth_hdr(const struct sk_buff *skb)
{
	return (struct ethhdr *)skb_inner_mac_header(skb);
}
#endif
