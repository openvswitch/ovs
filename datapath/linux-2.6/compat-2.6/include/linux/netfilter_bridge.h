#ifndef __LINUX_NETFILTER_BRIDGE_WRAPPER_H
#define __LINUX_NETFILTER_BRIDGE_WRAPPER_H

#include_next <linux/netfilter_bridge.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#include <linux/if_vlan.h>
#include <linux/if_pppox.h>

static inline unsigned int nf_bridge_encap_header_len(const struct sk_buff *skb)
{
	switch (skb->protocol) {
	case __constant_htons(ETH_P_8021Q):
		return VLAN_HLEN;
	default:
		return 0;
	}
}

#endif /* linux version < 2.6.22 */

#endif 
