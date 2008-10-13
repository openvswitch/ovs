#ifndef __LINUX_IF_ARP_WRAPPER_H
#define __LINUX_IF_ARP_WRAPPER_H 1

#include_next <linux/if_arp.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct arphdr *arp_hdr(const struct sk_buff *skb)
{
	return (struct arphdr *)skb_network_header(skb);
}
#endif /* __KERNEL__ */

#endif /* linux kernel < 2.6.22 */

#endif
