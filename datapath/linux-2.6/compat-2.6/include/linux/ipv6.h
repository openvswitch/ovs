#ifndef __LINUX_IPV6_WRAPPER_H
#define __LINUX_IPV6_WRAPPER_H 1

#include_next <linux/ipv6.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_network_header(skb);
}
#endif /* __KERNEL__ */

#endif /* linux kernel < 2.6.22 */

#endif
