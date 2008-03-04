#ifndef __LINUX_IPV6_WRAPPER_H
#define __LINUX_IPV6_WRAPPER_H 1

#include_next <linux/ipv6.h>

static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_network_header(skb);
}

#endif
