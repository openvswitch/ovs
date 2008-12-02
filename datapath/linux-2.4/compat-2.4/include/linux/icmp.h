#ifndef __LINUX_ICMP_WRAPPER_H
#define __LINUX_ICMP_WRAPPER_H 1

#include_next <linux/icmp.h>

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct icmphdr *icmp_hdr(const struct sk_buff *skb)
{
	return (struct icmphdr *)skb_transport_header(skb);
}
#endif

#endif
