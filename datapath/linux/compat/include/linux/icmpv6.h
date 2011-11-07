#ifndef __LINUX_ICMPV6_WRAPPER_H
#define __LINUX_ICMPV6_WRAPPER_H 1

#include_next <linux/icmpv6.h>

#ifndef HAVE_ICMP6_HDR
static inline struct icmp6hdr *icmp6_hdr(const struct sk_buff *skb)
{
	return (struct icmp6hdr *)skb_transport_header(skb);
}
#endif

#endif
