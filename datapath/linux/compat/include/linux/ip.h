#ifndef __LINUX_IP_WRAPPER_H
#define __LINUX_IP_WRAPPER_H 1

#include_next <linux/ip.h>

#ifndef HAVE_SKBUFF_HEADER_HELPERS
#include <linux/skbuff.h>

static inline struct iphdr *ip_hdr(const struct sk_buff *skb)
{
	return (struct iphdr *)skb_network_header(skb);
}

static inline unsigned int ip_hdrlen(const struct sk_buff *skb)
{
	return ip_hdr(skb)->ihl * 4;
}
#endif /* !HAVE_SKBUFF_HEADER_HELPERS */

#endif
