#ifndef __LINUX_UDP_WRAPPER_H
#define __LINUX_UDP_WRAPPER_H 1

#include_next <linux/udp.h>

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}
#endif

#endif
