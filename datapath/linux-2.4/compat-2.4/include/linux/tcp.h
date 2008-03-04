#ifndef __LINUX_TCP_WRAPPER_H
#define __LINUX_TCP_WRAPPER_H 1

#include_next <linux/tcp.h>

#ifdef __KERNEL__
#include <linux/skbuff.h>

static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
	return tcp_hdr(skb)->doff * 4;
}

static inline unsigned int tcp_optlen(const struct sk_buff *skb)
{
	return (tcp_hdr(skb)->doff - 5) * 4;
}
#endif

#endif
