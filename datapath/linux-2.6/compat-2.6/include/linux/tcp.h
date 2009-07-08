#ifndef __LINUX_TCP_WRAPPER_H
#define __LINUX_TCP_WRAPPER_H 1

#include_next <linux/tcp.h>

#ifndef HAVE_SKBUFF_HEADER_HELPERS
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}

static inline unsigned int tcp_hdrlen(const struct sk_buff *skb)
{
        return tcp_hdr(skb)->doff * 4;
}
#endif /* !HAVE_SKBUFF_HEADER_HELPERS */

#endif
