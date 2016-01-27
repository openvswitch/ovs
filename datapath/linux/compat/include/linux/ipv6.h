#ifndef __LINUX_IPV6_WRAPPER_H
#define __LINUX_IPV6_WRAPPER_H 1

#include_next <linux/ipv6.h>

struct frag_queue;
struct inet_frags;

#ifndef HAVE_SKBUFF_HEADER_HELPERS
static inline struct ipv6hdr *ipv6_hdr(const struct sk_buff *skb)
{
	return (struct ipv6hdr *)skb_network_header(skb);
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,17,0)
void rpl_ip6_expire_frag_queue(struct net *net, struct frag_queue *fq,
			       struct inet_frags *frags);
#define ip6_expire_frag_queue rpl_ip6_expire_frag_queue
#endif

#endif
