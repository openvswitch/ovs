#ifndef __LINUX_IF_ARP_WRAPPER_H
#define __LINUX_IF_ARP_WRAPPER_H 1

#include_next <linux/if_arp.h>

#ifndef HAVE_SKBUFF_HEADER_HELPERS
#include <linux/skbuff.h>

static inline struct arphdr *arp_hdr(const struct sk_buff *skb)
{
	return (struct arphdr *)skb_network_header(skb);
}
#endif /* !HAVE_SKBUFF_HEADER_HELPERS */

#endif
