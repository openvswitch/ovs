#ifndef __LINUX_ICMP_WRAPPER_H
#define __LINUX_ICMP_WRAPPER_H 1

#include_next <linux/icmp.h>

#ifndef HAVE_SKBUFF_HEADER_HELPERS
static inline struct icmphdr *icmp_hdr(const struct sk_buff *skb)
{
        return (struct icmphdr *)skb_transport_header(skb);
}
#endif

#endif
