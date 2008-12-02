#ifndef __LINUX_ICMP_WRAPPER_H
#define __LINUX_ICMP_WRAPPER_H 1

#include_next <linux/icmp.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#ifdef __KERNEL__
static inline struct icmphdr *icmp_hdr(const struct sk_buff *skb)
{
        return (struct icmphdr *)skb_transport_header(skb);
}
#endif /* __KERNEL__ */

#endif /* linux kernel < 2.6.22 */

#endif
