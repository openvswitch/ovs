#ifndef __LINUX_UDP_WRAPPER_H
#define __LINUX_UDP_WRAPPER_H 1

#include_next <linux/udp.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#ifdef __KERNEL__
static inline struct udphdr *udp_hdr(const struct sk_buff *skb)
{
	return (struct udphdr *)skb_transport_header(skb);
}
#endif /* __KERNEL__ */


#endif /* linux kernel < 2.6.22 */

#endif
