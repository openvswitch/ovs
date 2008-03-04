#ifndef __LINUX_TCP_WRAPPER_H
#define __LINUX_TCP_WRAPPER_H 1

#include_next <linux/tcp.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)

#ifdef __KERNEL__
static inline struct tcphdr *tcp_hdr(const struct sk_buff *skb)
{
	return (struct tcphdr *)skb_transport_header(skb);
}
#endif /* __KERNEL__ */

#endif /* linux kernel < 2.6.22 */

#endif
