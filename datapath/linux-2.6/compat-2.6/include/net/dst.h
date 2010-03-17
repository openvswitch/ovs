#ifndef __NET_DST_WRAPPER_H
#define __NET_DST_WRAPPER_H 1

#include_next <net/dst.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->dst)
		dst_release(skb_dst(skb));
	skb->dst = 0UL;
}

#endif /* linux kernel < 2.6.31 */

#endif
