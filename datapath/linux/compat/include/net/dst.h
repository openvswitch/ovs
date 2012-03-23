#ifndef __NET_DST_WRAPPER_H
#define __NET_DST_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/dst.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0) &&    \
    LINUX_VERSION_CODE > KERNEL_VERSION(3,0,20)

#define dst_get_neighbour_noref dst_get_neighbour

#endif

#ifndef HAVE_SKB_DST_ACCESSOR_FUNCS

static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->dst)
		dst_release(skb_dst(skb));
	skb->dst = NULL;
}

#endif

#endif
