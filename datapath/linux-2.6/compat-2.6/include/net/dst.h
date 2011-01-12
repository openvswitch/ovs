#ifndef __NET_DST_WRAPPER_H
#define __NET_DST_WRAPPER_H 1

#include_next <net/dst.h>

#ifndef HAVE_SKB_DST_ACCESSOR_FUNCS

static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->dst)
		dst_release(skb_dst(skb));
	skb->dst = NULL;
}

#endif

#endif
