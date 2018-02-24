#ifndef __NET_DST_WRAPPER_H
#define __NET_DST_WRAPPER_H 1

#include <linux/version.h>
#include_next <net/dst.h>

#ifndef HAVE_SKB_DST_ACCESSOR_FUNCS

static inline void skb_dst_drop(struct sk_buff *skb)
{
	if (skb->dst)
		dst_release(skb_dst(skb));
	skb->dst = NULL;
}

#endif

#ifndef DST_OBSOLETE_NONE
#define DST_OBSOLETE_NONE	0
#endif

#ifndef DST_NOCOUNT
#define DST_NOCOUNT		0
#endif

#if !defined(HAVE___SKB_DST_COPY)
static inline void __skb_dst_copy(struct sk_buff *nskb, unsigned long refdst)
{
	nskb->_skb_refdst = refdst;
	if (!(nskb->_skb_refdst & SKB_DST_NOREF))
		dst_clone(skb_dst(nskb));
}
#endif

#if  LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
static const u32 rpl_dst_default_metrics[RTAX_MAX + 1] = {
	/* This initializer is needed to force linker to place this variable
	 * into const section. Otherwise it might end into bss section.
	 * We really want to avoid false sharing on this variable, and catch
	 * any writes on it.
	 */
	[RTAX_MAX] = 0xdeadbeef,
};
#define dst_default_metrics rpl_dst_default_metrics

static inline void rpl_dst_init(struct dst_entry *dst, struct dst_ops *ops,
				struct net_device *dev, int initial_ref,
				int initial_obsolete, unsigned short flags)
{
	/* XXX: It's easier to handle compatibility by zeroing, as we can
	 *      refer to fewer fields. Do that here.
	 */
	memset(dst, 0, sizeof *dst);

	dst->dev = dev;
	if (dev)
		dev_hold(dev);
	dst->ops = ops;
	dst_init_metrics(dst, dst_default_metrics, true);
	dst->path = dst;
	dst->input = dst_discard;
#ifndef HAVE_DST_DISCARD_SK
	dst->output = dst_discard;
#else
	dst->output = dst_discard_sk;
#endif
	dst->obsolete = initial_obsolete;
	atomic_set(&dst->__refcnt, initial_ref);
	dst->lastuse = jiffies;
	dst->flags = flags;
	if (!(flags & DST_NOCOUNT))
		dst_entries_add(ops, 1);
}
#define dst_init rpl_dst_init
#endif

#endif
