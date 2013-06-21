#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>

#if !defined(HAVE_SKB_WARN_LRO) && defined(NETIF_F_LRO)

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

void __skb_warn_lro_forwarding(const struct sk_buff *skb)
{
	if (net_ratelimit())
		pr_warn("%s: received packets cannot be forwarded while LRO is enabled\n",
			skb->dev->name);
}

#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
int skb_checksum_help(struct sk_buff *skb, int inward)
#else
int skb_checksum_help(struct sk_buff *skb)
#endif
{
	if (unlikely(skb_is_nonlinear(skb))) {
		int err;

		err = __skb_linearize(skb);
		if (unlikely(err))
			return err;
	}

#undef skb_checksum_help
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
	return skb_checksum_help(skb, 0);
#else
	return skb_checksum_help(skb);
#endif
}
