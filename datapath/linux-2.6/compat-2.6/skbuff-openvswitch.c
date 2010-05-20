#if !defined(HAVE_SKB_WARN_LRO) && defined(NETIF_F_LRO)

#include <linux/netdevice.h>

void __skb_warn_lro_forwarding(const struct sk_buff *skb)
{
	if (net_ratelimit())
		printk(KERN_WARNING "%s: received packets cannot be forwarded"
				    " while LRO is enabled\n", skb->dev->name);
}

#endif
