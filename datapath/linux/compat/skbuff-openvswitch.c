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
