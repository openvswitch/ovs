#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)

#include <linux/netdevice.h>

void __skb_warn_lro_forwarding(const struct sk_buff *skb)
{
	if (net_ratelimit())
		printk(KERN_WARNING "%s: received packets cannot be forwarded"
				    " while LRO is enabled\n", skb->dev->name);
}

#endif /* kernel < 2.6.27 */
