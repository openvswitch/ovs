#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

#include <linux/netfilter_ipv4.h>
#include <net/ip.h>

int __ip_local_out(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	ip_send_check(iph);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	return nf_hook(PF_INET, NF_IP_LOCAL_OUT, &skb, NULL, skb->dst->dev,
		       dst_output);
#else
	return nf_hook(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, skb->dst->dev,
		       dst_output);
#endif /* kernel < 2.6.24 */
}

int ip_local_out(struct sk_buff *skb)
{
	int err;

	err = __ip_local_out(skb);
	if (likely(err == 1))
		err = dst_output(skb);

	return err;
}

#endif /* kernel < 2.6.25 */
