#ifndef __NET_IP_WRAPPER_H
#define __NET_IP_WRAPPER_H 1

#include_next <net/ip.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

extern int		__ip_local_out(struct sk_buff *skb);
extern int		ip_local_out(struct sk_buff *skb);

#endif /* linux kernel < 2.6.25 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,1,0)
static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}
#endif

#endif
