#ifndef __NET_IP_WRAPPER_H
#define __NET_IP_WRAPPER_H 1

#include_next <net/ip.h>

#include <linux/version.h>

#ifndef HAVE_IP_IS_FRAGMENT
static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}
#endif

#ifndef HAVE_INET_GET_LOCAL_PORT_RANGE_USING_NET
static inline void rpl_inet_get_local_port_range(struct net *net, int *low,
					     int *high)
{
	inet_get_local_port_range(low, high);
}
#define inet_get_local_port_range rpl_inet_get_local_port_range

#endif

/* IPv4 datagram length is stored into 16bit field (tot_len) */
#ifndef IP_MAX_MTU
#define IP_MAX_MTU	0xFFFFU
#endif

#ifndef HAVE_IP_SKB_DST_MTU
static inline bool rpl_ip_sk_use_pmtu(const struct sock *sk)
{
	return inet_sk(sk)->pmtudisc < IP_PMTUDISC_PROBE;
}
#define ip_sk_use_pmtu rpl_ip_sk_use_pmtu

static inline unsigned int ip_dst_mtu_maybe_forward(const struct dst_entry *dst,
						    bool forwarding)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	struct net *net = dev_net(dst->dev);

	if (net->ipv4.sysctl_ip_fwd_use_pmtu ||
	    dst_metric_locked(dst, RTAX_MTU) ||
	    !forwarding)
		return dst_mtu(dst);
#endif

	return min(dst->dev->mtu, IP_MAX_MTU);
}

static inline unsigned int rpl_ip_skb_dst_mtu(const struct sk_buff *skb)
{
	if (!skb->sk || ip_sk_use_pmtu(skb->sk)) {
		bool forwarding = IPCB(skb)->flags & IPSKB_FORWARDED;
		return ip_dst_mtu_maybe_forward(skb_dst(skb), forwarding);
	} else {
		return min(skb_dst(skb)->dev->mtu, IP_MAX_MTU);
	}
}
#define ip_skb_dst_mtu rpl_ip_skb_dst_mtu
#endif /* HAVE_IP_SKB_DST_MTU */

#endif
