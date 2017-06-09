#ifndef __NET_IP_WRAPPER_H
#define __NET_IP_WRAPPER_H 1

#include_next <net/ip.h>

#include <net/route.h>
#include <linux/version.h>

#ifndef HAVE_INET_GET_LOCAL_PORT_RANGE_USING_NET
static inline void rpl_inet_get_local_port_range(struct net *net, int *low,
					     int *high)
{
	inet_get_local_port_range(low, high);
}
#define inet_get_local_port_range rpl_inet_get_local_port_range

#endif

#ifndef IPSKB_FRAG_PMTU
#define IPSKB_FRAG_PMTU                BIT(6)
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

#ifdef HAVE_IP_FRAGMENT_TAKES_SOCK
#ifdef HAVE_IP_LOCAL_OUT_TAKES_NET
#define OVS_VPORT_OUTPUT_PARAMS struct net *net, struct sock *sock, struct sk_buff *skb
#else
#define OVS_VPORT_OUTPUT_PARAMS struct sock *sock, struct sk_buff *skb
#endif
#else
#define OVS_VPORT_OUTPUT_PARAMS struct sk_buff *skb
#endif

/* Prior to upstream commit d6b915e29f4a ("ip_fragment: don't forward
 * defragmented DF packet"), IPCB(skb)->frag_max_size was not always populated
 * correctly, which would lead to reassembled packets not being refragmented.
 * So, we backport all of ip_defrag() in these cases.
 */
#ifndef HAVE_CORRECT_MRU_HANDLING

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
static inline bool ip_defrag_user_in_between(u32 user,
					     enum ip_defrag_users lower_bond,
					     enum ip_defrag_users upper_bond)
{
	return user >= lower_bond && user <= upper_bond;
}
#endif /* < v4.2 */

int rpl_ip_do_fragment(struct net *net, struct sock *sk, struct sk_buff *skb,
		       int (*output)(OVS_VPORT_OUTPUT_PARAMS));
#define ip_do_fragment rpl_ip_do_fragment

/* If backporting IP defrag, then init/exit functions need to be called from
 * compat_{in,ex}it() to prepare the backported fragmentation cache. In this
 * case we declare the functions which are defined in
 * datapath/linux/compat/ip_fragment.c. */
int rpl_ip_defrag(struct net *net, struct sk_buff *skb, u32 user);
#define ip_defrag rpl_ip_defrag
int __init rpl_ipfrag_init(void);
void rpl_ipfrag_fini(void);
void ovs_netns_frags_init(struct net *net);
void ovs_netns_frags_exit(struct net *net);

#else /* HAVE_CORRECT_MRU_HANDLING */

#ifndef HAVE_IP_DO_FRAGMENT_TAKES_NET
static inline int rpl_ip_do_fragment(struct net *net, struct sock *sk,
				     struct sk_buff *skb,
				     int (*output)(OVS_VPORT_OUTPUT_PARAMS))
{
	return ip_do_fragment(sk, skb, output);
}
#define ip_do_fragment rpl_ip_do_fragment
#endif /* IP_DO_FRAGMENT_TAKES_NET */

/* We have no good way to detect the presence of upstream commit 8282f27449bf
 * ("inet: frag: Always orphan skbs inside ip_defrag()"), but it should be
 * always included in kernels 4.5+. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,5,0)
static inline int rpl_ip_defrag(struct net *net, struct sk_buff *skb, u32 user)
{
	skb_orphan(skb);
#ifndef HAVE_IP_DEFRAG_TAKES_NET
	return ip_defrag(skb, user);
#else
	return ip_defrag(net, skb, user);
#endif
}
#define ip_defrag rpl_ip_defrag
#endif

/* If we can use upstream defrag then we can rely on the upstream
 * defrag module to init/exit correctly. In this case the calls in
 * compat_{in,ex}it() can be no-ops. */
static inline int rpl_ipfrag_init(void) { return 0; }
static inline void rpl_ipfrag_fini(void) { }
static inline void ovs_netns_frags_init(struct net *net) { }
static inline void ovs_netns_frags_exit(struct net *net) { }
#endif /* HAVE_CORRECT_MRU_HANDLING */

#define ipfrag_init rpl_ipfrag_init
#define ipfrag_fini rpl_ipfrag_fini

#endif
