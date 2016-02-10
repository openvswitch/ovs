#ifndef __NET_IP6_ROUTE_WRAPPER
#define __NET_IP6_ROUTE_WRAPPER

#include <net/route.h>
#include <net/ip.h>                /* For OVS_VPORT_OUTPUT_PARAMS */
#include <net/ipv6.h>

#include_next<net/ip6_route.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)

static inline
struct dst_entry *rpl_ip6_route_output(struct net *net, const struct sock *sk,
				   struct flowi6 *fl6)
{
	struct flowi fl;

	memset(&fl, 0, sizeof(fl));
	fl.oif = fl6->flowi6_oif;
	fl.fl6_dst = fl6->daddr;
	fl.fl6_src = fl6->saddr;
	fl.mark = fl6->flowi6_mark;
	fl.proto = fl6->flowi6_proto;

	return ip6_route_output(net, (struct sock *) sk, &fl);
}
#define ip6_route_output rpl_ip6_route_output

#define ip6_dst_hoplimit(dst) dst_metric(dst, RTAX_HOPLIMIT)

#endif /* 2.6.39 */

#ifndef HAVE_NF_IPV6_OPS_FRAGMENT
#ifdef OVS_FRAGMENT_BACKPORT
int rpl_ip6_fragment(struct sock *sk, struct sk_buff *skb,
		     int (*output)(OVS_VPORT_OUTPUT_PARAMS));
#else
static inline int rpl_ip6_fragment(struct sock *sk, struct sk_buff *skb,
				   int (*output)(struct sk_buff *))
{
	kfree_skb(skb);
	return -ENOTSUPP;
}
#endif /* OVS_FRAGMENT_BACKPORT */
#define ip6_fragment rpl_ip6_fragment
#endif /* HAVE_NF_IPV6_OPS_FRAGMENT */

#endif /* _NET_IP6_ROUTE_WRAPPER */
