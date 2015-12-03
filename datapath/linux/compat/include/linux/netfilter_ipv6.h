#ifndef __NETFILTER_IPV6_WRAPPER_H
#define __NETFILTER_IPV6_WRAPPER_H 1

#include_next <linux/netfilter_ipv6.h>

#include <linux/version.h>
#include <net/ip.h>		/* For OVS_VPORT_OUTPUT_PARAMS */
#include <net/ip6_route.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
/* Try to minimise changes required to the actions.c code for calling IPv6
 * fragmentation. We can keep the fragment() API mostly the same, except that
 * the callback parameter needs to be in the form that older kernels accept.
 * We don't backport the other ipv6_ops as they're currently unused by OVS. */
struct ovs_nf_ipv6_ops {
	int (*fragment)(struct sock *sk, struct sk_buff *skb,
			int (*output)(OVS_VPORT_OUTPUT_PARAMS));
};
#define nf_ipv6_ops ovs_nf_ipv6_ops

#if defined(OVS_FRAGMENT_BACKPORT)
static struct ovs_nf_ipv6_ops ovs_ipv6_ops = {
	.fragment = ip6_fragment,
};

static inline struct ovs_nf_ipv6_ops *ovs_nf_get_ipv6_ops(void)
{
	return &ovs_ipv6_ops;
}
#else /* !OVS_FRAGMENT_BACKPORT || !CONFIG_NETFILTER || || !CONFIG_IPV6 */
static inline const struct ovs_nf_ipv6_ops *ovs_nf_get_ipv6_ops(void)
{
	return NULL;
}
#endif
#define nf_get_ipv6_ops ovs_nf_get_ipv6_ops

#endif /* < 4.3 */
#endif /* __NETFILTER_IPV6_WRAPPER_H */
