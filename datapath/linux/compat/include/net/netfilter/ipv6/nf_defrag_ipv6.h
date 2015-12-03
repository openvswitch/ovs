#ifndef _NF_DEFRAG_IPV6_WRAPPER_H
#define _NF_DEFRAG_IPV6_WRAPPER_H

#include <linux/kconfig.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)
#include_next <net/netfilter/ipv6/nf_defrag_ipv6.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)
#if defined(OVS_FRAGMENT_BACKPORT)
struct sk_buff *rpl_nf_ct_frag6_gather(struct sk_buff *skb, u32 user);
int __init rpl_nf_ct_frag6_init(void);
void rpl_nf_ct_frag6_cleanup(void);
void rpl_nf_ct_frag6_consume_orig(struct sk_buff *skb);
#else /* !OVS_FRAGMENT_BACKPORT */
static inline struct sk_buff *rpl_nf_ct_frag6_gather(struct sk_buff *skb,
						     u32 user)
{
	return skb;
}
static inline int __init rpl_nf_ct_frag6_init(void) { return 0; }
static inline void rpl_nf_ct_frag6_cleanup(void) { }
static inline void rpl_nf_ct_frag6_consume_orig(struct sk_buff *skb) { }
#endif /* OVS_FRAGMENT_BACKPORT */
#define nf_ct_frag6_gather rpl_nf_ct_frag6_gather
#define nf_ct_frag6_init rpl_nf_ct_frag6_init
#define nf_ct_frag6_cleanup rpl_nf_ct_frag6_cleanup
#define nf_ct_frag6_consume_orig rpl_nf_ct_frag6_consume_orig
#endif /* < 4.3 */

#endif /* __NF_DEFRAG_IPV6_WRAPPER_H */
