#ifndef _NF_DEFRAG_IPV6_WRAPPER_H
#define _NF_DEFRAG_IPV6_WRAPPER_H

#include <linux/kconfig.h>
#include_next <net/netfilter/ipv6/nf_defrag_ipv6.h>

/* Upstream commit 029f7f3b8701 ("netfilter: ipv6: nf_defrag: avoid/free clone
 * operations") changed the semantics of nf_ct_frag6_gather(), so we need
 * to backport for all prior kernels, i.e. kernel < 4.5.0.
 *
 * Upstream commit 48cac18ecf1d ("ipv6: orphan skbs in reassembly unit") fixes
 * a bug that requires all kernels prior to this fix, i.e. kernel < 4.11.0
 * to be backported.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0)
#define OVS_NF_DEFRAG6_BACKPORT 1
int rpl_nf_ct_frag6_gather(struct net *net, struct sk_buff *skb, u32 user);
#define nf_ct_frag6_gather rpl_nf_ct_frag6_gather

/* If backporting IPv6 defrag, then init/exit functions need to be called from
 * compat_{in,ex}it() to prepare the backported fragmentation cache. In this
 * case we declare the functions which are defined in
 * datapath/linux/compat/nf_conntrack_reasm.c.
 *
 * Otherwise, if we can use upstream defrag then we can rely on the upstream
 * nf_defrag_ipv6 module to init/exit correctly. In this case the calls in
 * compat_{in,ex}it() can be no-ops.
 */
int __init rpl_nf_ct_frag6_init(void);
void rpl_nf_ct_frag6_cleanup(void);
void ovs_netns_frags6_init(struct net *net);
void ovs_netns_frags6_exit(struct net *net);
#else /* !OVS_NF_DEFRAG6_BACKPORT */
static inline int __init rpl_nf_ct_frag6_init(void) { return 0; }
static inline void rpl_nf_ct_frag6_cleanup(void) { }
static inline void ovs_netns_frags6_init(struct net *net) { }
static inline void ovs_netns_frags6_exit(struct net *net) { }
#endif /* OVS_NF_DEFRAG6_BACKPORT */
#define nf_ct_frag6_init rpl_nf_ct_frag6_init
#define nf_ct_frag6_cleanup rpl_nf_ct_frag6_cleanup

#endif /* __NF_DEFRAG_IPV6_WRAPPER_H */
