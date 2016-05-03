#ifndef _NF_DEFRAG_IPV6_WRAPPER_H
#define _NF_DEFRAG_IPV6_WRAPPER_H

#include <linux/kconfig.h>
#include_next <net/netfilter/ipv6/nf_defrag_ipv6.h>

/* Upstream commit 029f7f3b8701 ("netfilter: ipv6: nf_defrag: avoid/free clone
 * operations") changed the semantics of nf_ct_frag6_gather(), so we backport
 * it for all prior kernels.
 */
#if defined(HAVE_NF_CT_FRAG6_CONSUME_ORIG) || \
    defined(HAVE_NF_CT_FRAG6_OUTPUT)
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
#else /* !OVS_NF_DEFRAG6_BACKPORT */
static inline int __init rpl_nf_ct_frag6_init(void) { return 0; }
static inline void rpl_nf_ct_frag6_cleanup(void) { }
#endif /* OVS_NF_DEFRAG6_BACKPORT */
#define nf_ct_frag6_init rpl_nf_ct_frag6_init
#define nf_ct_frag6_cleanup rpl_nf_ct_frag6_cleanup

#endif /* __NF_DEFRAG_IPV6_WRAPPER_H */
