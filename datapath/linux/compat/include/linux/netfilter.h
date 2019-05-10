#ifndef __NETFILTER_WRAPPER_H
#define __NETFILTER_WRAPPER_H

#include_next <linux/netfilter.h>

#if !defined(HAVE_NF_HOOK_STATE) || !defined(HAVE_NF_HOOK_STATE_NET)
struct rpl_nf_hook_state {
	unsigned int hook;
	u_int8_t pf;
	struct net_device *in;
	struct net_device *out;
	struct sock *sk;
	struct net *net;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};
#define nf_hook_state rpl_nf_hook_state
#endif

#endif /* __NETFILTER_WRAPPER_H */
