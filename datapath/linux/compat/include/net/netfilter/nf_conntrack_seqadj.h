#ifndef _NF_CONNTRACK_SEQADJ_WRAPPER_H
#define _NF_CONNTRACK_SEQADJ_WRAPPER_H

#ifdef HAVE_NF_CT_SEQ_ADJUST
#include_next <net/netfilter/nf_conntrack_seqadj.h>
#else

#include <net/netfilter/nf_nat_helper.h>

/* TCP sequence number adjustment.  Returns 1 on success, 0 on failure */
static inline int
nf_ct_seq_adjust(struct sk_buff *skb,
		 struct nf_conn *ct, enum ip_conntrack_info ctinfo,
		 unsigned int protoff)
{
	typeof(nf_nat_seq_adjust_hook) seq_adjust;

	seq_adjust = rcu_dereference(nf_nat_seq_adjust_hook);
	if (!seq_adjust ||
	    !seq_adjust(skb, ct, ctinfo, ip_hdrlen(skb))) {
		NF_CT_STAT_INC_ATOMIC(nf_ct_net(ct), drop);
		return 0;
	}

	return 1;
}

#endif /* HAVE_NF_CT_SEQ_ADJUST */

#endif /* _NF_CONNTRACK_SEQADJ_WRAPPER_H */
