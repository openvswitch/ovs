#ifndef _NF_CONNTRACK_TIMEOUT_WRAPPER_H
#define _NF_CONNTRACK_TIMEOUT_WRAPPER_H

#include_next <net/netfilter/nf_conntrack_timeout.h>

#ifndef HAVE_NF_CT_SET_TIMEOUT

#ifndef HAVE_NF_CT_TIMEOUT
#define nf_ct_timeout ctnl_timeout
#endif

#ifdef CONFIG_NF_CONNTRACK_TIMEOUT
int rpl_nf_ct_set_timeout(struct net *net, struct nf_conn *ct, u8 l3num, u8 l4num,
			  const char *timeout_name);
void rpl_nf_ct_destroy_timeout(struct nf_conn *ct);
#else
static inline int rpl_nf_ct_set_timeout(struct net *net, struct nf_conn *ct,
					u8 l3num, u8 l4num,
					const char *timeout_name)
{
	return -EOPNOTSUPP;
}

static inline void rpl_nf_ct_destroy_timeout(struct nf_conn *ct)
{
	return;
}
#endif /* CONFIG_NF_CONNTRACK_TIMEOUT */

#define nf_ct_set_timeout rpl_nf_ct_set_timeout
#define nf_ct_destroy_timeout rpl_nf_ct_destroy_timeout

#endif /* HAVE_NF_CT_SET_TIMEOUT */
#endif /* _NF_CONNTRACK_TIMEOUT_WRAPPER_H */
