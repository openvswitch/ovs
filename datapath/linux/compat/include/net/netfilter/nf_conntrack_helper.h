#ifndef _NF_CONNTRACK_HELPER_WRAPPER_H
#define _NF_CONNTRACK_HELPER_WRAPPER_H

#include_next <net/netfilter/nf_conntrack_helper.h>

#ifndef HAVE_NF_CONNTRACK_HELPER_PUT
static inline void nf_conntrack_helper_put(struct nf_conntrack_helper *helper) {
	module_put(helper->me);
}
#endif

#ifndef HAVE_NF_CT_HELPER_EXT_ADD_TAKES_HELPER
static inline struct nf_conn_help *
rpl_nf_ct_helper_ext_add(struct nf_conn *ct,
			 struct nf_conntrack_helper *helper, gfp_t gfp)
{
	return nf_ct_helper_ext_add(ct, gfp);
}
#define nf_ct_helper_ext_add rpl_nf_ct_helper_ext_add
#endif /* HAVE_NF_CT_HELPER_EXT_ADD_TAKES_HELPER */

#endif /* _NF_CONNTRACK_HELPER_WRAPPER_H */
