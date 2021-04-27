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

#ifndef HAVE_NF_NAT_HELPER_TRY_MODULE_GET
static inline int rpl_nf_nat_helper_try_module_get(const char *name, u16 l3num,
						   u8 protonum)
{
	request_module("ip_nat_%s", name);
	return 0;
}
#define nf_nat_helper_try_module_get rpl_nf_nat_helper_try_module_get
#endif /* HAVE_NF_NAT_HELPER_TRY_MODULE_GET */

#ifndef HAVE_NF_NAT_HELPER_PUT
void rpl_nf_nat_helper_put(struct nf_conntrack_helper *helper)
{
}
#define nf_nat_helper_put rpl_nf_nat_helper_put
#endif /* HAVE_NF_NAT_HELPER_PUT */

#endif /* _NF_CONNTRACK_HELPER_WRAPPER_H */
