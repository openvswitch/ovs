#ifndef _NF_CONNTRACK_HELPER_WRAPPER_H
#define _NF_CONNTRACK_HELPER_WRAPPER_H

#include_next <net/netfilter/nf_conntrack_helper.h>

#ifndef HAVE_NF_CONNTRACK_HELPER_PUT
static inline void nf_conntrack_helper_put(struct nf_conntrack_helper *helper) {
	module_put(helper->me);
}
#endif

#endif /* _NF_CONNTRACK_HELPER_WRAPPER_H */
