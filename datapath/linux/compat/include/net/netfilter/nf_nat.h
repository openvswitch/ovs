#ifndef _NF_NAT_WRAPPER_H
#define _NF_NAT_WRAPPER_H

#include_next <net/netfilter/nf_nat.h>

#ifndef HAVE_NF_CT_NAT_EXT_ADD

static inline struct nf_conn_nat *
nf_ct_nat_ext_add(struct nf_conn *ct)
{
	struct nf_conn_nat *nat = nfct_nat(ct);
	if (nat)
		return nat;

	if (!nf_ct_is_confirmed(ct))
		nat = nf_ct_ext_add(ct, NF_CT_EXT_NAT, GFP_ATOMIC);

	return nat;
}
#endif /* HAVE_NF_CT_NAT_EXT_ADD */

#ifndef HAVE_NF_NAT_ALLOC_NULL_BINDING
static inline unsigned int
nf_nat_alloc_null_binding(struct nf_conn *ct, unsigned int hooknum)
{
	/* Force range to this IP; let proto decide mapping for
	 * per-proto parts (hence not IP_NAT_RANGE_PROTO_SPECIFIED).
	 * Use reply in case it's already been mangled (eg local packet).
	 */
	union nf_inet_addr ip =
		(HOOK2MANIP(hooknum) == NF_NAT_MANIP_SRC ?
		ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3 :
		ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3);
	struct nf_nat_range range = {
		.flags		= NF_NAT_RANGE_MAP_IPS,
		.min_addr	= ip,
		.max_addr	= ip,
	};
	return nf_nat_setup_info(ct, &range, HOOK2MANIP(hooknum));
}

#endif /* HAVE_NF_NAT_ALLOC_NULL_BINDING */

#endif /* _NF_NAT_WRAPPER_H */
