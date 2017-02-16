#ifndef _NF_CONNTRACK_CORE_WRAPPER_H
#define _NF_CONNTRACK_CORE_WRAPPER_H

#include_next <net/netfilter/nf_conntrack_core.h>

#ifndef HAVE_NF_CT_TMPL_ALLOC_TAKES_STRUCT_ZONE

#include <net/netfilter/nf_conntrack_zones.h>

#define nf_ct_tmpl_alloc rpl_nf_ct_tmpl_alloc
/* Released via destroy_conntrack() */
static inline struct nf_conn *
nf_ct_tmpl_alloc(struct net *net, const struct nf_conntrack_zone *zone,
		 gfp_t flags)
{
	struct nf_conn *tmpl;

	tmpl = kzalloc(sizeof(*tmpl), flags);
	if (tmpl == NULL)
		return NULL;

	tmpl->status = IPS_TEMPLATE;
	write_pnet(&tmpl->ct_net, net);

	if (nf_ct_zone_add(tmpl, flags, zone) < 0)
		goto out_free;

	atomic_set(&tmpl->ct_general.use, 0);

	return tmpl;
out_free:
	kfree(tmpl);
	return NULL;
}

static void rpl_nf_ct_tmpl_free(struct nf_conn *tmpl)
{
	nf_ct_ext_destroy(tmpl);
	nf_ct_ext_free(tmpl);
	kfree(tmpl);
}
#define nf_ct_tmpl_free rpl_nf_ct_tmpl_free

static inline struct nf_conntrack_tuple_hash *
rpl_nf_conntrack_find_get(struct net *net,
			  const struct nf_conntrack_zone *zone,
			  const struct nf_conntrack_tuple *tuple)
{
	return nf_conntrack_find_get(net, zone->id, tuple);
}
#define nf_conntrack_find_get rpl_nf_conntrack_find_get
#endif /* HAVE_NF_CT_TMPL_ALLOC_TAKES_STRUCT_ZONE */

#ifndef HAVE_NF_CT_GET_TUPLEPR_TAKES_STRUCT_NET
static inline bool rpl_nf_ct_get_tuple(const struct sk_buff *skb,
				       unsigned int nhoff,
				       unsigned int dataoff, u_int16_t l3num,
				       u_int8_t protonum,
				       struct net *net,
				       struct nf_conntrack_tuple *tuple,
				       const struct nf_conntrack_l3proto *l3proto,
				       const struct nf_conntrack_l4proto *l4proto)
{
	return nf_ct_get_tuple(skb, nhoff, dataoff, l3num, protonum, tuple,
			       l3proto, l4proto);
}
#define nf_ct_get_tuple rpl_nf_ct_get_tuple
#endif /* HAVE_NF_CT_GET_TUPLEPR_TAKES_STRUCT_NET */

/* Commit 08733a0cb7de ("netfilter: handle NF_REPEAT from nf_conntrack_in()")
 * introduced behavioural changes to this function which cannot be detected
 * in the headers. Unconditionally backport to kernels older than the one which
 * contains this commit. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,10,0)
static unsigned int rpl_nf_conntrack_in(struct net *net, u_int8_t pf,
					unsigned int hooknum,
					struct sk_buff *skb)
{
	int err;

	/* Repeat if requested, see nf_iterate(). */
	do {
		err = nf_conntrack_in(net, pf, hooknum, skb);
	} while (err == NF_REPEAT);

	return err;
}
#define nf_conntrack_in rpl_nf_conntrack_in
#endif /* < 4.10 */

#endif /* _NF_CONNTRACK_CORE_WRAPPER_H */
