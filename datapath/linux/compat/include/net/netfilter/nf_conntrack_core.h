#ifndef _NF_CONNTRACK_CORE_WRAPPER_H
#define _NF_CONNTRACK_CORE_WRAPPER_H

#include_next <net/netfilter/nf_conntrack_core.h>

#ifndef HAVE_NF_CT_TMPL_ALLOC_TAKES_STRUCT_ZONE

#include <net/netfilter/nf_conntrack_zones.h>

/* Released via destroy_conntrack() */
static inline struct nf_conn *
rpl_nf_ct_tmpl_alloc(struct net *net, const struct nf_conntrack_zone *zone,
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
#define nf_ct_tmpl_alloc rpl_nf_ct_tmpl_alloc

static inline void rpl_nf_ct_tmpl_free(struct nf_conn *tmpl)
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

#ifdef HAVE_NF_CONN_TIMER

#ifndef HAVE_NF_CT_DELETE
#include <net/netfilter/nf_conntrack_timestamp.h>
#endif

static inline bool rpl_nf_ct_delete(struct nf_conn *ct, u32 portid, int report)
{
	if (del_timer(&ct->timeout))
#ifdef HAVE_NF_CT_DELETE
		return nf_ct_delete(ct, portid, report);
#else
	{
		struct nf_conn_tstamp *tstamp;

		tstamp = nf_conn_tstamp_find(ct);
		if (tstamp && tstamp->stop == 0)
			tstamp->stop = ktime_to_ns(ktime_get_real());

		if (!test_bit(IPS_DYING_BIT, &ct->status) &&
		    unlikely(nf_conntrack_event(IPCT_DESTROY, ct) < 0)) {
			/* destroy event was not delivered */
			nf_ct_delete_from_lists(ct);
			nf_ct_dying_timeout(ct);
			return false;
		}
		set_bit(IPS_DYING_BIT, &ct->status);
		nf_ct_delete_from_lists(ct);
		nf_ct_put(ct);
		return true;
	}
#endif
	return false;
}
#define nf_ct_delete rpl_nf_ct_delete
#endif /* HAVE_NF_CONN_TIMER */

#ifndef HAVE_NF_CONNTRACK_IN_TAKES_NF_HOOK_STATE
static inline unsigned int
rpl_nf_conntrack_in(struct sk_buff *skb, const struct nf_hook_state *state)
{
	return nf_conntrack_in(state->net, state->pf, state->hook, skb);
}
#define nf_conntrack_in rpl_nf_conntrack_in
#endif /* HAVE_NF_CONNTRACK_IN_TAKES_NF_HOOK_STATE */

#ifdef HAVE_NF_CT_INVERT_TUPLEPR
static inline bool rpl_nf_ct_invert_tuple(struct nf_conntrack_tuple *inverse,
	const struct nf_conntrack_tuple *orig)
{
	return nf_ct_invert_tuplepr(inverse, orig);
}
#else
static inline bool rpl_nf_ct_invert_tuple(struct nf_conntrack_tuple *inverse,
	const struct nf_conntrack_tuple *orig)
{
	return nf_ct_invert_tuple(inverse, orig);
}
#endif /* HAVE_NF_CT_INVERT_TUPLEPR */

#endif /* _NF_CONNTRACK_CORE_WRAPPER_H */
