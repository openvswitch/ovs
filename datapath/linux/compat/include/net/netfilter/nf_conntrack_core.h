#ifndef _NF_CONNTRACK_CORE_WRAPPER_H
#define _NF_CONNTRACK_CORE_WRAPPER_H

#include_next <net/netfilter/nf_conntrack_core.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)

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

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0) */
#endif /* _NF_CONNTRACK_CORE_WRAPPER_H */
