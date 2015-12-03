#ifndef _NF_CONNTRACK_EXPECT_WRAPPER_H
#define _NF_CONNTRACK_EXPECT_WRAPPER_H

#include_next <net/netfilter/nf_conntrack_expect.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0)

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_zones.h>

static inline struct nf_conntrack_expect *
rpl___nf_ct_expect_find(struct net *net,
			const struct nf_conntrack_zone *zone,
			const struct nf_conntrack_tuple *tuple)
{
	return __nf_ct_expect_find(net, zone->id, tuple);
}
#define __nf_ct_expect_find rpl___nf_ct_expect_find

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0) */
#endif /* _NF_CONNTRACK_EXPECT_WRAPPER_H */
