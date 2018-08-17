#include <linux/types.h>

#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_l3proto.h>

/*
 * Upstream net-next commmit 7e35ec0e8044
 * ("netfilter: conntrack: move nf_ct_netns_{get,put}() to core")
 * is introduced in v4.15, and it supports NFPROTO_INET in
 * nf_ct_netns_{get,put}() that OVS conntrack uses this feature.
 *
 * However, we only need this feature if the underlying nf_conntrack_l3proto
 * supports net_ns_get/put.  Thus, we just mock the functions if
 * HAVE_NET_NS_SET is false.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0)
#ifdef HAVE_NET_NS_SET
static int nf_ct_netns_do_get(struct net *net, u8 nfproto)
{
	const struct nf_conntrack_l3proto *l3proto;
	int ret;

	might_sleep();

	ret = nf_ct_l3proto_try_module_get(nfproto);
	if (ret < 0)
		return ret;

	/* we already have a reference, can't fail */
	rcu_read_lock();
	l3proto = __nf_ct_l3proto_find(nfproto);
	rcu_read_unlock();

	if (!l3proto->net_ns_get)
		return 0;

	ret = l3proto->net_ns_get(net);
	if (ret < 0)
		nf_ct_l3proto_module_put(nfproto);

	return ret;
}

int rpl_nf_ct_netns_get(struct net *net, u8 nfproto)
{
	int err;

	if (nfproto == NFPROTO_INET) {
		err = nf_ct_netns_do_get(net, NFPROTO_IPV4);
		if (err < 0)
			goto err1;
		err = nf_ct_netns_do_get(net, NFPROTO_IPV6);
		if (err < 0)
			goto err2;
	} else {
		err = nf_ct_netns_do_get(net, nfproto);
		if (err < 0)
			goto err1;
	}
	return 0;

err2:
	nf_ct_netns_put(net, NFPROTO_IPV4);
err1:
	return err;
}
EXPORT_SYMBOL_GPL(rpl_nf_ct_netns_get);

static void nf_ct_netns_do_put(struct net *net, u8 nfproto)
{
	const struct nf_conntrack_l3proto *l3proto;

	might_sleep();

	/* same as nf_conntrack_netns_get(), reference assumed */
	rcu_read_lock();
	l3proto = __nf_ct_l3proto_find(nfproto);
	rcu_read_unlock();

	if (WARN_ON(!l3proto))
		return;

	if (l3proto->net_ns_put)
		l3proto->net_ns_put(net);

	nf_ct_l3proto_module_put(nfproto);
}

void rpl_nf_ct_netns_put(struct net *net, uint8_t nfproto)
{
	if (nfproto == NFPROTO_INET) {
		nf_ct_netns_do_put(net, NFPROTO_IPV4);
		nf_ct_netns_do_put(net, NFPROTO_IPV6);
	} else
		nf_ct_netns_do_put(net, nfproto);
}
EXPORT_SYMBOL_GPL(rpl_nf_ct_netns_put);

#else /* !HAVE_NET_NS_SET */
void rpl_nf_ct_netns_put(struct net *net, uint8_t nfproto)
{
}
EXPORT_SYMBOL_GPL(rpl_nf_ct_netns_put);

int rpl_nf_ct_netns_get(struct net *net, u8 nfproto)
{
    return 0;
}
EXPORT_SYMBOL_GPL(rpl_nf_ct_netns_get);

#endif /* HAVE_NET_NS_SET */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0) */
