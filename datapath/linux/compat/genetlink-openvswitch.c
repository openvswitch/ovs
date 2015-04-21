#include <net/genetlink.h>
#include <linux/version.h>

#ifndef HAVE_GENL_NOTIFY_TAKES_FAMILY

#undef genl_notify

void rpl_genl_notify(struct rpl_genl_family *family, struct sk_buff *skb,
		     struct net *net, u32 portid, u32 group,
		     struct nlmsghdr *nlh, gfp_t flags)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,3,0)
	struct sock *sk = net->genl_sock;
	int report = 0;

	if (nlh)
		report = nlmsg_report(nlh);

	nlmsg_notify(sk, skb, portid, group, report, flags);
#else
	genl_notify(skb, net, portid, group, nlh, flags);
#endif
}
EXPORT_SYMBOL_GPL(rpl_genl_notify);

int rpl___genl_register_family(struct rpl_genl_family *f)
{
	int err;

	f->compat_family.id = f->id;
	f->compat_family.hdrsize = f->hdrsize;
	strncpy(f->compat_family.name, f->name, GENL_NAMSIZ);
	f->compat_family.version = f->version;
	f->compat_family.maxattr = f->maxattr;
	f->compat_family.netnsok = f->netnsok;
#ifdef HAVE_PARALLEL_OPS
	f->compat_family.parallel_ops = f->parallel_ops;
#endif
	err = genl_register_family_with_ops(&f->compat_family,
					    (struct genl_ops *) f->ops, f->n_ops);
	if (err)
		goto error;

	if (f->mcgrps) {
		/* Need to Fix GROUP_ID() for more than one group. */
		BUG_ON(f->n_mcgrps > 1);
		err = genl_register_mc_group(&f->compat_family,
					     (struct genl_multicast_group *) f->mcgrps);
		if (err)
			goto error;
	}
error:
	return err;

}
EXPORT_SYMBOL_GPL(rpl___genl_register_family);

#endif /* kernel version < 3.13.0 */
