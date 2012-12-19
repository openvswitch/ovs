/* -*- c -*- */

#include <net/genetlink.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#include <linux/mutex.h>
#include <linux/openvswitch.h>

#include "openvswitch/datapath-compat.h"

static DEFINE_MUTEX(mc_group_mutex);

int genl_register_mc_group(struct genl_family *family,
			   struct genl_multicast_group *grp)
{
	static int next_group = GENL_FIRST_MCGROUP;

	grp->family = family;

	if (!strcmp(grp->name, OVS_VPORT_MCGROUP)) {
		grp->id = OVS_VPORT_MCGROUP_FALLBACK_ID;
		return 0;
	}

	mutex_lock(&mc_group_mutex);
	grp->id = next_group;

	if (++next_group > GENL_LAST_MCGROUP)
		next_group = GENL_FIRST_MCGROUP;
	mutex_unlock(&mc_group_mutex);

	return 0;
}
#endif /* kernel < 2.6.23 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
/**
 * genl_register_family_with_ops - register a generic netlink family
 * @family: generic netlink family
 * @ops: operations to be registered
 * @n_ops: number of elements to register
 *
 * Registers the specified family and operations from the specified table.
 * Only one family may be registered with the same family name or identifier.
 *
 * The family id may equal GENL_ID_GENERATE causing an unique id to
 * be automatically generated and assigned.
 *
 * Either a doit or dumpit callback must be specified for every registered
 * operation or the function will fail. Only one operation structure per
 * command identifier may be registered.
 *
 * See include/net/genetlink.h for more documenation on the operations
 * structure.
 *
 * This is equivalent to calling genl_register_family() followed by
 * genl_register_ops() for every operation entry in the table taking
 * care to unregister the family on error path.
 *
 * Return 0 on success or a negative error code.
 */
int genl_register_family_with_ops(struct genl_family *family,
	struct genl_ops *ops, size_t n_ops)
{
	int err, i;

	err = genl_register_family(family);
	if (err)
		return err;

	for (i = 0; i < n_ops; ++i, ++ops) {
		err = genl_register_ops(family, ops);
		if (err)
			goto err_out;
	}
	return 0;
err_out:
	genl_unregister_family(family);
	return err;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/**
 * nlmsg_notify - send a notification netlink message
 * @sk: netlink socket to use
 * @skb: notification message
 * @portid: destination netlink portid for reports or 0
 * @group: destination multicast group or 0
 * @report: 1 to report back, 0 to disable
 * @flags: allocation flags
 */
int nlmsg_notify(struct sock *sk, struct sk_buff *skb, u32 portid,
		 unsigned int group, int report, gfp_t flags)
{
	int err = 0;

	if (group) {
		int exclude_portid = 0;

		if (report) {
			atomic_inc(&skb->users);
			exclude_portid = portid;
		}

		/* errors reported via destination sk->sk_err, but propagate
		 * delivery errors if NETLINK_BROADCAST_ERROR flag is set */
		err = nlmsg_multicast(sk, skb, exclude_portid, group, flags);
	}

	if (report) {
		int err2;

		err2 = nlmsg_unicast(sk, skb, portid);
		if (!err || err == -ESRCH)
			err = err2;
	}

	return err;
}
#endif

/* This is analogous to rtnl_notify() but uses genl_sock instead of rtnl.
 *
 * This is not (yet) in any upstream kernel. */
void genl_notify(struct sk_buff *skb, struct net *net, u32 portid, u32 group,
		 struct nlmsghdr *nlh, gfp_t flags)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
	struct sock *sk = net->genl_sock;
#else
	struct sock *sk = genl_sock;
#endif
	int report = 0;

	if (nlh)
		report = nlmsg_report(nlh);

	nlmsg_notify(sk, skb, portid, group, report, flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,30)
/* This function wasn't exported before 2.6.30.  Lose! */
void netlink_set_err(struct sock *ssk, u32 portid, u32 group, int code)
{
}
#endif
