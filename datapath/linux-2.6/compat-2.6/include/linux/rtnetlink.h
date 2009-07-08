#ifndef __RTNETLINK_WRAPPER_H
#define __RTNETLINK_WRAPPER_H 1

#include_next <linux/rtnetlink.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
static inline int rtnl_notify(struct sk_buff *skb, struct net *net, u32 pid,
			      u32 group, struct nlmsghdr *nlh, gfp_t flags)
{
	BUG_ON(nlh);		/* not implemented */
	if (group) {
		/* errors reported via destination sk->sk_err */
		nlmsg_multicast(rtnl, skb, 0, group);
	}
	return 0;
}

static inline void rtnl_set_sk_err(struct net *net, u32 group, int error)
{
	netlink_set_err(rtnl, 0, group, error);
}
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define rtnl_notify(skb, net, pid, group, nlh, flags) \
	((void) (net), rtnl_notify(skb, pid, group, nlh, flags))
#define rtnl_set_sk_err(net, group, error) \
	((void) (net), rtnl_set_sk_err(group, error))
#endif /* linux kernel < 2.6.25 */

#endif /* linux/rtnetlink.h wrapper */
