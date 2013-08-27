#include <net/genetlink.h>
#include <linux/version.h>

/* This is analogous to rtnl_notify() but uses genl_sock instead of rtnl.
 *
 * This is not (yet) in any upstream kernel. */
void genl_notify(struct sk_buff *skb, struct net *net, u32 portid, u32 group,
		 struct nlmsghdr *nlh, gfp_t flags)
{
	struct sock *sk = net->genl_sock;
	int report = 0;

	if (nlh)
		report = nlmsg_report(nlh);

	nlmsg_notify(sk, skb, portid, group, report, flags);
}
