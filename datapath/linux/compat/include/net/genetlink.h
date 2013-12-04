#ifndef __NET_GENERIC_NETLINK_WRAPPER_H
#define __NET_GENERIC_NETLINK_WRAPPER_H 1

#include <linux/version.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include_next <net/genetlink.h>

/*
 * 15e473046cb6e5d18a4d0057e61d76315230382b renames pid to portid
 * the affected structures are
 * netlink_skb_parms::pid -> portid
 * genl_info::snd_pid -> snd_portid
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
#define snd_portid snd_pid
#define portid pid
#endif

extern void genl_notify(struct sk_buff *skb, struct net *net, u32 portid,
			u32 group, struct nlmsghdr *nlh, gfp_t flags);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
static inline struct sk_buff *genlmsg_new_unicast(size_t payload,
						  struct genl_info *info,
						  gfp_t flags)
{
	return genlmsg_new(payload, flags);
}
#endif

#endif /* genetlink.h */
