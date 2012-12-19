#ifndef __NET_GENERIC_NETLINK_WRAPPER_H
#define __NET_GENERIC_NETLINK_WRAPPER_H 1

#include <linux/version.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>

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

/* Very special super-nasty workaround here:
 *
 * Before 2.6.19, nlmsg_multicast() lacked a 'flags' parameter.  We work
 * around that in our <net/netlink.h> replacement, so that nlmsg_multicast
 * is a macro that expands to rpl_nlmsg_multicast, which in turn has the
 * 'flags' parameter.
 *
 * However, also before 2.6.19, <net/genetlink.h> contains an inline definition
 * of genlmsg_multicast() that, of course, calls it without the 'flags'
 * parameter.  This causes a build failure.
 *
 * This works around the problem by temporarily renaming both nlmsg_multicast
 * and genlmsg_multicast with a "busted_" prefix.  (Nothing actually defines
 * busted_nlmsg_multicast(), so if anything actually tries to call it, then
 * we'll get a link error.)
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#undef nlmsg_multicast
#define nlmsg_multicast busted_nlmsg_multicast
#define genlmsg_multicast busted_genlmsg_multicast
extern int busted_nlmsg_multicast(struct sock *sk, struct sk_buff *skb,
				  u32 portid, unsigned int group);
#endif	/* linux kernel < v2.6.19 */

#include_next <net/genetlink.h>

/* Drop the "busted_" prefix described above. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#undef nlmsg_multicast
#undef genlmsg_multicast
#define nlmsg_multicast rpl_nlmsg_multicast
#endif	/* linux kernel < v2.6.19 */

#include <net/net_namespace.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

#include <linux/genetlink.h>

/**
 * struct genl_multicast_group - generic netlink multicast group
 * @name: name of the multicast group, names are per-family
 * @id: multicast group ID, assigned by the core, to use with
 *	  genlmsg_multicast().
 * @list: list entry for linking
 * @family: pointer to family, need not be set before registering
 */
struct genl_multicast_group {
	struct genl_family  *family;	/* private */
	struct list_head	list;	   /* private */
	char name[GENL_NAMSIZ];
	u32	id;
};

int genl_register_mc_group(struct genl_family *family,
		struct genl_multicast_group *grp);
#endif /* linux kernel < 2.6.23 */


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
/**
 * genlmsg_msg_size - length of genetlink message not including padding
 * @payload: length of message payload
 */
static inline int genlmsg_msg_size(int payload)
{
	return GENL_HDRLEN + payload;
}

/**
 * genlmsg_total_size - length of genetlink message including padding
 * @payload: length of message payload
 */
static inline int genlmsg_total_size(int payload)
{
	return NLMSG_ALIGN(genlmsg_msg_size(payload));
}

#define genlmsg_multicast(s, p, g, f) \
		genlmsg_multicast_flags((s), (p), (g), (f))

static inline int genlmsg_multicast_flags(struct sk_buff *skb, u32 portid,
		unsigned int group, gfp_t flags)
{
	int err;

	NETLINK_CB(skb).dst_group = group;

	err = netlink_broadcast(genl_sock, skb, portid, group, flags);
	if (err > 0)
		err = 0;

	return err;
}
#endif /* linux kernel < 2.6.19 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define genlmsg_multicast_netns(net, skb, portid, grp, flags) \
		genlmsg_multicast(skb, portid, grp, flags)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)

#define genlmsg_put(skb, p, seq, fam, flg, c) \
	genlmsg_put((skb), (p), (seq), (fam)->id, (fam)->hdrsize, \
			(flg), (c), (fam)->version)

/**
 * genlmsg_put_reply - Add generic netlink header to a reply message
 * @skb: socket buffer holding the message
 * @info: receiver info
 * @family: generic netlink family
 * @flags: netlink message flags
 * @cmd: generic netlink command
 *
 * Returns pointer to user specific header
 */
static inline void *genlmsg_put_reply(struct sk_buff *skb,
			struct genl_info *info, struct genl_family *family,
			int flags, u8 cmd)
{
	return genlmsg_put(skb, info->snd_portid, info->snd_seq, family,
				flags, cmd);
}

/**
 * genlmsg_reply - reply to a request
 * @skb: netlink message to be sent back
 * @info: receiver information
 */
static inline int genlmsg_reply(struct sk_buff *skb, struct genl_info *info)
{
	return genlmsg_unicast(skb, info->snd_portid);
}

/**
 * genlmsg_new - Allocate a new generic netlink message
 * @payload: size of the message payload
 * @flags: the type of memory to allocate.
 */
static inline struct sk_buff *genlmsg_new(size_t payload, gfp_t flags)
{
	return nlmsg_new(genlmsg_total_size(payload), flags);
}
#endif /* linux kernel < 2.6.20 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
int genl_register_family_with_ops(struct genl_family *family,
	struct genl_ops *ops, size_t n_ops);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
#define genl_notify(skb, net, portid, group, nlh, flags) \
	genl_notify(skb, portid, group, nlh, flags)
#endif
extern void genl_notify(struct sk_buff *skb, struct net *net, u32 portid,
			u32 group, struct nlmsghdr *nlh, gfp_t flags);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24) && \
    LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
static inline struct net *genl_info_net(struct genl_info *info)
{
	return &init_net;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32)
#define genlmsg_unicast(ignore_net, skb, portid)   genlmsg_unicast(skb, portid)
#endif
#endif /* genetlink.h */
