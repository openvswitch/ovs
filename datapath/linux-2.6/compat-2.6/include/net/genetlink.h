#ifndef __NET_GENERIC_NETLINK_WRAPPER_H
#define __NET_GENERIC_NETLINK_WRAPPER_H 1


#include <linux/netlink.h>
#include_next <net/genetlink.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)

#include <linux/genetlink.h>

/*----------------------------------------------------------------------------
 * In 2.6.23, registering of multicast groups was added.  Our compatability 
 * layer just supports registering a single group, since that's all we
 * need.
 */

/**
 * struct genl_multicast_group - generic netlink multicast group
 * @name: name of the multicast group, names are per-family
 * @id: multicast group ID, assigned by the core, to use with
 *	  genlmsg_multicast().
 * @list: list entry for linking
 * @family: pointer to family, need not be set before registering
 */
struct genl_multicast_group
{
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

static inline int genlmsg_multicast_flags(struct sk_buff *skb, u32 pid, 
		unsigned int group, gfp_t flags)
{
	int err;

	NETLINK_CB(skb).dst_group = group;

	err = netlink_broadcast(genl_sock, skb, pid, group, flags);
	if (err > 0)
		err = 0;

	return err;
}
#endif /* linux kernel < 2.6.19 */


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
	return genlmsg_put(skb, info->snd_pid, info->snd_seq, family,
				flags, cmd);
}

/**
 * genlmsg_reply - reply to a request
 * @skb: netlink message to be sent back
 * @info: receiver information
 */
static inline int genlmsg_reply(struct sk_buff *skb, struct genl_info *info)
{
	return genlmsg_unicast(skb, info->snd_pid);
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

#endif /* genetlink.h */
