#ifndef __LINUX_NETLINK_WRAPPER_H
#define __LINUX_NETLINK_WRAPPER_H 1

#include <linux/skbuff.h>
#include_next <linux/netlink.h>
#include <net/netlink.h>

#include <linux/version.h>

#ifndef NLMSG_DEFAULT_SIZE
#define NLMSG_DEFAULT_SIZE (NLMSG_GOODSIZE - NLMSG_HDRLEN)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define nlmsg_new(s, f)   nlmsg_new_proper((s), (f))
static inline struct sk_buff *nlmsg_new_proper(int size, gfp_t flags)
{
	return alloc_skb(size, flags);
}

#endif /* linux kernel < 2.6.19 */


#endif
