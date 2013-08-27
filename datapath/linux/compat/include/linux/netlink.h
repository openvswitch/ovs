#ifndef __LINUX_NETLINK_WRAPPER_H
#define __LINUX_NETLINK_WRAPPER_H 1

#include <linux/skbuff.h>
#include_next <linux/netlink.h>

#ifndef NLA_TYPE_MASK
#define NLA_F_NESTED		(1 << 15)
#define NLA_F_NET_BYTEORDER	(1 << 14)
#define NLA_TYPE_MASK		(~(NLA_F_NESTED | NLA_F_NET_BYTEORDER))
#endif

#include <net/netlink.h>

#ifndef NLMSG_DEFAULT_SIZE
#define NLMSG_DEFAULT_SIZE (NLMSG_GOODSIZE - NLMSG_HDRLEN)
#endif

#endif
