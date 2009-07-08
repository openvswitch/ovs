#ifndef __NET_NETLINK_WRAPPER_H
#define __NET_NETLINK_WRAPPER_H 1

#include_next <net/netlink.h>

#ifndef HAVE_NLA_NUL_STRING
#define NLA_NUL_STRING NLA_STRING

static inline int VERIFY_NUL_STRING(struct nlattr *attr)
{
	return (!attr || (nla_len(attr)
			  && memchr(nla_data(attr), '\0', nla_len(attr)))
		? 0 : EINVAL);
}
#else
static inline int VERIFY_NUL_STRING(struct nlattr *attr)
{
	return 0;
}
#endif	/* !HAVE_NLA_NUL_STRING */

#endif /* net/netlink.h */
