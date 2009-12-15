#ifndef __LINUX_IN_WRAPPER_H
#define __LINUX_IN_WRAPPER_H 1

#include_next <linux/in.h>

#ifndef HAVE_IPV4_IS_MULTICAST

static inline bool ipv4_is_multicast(__be32 addr)
{
	return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}

#endif /* !HAVE_IPV4_IS_MULTICAST */

#endif
