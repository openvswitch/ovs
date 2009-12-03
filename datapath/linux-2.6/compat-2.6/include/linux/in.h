#ifndef __LINUX_IN_WRAPPER_H
#define __LINUX_IN_WRAPPER_H 1

#include_next <linux/in.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)

static inline bool ipv4_is_multicast(__be32 addr)
{
	return (addr & htonl(0xf0000000)) == htonl(0xe0000000);
}

#endif /* linux kernel < 2.6.25 */

#endif
