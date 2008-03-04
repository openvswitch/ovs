#ifndef __NET_CHECKSUM_WRAPPER_H
#define __NET_CHECKSUM_WRAPPER_H 1

#include_next <net/checksum.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)

static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}

#endif /* linux kernel < 2.6.20 */

#endif /* checksum.h */
