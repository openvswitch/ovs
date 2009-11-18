#ifndef __NET_CHECKSUM_WRAPPER_H
#define __NET_CHECKSUM_WRAPPER_H 1

#include_next <net/checksum.h>

#ifndef HAVE_CSUM_UNFOLD
static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}
#endif /* !HAVE_CSUM_UNFOLD */

#endif /* checksum.h */
