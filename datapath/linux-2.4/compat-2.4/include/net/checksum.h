#ifndef __NET_CHECKSUM_WRAPPER_H
#define __NET_CHECKSUM_WRAPPER_H 1

#include_next <net/checksum.h>

static inline __wsum csum_unfold(__sum16 n)
{
	return (__force __wsum)n;
}

#endif
