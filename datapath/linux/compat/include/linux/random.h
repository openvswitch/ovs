#ifndef __LINUX_RANDOM_WRAPPER_H
#define __LINUX_RANDOM_WRAPPER_H 1

#include_next <linux/random.h>

#ifndef HAVE_PRANDOM_U32
#define prandom_u32()		random32()
#endif

#ifndef HAVE_PRANDOM_U32_MAX
static inline u32 prandom_u32_max(u32 ep_ro)
{
	return (u32)(((u64) prandom_u32() * ep_ro) >> 32);
}
#endif

#endif
