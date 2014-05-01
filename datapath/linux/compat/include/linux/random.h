#ifndef __LINUX_RANDOM_WRAPPER_H
#define __LINUX_RANDOM_WRAPPER_H 1

#include_next <linux/random.h>

#ifndef HAVE_PRANDOM_U32
#define prandom_u32()		random32()
#endif

#endif
