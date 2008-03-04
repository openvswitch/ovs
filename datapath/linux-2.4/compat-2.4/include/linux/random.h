#ifndef __LINUX_RANDOM_WRAPPER_H
#define __LINUX_RANDOM_WRAPPER_H 1

#include_next <linux/random.h>

#ifdef __KERNEL__
u32 random32(void);
void srandom32(u32 seed);
#endif

#endif
