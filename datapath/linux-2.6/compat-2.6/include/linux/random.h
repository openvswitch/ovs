#ifndef __LINUX_RANDOM_WRAPPER_H
#define __LINUX_RANDOM_WRAPPER_H 1

#include_next <linux/random.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)

#ifdef __KERNEL__
u32 random32(void);
void srandom32(u32 seed);
#endif /* __KERNEL__ */

#endif /* linux kernel < 2.6.19 */


#endif
