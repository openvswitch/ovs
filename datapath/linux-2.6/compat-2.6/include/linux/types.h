#ifndef __LINUX_TYPES_WRAPPER_H
#define __LINUX_TYPES_WRAPPER_H 1

#include_next <linux/types.h>

#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)

typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;

#endif /* linux kernel < 2.6.20 */

#endif
