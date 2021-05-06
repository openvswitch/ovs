#ifndef __LINUX_TYPES_WRAPPER_H
#define __LINUX_TYPES_WRAPPER_H 1

#include_next <linux/types.h>

#ifndef HAVE_CSUM_TYPES
typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;
#endif

#endif
