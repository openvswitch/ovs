#ifndef __LINUX_TYPES_USER_WRAPPER_H
#define __LINUX_TYPES_USER_WRAPPER_H 1

#include_next <linux/types.h>

/* These were only introduced in v2.6.36. */
#ifndef __aligned_u64
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#define __aligned_be64 __be64 __attribute__((aligned(8)))
#define __aligned_le64 __le64 __attribute__((aligned(8)))
#endif

#endif
