#ifndef __LINUX_TYPES_WRAPPER_H
#define __LINUX_TYPES_WRAPPER_H 1

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#error These replacement header files are for use with Linux 2.4.x only.
#endif

#include_next <linux/types.h>

/*
 * Below are truly Linux-specific types that should never collide with
 * any application/library that wants linux/types.h.
 */

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#ifdef __CHECK_ENDIAN__
#define __bitwise __bitwise__
#else
#define __bitwise
#endif

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
#if defined(__GNUC__) && !defined(__STRICT_ANSI__)
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;
#endif
typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;

#ifdef __KERNEL__
typedef unsigned __bitwise__ gfp_t;

#ifdef CONFIG_RESOURCES_64BIT
typedef u64 resource_size_t;
#else
typedef u32 resource_size_t;
#endif

#endif	/* __KERNEL__ */

#endif
