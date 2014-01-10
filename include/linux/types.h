/*
 * Copyright (c) 2011 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LINUX_TYPES_H
#define LINUX_TYPES_H 1

/* On Linux, this header file just includes <linux/types.h>.
 *
 * On other platforms, this header file implements just enough of
 * <linux/types.h> to allow <linux/openvswitch.h> to work, that is, it defines
 * the __u<N> and __be<N> types. */

#ifdef __KERNEL__
#include_next <linux/types.h>
#elif defined(HAVE_LINUX_TYPES_H)
/* With some combinations of kernel and userspace headers, including both
 * <sys/types.h> and <linux/types.h> only works if you do so in that order, so
 * force it.  */

#ifdef __CHECKER__
#define __CHECK_ENDIAN__
#endif

#include <sys/types.h>
#include_next <linux/types.h>
#else  /* no <linux/types.h> */
#include <stdint.h>

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif

typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

typedef uint16_t __bitwise__ __be16;
typedef uint32_t __bitwise__ __be32;
typedef uint64_t __bitwise__ __be64;
#endif	/* no <linux/types.h> */

#ifndef _WIN32
typedef __u32 HANDLE;
#endif

#endif /* <linux/types.h> */
