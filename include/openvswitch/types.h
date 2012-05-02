/*
 * Copyright (c) 2010, 2011 Nicira, Inc.
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

#ifndef OPENVSWITCH_TYPES_H
#define OPENVSWITCH_TYPES_H 1

#include <linux/types.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef __CHECKER__
#define OVS_BITWISE __attribute__((bitwise))
#define OVS_FORCE __attribute__((force))
#else
#define OVS_BITWISE
#define OVS_FORCE
#endif

/* The ovs_be<N> types indicate that an object is in big-endian, not
 * native-endian, byte order.  They are otherwise equivalent to uint<N>_t.
 *
 * We bootstrap these from the Linux __be<N> types.  If we instead define our
 * own independently then __be<N> and ovs_be<N> become mutually
 * incompatible. */
typedef __be16 ovs_be16;
typedef __be32 ovs_be32;
typedef __be64 ovs_be64;

/* Netlink and OpenFlow both contain 64-bit values that are only guaranteed to
 * be aligned on 32-bit boundaries.  These types help.
 *
 * lib/unaligned.h has helper functions for accessing these. */

/* A 64-bit value, in host byte order, that is only aligned on a 32-bit
 * boundary.  */
typedef struct {
#ifdef WORDS_BIGENDIAN
        uint32_t hi, lo;
#else
        uint32_t lo, hi;
#endif
} ovs_32aligned_u64;

/* A 64-bit value, in network byte order, that is only aligned on a 32-bit
 * boundary. */
typedef struct {
        ovs_be32 hi, lo;
} ovs_32aligned_be64;

#endif /* openvswitch/types.h */
