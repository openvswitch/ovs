/*
 * Copyright (c) 2008, 2010, 2011, 2013, 2016 Nicira, Inc.
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
#ifndef BYTE_ORDER_H
#define BYTE_ORDER_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "openvswitch/types.h"

#ifndef __CHECKER__
#if !(defined(_WIN32) || defined(htonll))
static inline ovs_be64
htonll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

static inline uint64_t
ntohll(ovs_be64 n)
{
    return htonl(1) == 1 ? n : ((uint64_t) ntohl(n) << 32) | ntohl(n >> 32);
}
#endif /* !(defined(_WIN32) || defined(htonll)) */
#else
/* Making sparse happy with these functions also makes them unreadable, so
 * don't bother to show it their implementations. */
ovs_be64 htonll(uint64_t);
uint64_t ntohll(ovs_be64);
#endif

static inline ovs_be128
hton128(const ovs_u128 src)
{
    ovs_be128 dst;

    dst.be64.hi = htonll(src.u64.hi);
    dst.be64.lo = htonll(src.u64.lo);
    return dst;
}

static inline ovs_u128
ntoh128(const ovs_be128 src)
{
    ovs_u128 dst;

    dst.u64.hi = ntohll(src.be64.hi);
    dst.u64.lo = ntohll(src.be64.lo);
    return dst;
}

static inline uint32_t
uint32_byteswap(uint32_t crc) {
    return (((crc & 0x000000ff) << 24) |
            ((crc & 0x0000ff00) <<  8) |
            ((crc & 0x00ff0000) >>  8) |
            ((crc & 0xff000000) >> 24));
}

/* These macros may substitute for htons(), htonl(), and htonll() in contexts
 * where function calls are not allowed, such as case labels.  They should not
 * be used elsewhere because all of them evaluate their argument many times. */
#if defined(WORDS_BIGENDIAN) || __CHECKER__
#define CONSTANT_HTONS(VALUE) ((OVS_FORCE ovs_be16) ((VALUE) & 0xffff))
#define CONSTANT_HTONL(VALUE) ((OVS_FORCE ovs_be32) ((VALUE) & 0xffffffff))
#define CONSTANT_HTONLL(VALUE) \
        ((OVS_FORCE ovs_be64) ((VALUE) & UINT64_C(0xffffffffffffffff)))
#else
#define CONSTANT_HTONS(VALUE)                       \
        (((((ovs_be16) (VALUE)) & 0xff00) >> 8) |   \
         ((((ovs_be16) (VALUE)) & 0x00ff) << 8))
#define CONSTANT_HTONL(VALUE)                           \
        (((((ovs_be32) (VALUE)) & 0x000000ff) << 24) |  \
         ((((ovs_be32) (VALUE)) & 0x0000ff00) <<  8) |  \
         ((((ovs_be32) (VALUE)) & 0x00ff0000) >>  8) |  \
         ((((ovs_be32) (VALUE)) & 0xff000000) >> 24))
#define CONSTANT_HTONLL(VALUE)                                           \
        (((((ovs_be64) (VALUE)) & UINT64_C(0x00000000000000ff)) << 56) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x000000000000ff00)) << 40) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x0000000000ff0000)) << 24) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x00000000ff000000)) <<  8) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x000000ff00000000)) >>  8) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x0000ff0000000000)) >> 24) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0x00ff000000000000)) >> 40) | \
         ((((ovs_be64) (VALUE)) & UINT64_C(0xff00000000000000)) >> 56))
#endif

/* Returns the ovs_be32 that you would get from:
 *
 *    union { uint8_t b[4]; ovs_be32 be32; } x = { .b = { b0, b1, b2, b3 } };
 *    return x.be32;
 *
 * but without the undefined behavior. */
static inline ovs_be32
bytes_to_be32(uint8_t b0, uint8_t b1, uint8_t b2, uint8_t b3)
{
#if WORDS_BIGENDIAN
    uint32_t x = ((uint32_t) b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
#else
    uint32_t x = ((uint32_t) b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
#endif
    return (OVS_FORCE ovs_be32) x;
}

/* These functions zero-extend big-endian values to longer ones,
 * or truncate long big-endian value to shorter ones. */
#ifndef __CHECKER__
#if WORDS_BIGENDIAN
static inline ovs_be32 be16_to_be32(ovs_be16 x) { return x; }
static inline ovs_be64 be16_to_be64(ovs_be16 x) { return x; }
static inline ovs_be64 be32_to_be64(ovs_be32 x) { return x; }
static inline ovs_be32 be64_to_be32(ovs_be64 x) { return x; }
static inline ovs_be16 be64_to_be16(ovs_be64 x) { return x; }
static inline ovs_be16 be32_to_be16(ovs_be32 x) { return x; }
#else /* !WORDS_BIGENDIAN */
static inline ovs_be32 be16_to_be32(ovs_be16 x) { return (ovs_be32) x << 16; }
static inline ovs_be64 be16_to_be64(ovs_be16 x) { return (ovs_be64) x << 48; }
static inline ovs_be64 be32_to_be64(ovs_be32 x) { return (ovs_be64) x << 32; }
static inline ovs_be32 be64_to_be32(ovs_be64 x) { return x >> 32; }
static inline ovs_be16 be64_to_be16(ovs_be64 x) { return x >> 48; }
static inline ovs_be16 be32_to_be16(ovs_be32 x) { return x >> 16; }
#endif /* !WORDS_BIGENDIAN */
#else /* __CHECKER__ */
/* Making sparse happy with these functions also makes them unreadable, so
 * don't bother to show it their implementations. */
ovs_be32 be16_to_be32(ovs_be16);
ovs_be64 be16_to_be64(ovs_be16);
ovs_be64 be32_to_be64(ovs_be32);
ovs_be32 be64_to_be32(ovs_be64);
ovs_be16 be64_to_be16(ovs_be64);
ovs_be16 be32_to_be16(ovs_be32);
#endif

#endif /* byte-order.h */
