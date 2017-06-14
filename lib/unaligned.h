/*
 * Copyright (c) 2010, 2011, 2014 Nicira, Inc.
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

#ifndef UNALIGNED_H
#define UNALIGNED_H 1

#include <stdint.h>
#include "byte-order.h"
#include "openvswitch/types.h"
#include "openvswitch/type-props.h"
#include "util.h"

/* Public API. */
static inline uint16_t get_unaligned_u16(const uint16_t *);
static inline uint32_t get_unaligned_u32(const uint32_t *);
static inline void put_unaligned_u16(uint16_t *, uint16_t);
static inline void put_unaligned_u32(uint32_t *, uint32_t);
static inline void put_unaligned_u64(uint64_t *, uint64_t);

static inline ovs_be16 get_unaligned_be16(const ovs_be16 *);
static inline ovs_be32 get_unaligned_be32(const ovs_be32 *);
static inline ovs_be64 get_unaligned_be64(const ovs_be64 *);
static inline void put_unaligned_be16(ovs_be16 *, ovs_be16);
static inline void put_unaligned_be32(ovs_be32 *, ovs_be32);
static inline void put_unaligned_be64(ovs_be64 *, ovs_be64);

/* uint64_t get_unaligned_u64(uint64_t *p);
 *
 * Returns the value of the possibly misaligned uint64_t at 'p'.  'p' may
 * actually be any type that points to a 64-bit integer.  That is, on Unix-like
 * 32-bit ABIs, it may point to an "unsigned long long int", and on Unix-like
 * 64-bit ABIs, it may point to an "unsigned long int" or an "unsigned long
 * long int".
 *
 * This is special-cased because on some Linux targets, the kernel __u64 is
 * unsigned long long int and the userspace uint64_t is unsigned long int, so
 * that any single function prototype would fail to accept one or the other.
 *
 * Below, "sizeof (*(P) % 1)" verifies that *P has an integer type, since
 * operands to % must be integers.
 */
#define get_unaligned_u64(P)                                \
    (BUILD_ASSERT(sizeof *(P) == 8),                        \
     BUILD_ASSERT_GCCONLY(!TYPE_IS_SIGNED(typeof(*(P)))),   \
     (void) sizeof (*(P) % 1),                              \
     get_unaligned_u64__((const uint64_t *) (P)))

#ifdef __GNUC__
/* GCC implementations. */
#define GCC_UNALIGNED_ACCESSORS(TYPE, ABBREV)   \
struct unaligned_##ABBREV {                     \
    TYPE x __attribute__((__packed__));         \
};                                              \
static inline struct unaligned_##ABBREV *       \
unaligned_##ABBREV(const TYPE *p)               \
{                                               \
    return (struct unaligned_##ABBREV *) p;     \
}                                               \
                                                \
static inline TYPE                              \
get_unaligned_##ABBREV(const TYPE *p)           \
{                                               \
    return unaligned_##ABBREV(p)->x;            \
}                                               \
                                                \
static inline void                              \
put_unaligned_##ABBREV(TYPE *p, TYPE x)         \
{                                               \
    unaligned_##ABBREV(p)->x = x;               \
}

GCC_UNALIGNED_ACCESSORS(uint16_t, u16);
GCC_UNALIGNED_ACCESSORS(uint32_t, u32);
GCC_UNALIGNED_ACCESSORS(uint64_t, u64__); /* Special case: see below. */

GCC_UNALIGNED_ACCESSORS(ovs_be16, be16);
GCC_UNALIGNED_ACCESSORS(ovs_be32, be32);
GCC_UNALIGNED_ACCESSORS(ovs_be64, be64);
#else
/* Generic implementations. */

static inline uint16_t get_unaligned_u16(const uint16_t *p_)
{
    const uint8_t *p = (const uint8_t *) p_;
    return ntohs((p[0] << 8) | p[1]);
}

static inline void put_unaligned_u16(uint16_t *p_, uint16_t x_)
{
    uint8_t *p = (uint8_t *) p_;
    uint16_t x = ntohs(x_);

    p[0] = x >> 8;
    p[1] = x;
}

static inline uint32_t get_unaligned_u32(const uint32_t *p_)
{
    const uint8_t *p = (const uint8_t *) p_;
    return ntohl((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline void put_unaligned_u32(uint32_t *p_, uint32_t x_)
{
    uint8_t *p = (uint8_t *) p_;
    uint32_t x = ntohl(x_);

    p[0] = x >> 24;
    p[1] = x >> 16;
    p[2] = x >> 8;
    p[3] = x;
}

static inline uint64_t get_unaligned_u64__(const uint64_t *p_)
{
    const uint8_t *p = (const uint8_t *) p_;
    return ntohll(((uint64_t) p[0] << 56)
                  | ((uint64_t) p[1] << 48)
                  | ((uint64_t) p[2] << 40)
                  | ((uint64_t) p[3] << 32)
                  | (p[4] << 24)
                  | (p[5] << 16)
                  | (p[6] << 8)
                  | p[7]);
}

static inline void put_unaligned_u64__(uint64_t *p_, uint64_t x_)
{
    uint8_t *p = (uint8_t *) p_;
    uint64_t x = ntohll(x_);

    p[0] = x >> 56;
    p[1] = x >> 48;
    p[2] = x >> 40;
    p[3] = x >> 32;
    p[4] = x >> 24;
    p[5] = x >> 16;
    p[6] = x >> 8;
    p[7] = x;
}

/* Only sparse cares about the difference between uint<N>_t and ovs_be<N>, and
 * that takes the GCC branch, so there's no point in working too hard on these
 * accessors. */
#define get_unaligned_be16 get_unaligned_u16
#define get_unaligned_be32 get_unaligned_u32
#define put_unaligned_be16 put_unaligned_u16
#define put_unaligned_be32 put_unaligned_u32
#define put_unaligned_be64 put_unaligned_u64

/* We do not #define get_unaligned_be64 as for the other be<N> functions above,
 * because such a definition would mean that get_unaligned_be64() would have a
 * different interface in each branch of the #if: with GCC it would take a
 * "ovs_be64 *", with other compilers any pointer-to-64-bit-type (but not void
 * *).  The latter means code like "get_unaligned_be64(ofpbuf_data(b))" would
 * work with GCC but not with other compilers, which is surprising and
 * undesirable.  Hence this wrapper function. */
static inline ovs_be64
get_unaligned_be64(const ovs_be64 *p)
{
    return get_unaligned_u64(p);
}
#endif

/* Stores 'x' at possibly misaligned address 'p'.
 *
 * put_unaligned_u64() could be overloaded in the same way as
 * get_unaligned_u64(), but so far it has not proven necessary.
 */
static inline void
put_unaligned_u64(uint64_t *p, uint64_t x)
{
    put_unaligned_u64__(p, x);
}

/* Returns the value in 'x'. */
static inline uint32_t
get_16aligned_u32(const ovs_16aligned_u32 *x)
{
    return ((uint32_t) x->hi << 16) | x->lo;
}

/* Stores 'value' in 'x'. */
static inline void
put_16aligned_u32(ovs_16aligned_u32 *x, uint32_t value)
{
    x->hi = value >> 16;
    x->lo = value;
}

/* Returns the value in 'x'. */
static inline uint64_t
get_32aligned_u64(const ovs_32aligned_u64 *x)
{
    return ((uint64_t) x->hi << 32) | x->lo;
}

/* Stores 'value' in 'x'. */
static inline void
put_32aligned_u64(ovs_32aligned_u64 *x, uint64_t value)
{
    x->hi = value >> 32;
    x->lo = value;
}

/* Returns the value in 'x'. */
static inline ovs_u128
get_32aligned_u128(const ovs_32aligned_u128 *x)
{
    ovs_u128 u = { .u32 = { x->u32[0], x->u32[1], x->u32[2], x->u32[3] } };
    return u;
}

/* Stores 'value' in 'x'. */
static inline void
put_32aligned_u128(ovs_32aligned_u128 *x, ovs_u128 value)
{
    x->u32[0] = value.u32[0];
    x->u32[1] = value.u32[1];
    x->u32[2] = value.u32[2];
    x->u32[3] = value.u32[3];
}

#ifndef __CHECKER__
/* Returns the value of 'x'. */
static inline ovs_be32
get_16aligned_be32(const ovs_16aligned_be32 *x)
{
#ifdef WORDS_BIGENDIAN
    return ((ovs_be32) x->hi << 16) | x->lo;
#else
    return ((ovs_be32) x->lo << 16) | x->hi;
#endif
}

/* Stores network byte order 'value' into 'x'. */
static inline void
put_16aligned_be32(ovs_16aligned_be32 *x, ovs_be32 value)
{
#if WORDS_BIGENDIAN
    x->hi = value >> 16;
    x->lo = value;
#else
    x->hi = value;
    x->lo = value >> 16;
#endif
}

/* Returns the value of 'x'. */
static inline ovs_be64
get_32aligned_be64(const ovs_32aligned_be64 *x)
{
#ifdef WORDS_BIGENDIAN
    return ((ovs_be64) x->hi << 32) | x->lo;
#else
    return ((ovs_be64) x->lo << 32) | x->hi;
#endif
}

/* Stores network byte order 'value' into 'x'. */
static inline void
put_32aligned_be64(ovs_32aligned_be64 *x, ovs_be64 value)
{
#if WORDS_BIGENDIAN
    x->hi = value >> 32;
    x->lo = value;
#else
    x->hi = value;
    x->lo = value >> 32;
#endif
}

/* Returns the value of 'x'. */
static inline ovs_be128
get_32aligned_be128(const ovs_32aligned_be128 *x)
{
    ovs_be128 u = { .be32 = { x->be32[0], x->be32[1],
                              x->be32[2], x->be32[3] } };
    return u;
}

/* Stores network byte order 'value' into 'x'. */
static inline void
put_32aligned_be128(ovs_32aligned_be128 *x, ovs_be128 value)
{
    x->be32[0] = value.be32[0];
    x->be32[1] = value.be32[1];
    x->be32[2] = value.be32[2];
    x->be32[3] = value.be32[3];
}
#else  /* __CHECKER__ */
/* Making sparse happy with these functions also makes them unreadable, so
 * don't bother to show it their implementations. */
ovs_be32 get_16aligned_be32(const ovs_16aligned_be32 *);
void put_16aligned_be32(ovs_16aligned_be32 *, ovs_be32);
ovs_be64 get_32aligned_be64(const ovs_32aligned_be64 *);
void put_32aligned_be64(ovs_32aligned_be64 *, ovs_be64);
ovs_be128 get_32aligned_be128(const ovs_32aligned_be128 *);
void put_32aligned_be128(ovs_32aligned_be128 *, ovs_be128);
#endif

#endif /* unaligned.h */
