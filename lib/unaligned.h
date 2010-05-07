/*
 * Copyright (c) 2010 Nicira Networks.
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
#include "xtoxll.h"

/* Public API. */
static inline uint16_t get_unaligned_u16(const uint16_t *);
static inline uint32_t get_unaligned_u32(const uint32_t *);
static inline uint64_t get_unaligned_u64(const uint64_t *);
static inline void put_unaligned_u16(uint16_t *, uint16_t);
static inline void put_unaligned_u32(uint32_t *, uint32_t);
static inline void put_unaligned_u64(uint64_t *, uint64_t);

#ifdef __GNUC__
/* GCC implementations. */
#define GCC_UNALIGNED_ACCESSORS(SIZE)                       \
struct unaligned_u##SIZE {                                  \
    uint##SIZE##_t x __attribute__((__packed__));           \
};                                                          \
static inline struct unaligned_u##SIZE *                    \
unaligned_u##SIZE(const uint##SIZE##_t *p)                  \
{                                                           \
    return (struct unaligned_u##SIZE *) p;                  \
}                                                           \
                                                            \
static inline uint##SIZE##_t                                \
get_unaligned_u##SIZE(const uint##SIZE##_t *p)              \
{                                                           \
    return unaligned_u##SIZE(p)->x;                         \
}                                                           \
                                                            \
static inline void                                          \
put_unaligned_u##SIZE(uint##SIZE##_t *p, uint##SIZE##_t x)  \
{                                                           \
    unaligned_u##SIZE(p)->x = x;                            \
}

GCC_UNALIGNED_ACCESSORS(16);
GCC_UNALIGNED_ACCESSORS(32);
GCC_UNALIGNED_ACCESSORS(64);
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

static inline uint64_t get_unaligned_u64(const uint64_t *p_)
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

static inline void put_unaligned_u64(uint64_t *p_, uint64_t x_)
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
#endif

#endif /* unaligned.h */
