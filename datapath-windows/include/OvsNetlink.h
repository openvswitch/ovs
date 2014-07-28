/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2014 Nicira, Inc.
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

#ifndef __OVS_NETLINK_H_
#define __OVS_NETLINK_H_ 1

#include "lib/netlink-protocol.h"

/* Returns X / Y, rounding up.  X must be nonnegative to round correctly. */
#define DIV_ROUND_UP(X, Y) (((X) + ((Y) - 1)) / (Y))

/* Returns X rounded up to the nearest multiple of Y. */
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))

static __inline int
nl_attr_is_valid(const struct nlattr *nla, size_t maxlen)
{
    return (maxlen >= sizeof *nla
            && nla->nla_len >= sizeof *nla
            && nla->nla_len <= maxlen);
}

static __inline size_t
nl_attr_len_pad(const struct nlattr *nla, size_t maxlen)
{
    size_t len = NLA_ALIGN(nla->nla_len);

    return len <= maxlen ? len : nla->nla_len;
}

/* This macro is careful to check for attributes with bad lengths. */
#define NL_ATTR_FOR_EACH(ITER, LEFT, ATTRS, ATTRS_LEN)                  \
    for ((ITER) = (ATTRS), (LEFT) = (ATTRS_LEN);                        \
         nl_attr_is_valid(ITER, LEFT);                                  \
         (LEFT) -= nl_attr_len_pad(ITER, LEFT), (ITER) = nl_attr_next(ITER))

/* This macro does not check for attributes with bad lengths.  It should only
 * be used with messages from trusted sources or with messages that have
 * already been validated (e.g. with NL_ATTR_FOR_EACH).  */
#define NL_ATTR_FOR_EACH_UNSAFE(ITER, LEFT, ATTRS, ATTRS_LEN)           \
    for ((ITER) = (ATTRS), (LEFT) = (ATTRS_LEN);                        \
         (LEFT) > 0;                                                    \
         (LEFT) -= NLA_ALIGN((ITER)->nla_len), (ITER) = nl_attr_next(ITER))

/* These were introduced all together in 2.6.24. */
#ifndef NLA_TYPE_MASK
#define NLA_F_NESTED        (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK       ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
#endif

/* Netlink attribute iteration. */
static __inline struct nlattr *
nl_attr_next(const struct nlattr *nla)
{
    return (struct nlattr *) ((uint8_t *) nla + NLA_ALIGN(nla->nla_len));
}

 /* Returns the bits of 'nla->nla_type' that are significant for determining
  * its type. */
static __inline int
nl_attr_type(const struct nlattr *nla)
{
   return nla->nla_type & NLA_TYPE_MASK;
}

static __inline void *
nl_attr_data(const struct nlattr *nla)
{
    return ((char *)nla + NLA_HDRLEN);
}

/* Returns the number of bytes in the payload of attribute 'nla'. */
static __inline uint32_t
nl_attr_get_size(const struct nlattr *nla)
{
    return nla->nla_len - NLA_HDRLEN;
}

/* Returns the first byte in the payload of attribute 'nla'. */
static __inline const void *
nl_attr_get(const struct nlattr *nla)
{
    ASSERT(nla->nla_len >= NLA_HDRLEN);
    return nla + 1;
}

#define NL_ATTR_GET_AS(NLA, TYPE) \
        (*(TYPE*) nl_attr_get_unspec(nla, sizeof(TYPE)))

/* Asserts that 'nla''s payload is at least 'size' bytes long, and returns the
 * first byte of the payload. */
static const void *
nl_attr_get_unspec(const struct nlattr *nla, size_t size)
{
    DBG_UNREFERENCED_PARAMETER(size);
    ASSERT(nla->nla_len >= NLA_HDRLEN + size);
    return nla + 1;
}

/* Returns the 64-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 8 bytes long. */
static __inline __be64
nl_attr_get_be64(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, __be64);
}

/* Returns the 32-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 4 bytes long. */
static __inline __be32
nl_attr_get_be32(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, __be32);
}

/* Returns the 8-bit value in 'nla''s payload. */
static __inline uint8_t
nl_attr_get_u8(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, uint8_t);
}


/* Returns the 32-bit host byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 4 bytes long. */
static __inline uint32_t
nl_attr_get_u32(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, uint32_t);
}


static __inline const struct nlattr *
nl_attr_find__(const struct nlattr *attrs, size_t size, uint16_t type)
{
    const struct nlattr *nla;
    size_t left;

    NL_ATTR_FOR_EACH (nla, left, attrs, size) {
        if (nl_attr_type(nla) == type) {
            return nla;
        }
    }
    return NULL;
}

/* Returns the first Netlink attribute within 'nla' with the specified
 * 'type'.
 *
 * This function does not validate the attribute's length. */
static __inline const struct nlattr *
nl_attr_find_nested(const struct nlattr *nla, uint16_t type)
{
    return nl_attr_find__(nl_attr_get(nla), nl_attr_get_size(nla), type);
}

#endif /* __OVS_NETLINK_H_ */
