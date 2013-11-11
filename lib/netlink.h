/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
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

#ifndef NETLINK_H
#define NETLINK_H 1

/* Netlink message helpers.
 *
 * Netlink is a datagram-based network protocol primarily for communication
 * between user processes and the kernel, and mainly on Linux.  Netlink is
 * specified in RFC 3549, "Linux Netlink as an IP Services Protocol".
 *
 * Netlink is not suitable for use in physical networks of heterogeneous
 * machines because host byte order is used throughout.
 *
 * This header file defines helper functions for working with Netlink messages.
 * For Netlink protocol definitions, see netlink-protocol.h.  For
 * Linux-specific definitions for Netlink sockets, see netlink-socket.h.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "netlink-protocol.h"
#include "openvswitch/types.h"

struct ofpbuf;
struct nlattr;

/* Accessing headers and data. */
struct nlmsghdr *nl_msg_nlmsghdr(const struct ofpbuf *);
struct genlmsghdr *nl_msg_genlmsghdr(const struct ofpbuf *);
bool nl_msg_nlmsgerr(const struct ofpbuf *, int *error);
void nl_msg_reserve(struct ofpbuf *, size_t);

/* Appending and prepending headers and raw data. */
void nl_msg_put_nlmsghdr(struct ofpbuf *, size_t expected_payload,
                         uint32_t type, uint32_t flags);
void nl_msg_put_genlmsghdr(struct ofpbuf *, size_t expected_payload,
                           int family, uint32_t flags,
                           uint8_t cmd, uint8_t version);
void nl_msg_put(struct ofpbuf *, const void *, size_t);
void *nl_msg_put_uninit(struct ofpbuf *, size_t);
void nl_msg_push(struct ofpbuf *, const void *, size_t);
void *nl_msg_push_uninit(struct ofpbuf *, size_t);

/* Appending attributes. */
void *nl_msg_put_unspec_uninit(struct ofpbuf *, uint16_t type, size_t);
void *nl_msg_put_unspec_zero(struct ofpbuf *, uint16_t type, size_t);
void nl_msg_put_unspec(struct ofpbuf *, uint16_t type, const void *, size_t);
void nl_msg_put_flag(struct ofpbuf *, uint16_t type);
void nl_msg_put_u8(struct ofpbuf *, uint16_t type, uint8_t value);
void nl_msg_put_u16(struct ofpbuf *, uint16_t type, uint16_t value);
void nl_msg_put_u32(struct ofpbuf *, uint16_t type, uint32_t value);
void nl_msg_put_u64(struct ofpbuf *, uint16_t type, uint64_t value);
void nl_msg_put_be16(struct ofpbuf *, uint16_t type, ovs_be16 value);
void nl_msg_put_be32(struct ofpbuf *, uint16_t type, ovs_be32 value);
void nl_msg_put_be64(struct ofpbuf *, uint16_t type, ovs_be64 value);
void nl_msg_put_odp_port(struct ofpbuf *, uint16_t type, odp_port_t value);
void nl_msg_put_string(struct ofpbuf *, uint16_t type, const char *value);

size_t nl_msg_start_nested(struct ofpbuf *, uint16_t type);
void nl_msg_end_nested(struct ofpbuf *, size_t offset);
void nl_msg_put_nested(struct ofpbuf *, uint16_t type,
                       const void *data, size_t size);

/* Prepending attributes. */
void *nl_msg_push_unspec_uninit(struct ofpbuf *, uint16_t type, size_t);
void nl_msg_push_unspec(struct ofpbuf *, uint16_t type, const void *, size_t);
void nl_msg_push_flag(struct ofpbuf *, uint16_t type);
void nl_msg_push_u8(struct ofpbuf *, uint16_t type, uint8_t value);
void nl_msg_push_u16(struct ofpbuf *, uint16_t type, uint16_t value);
void nl_msg_push_u32(struct ofpbuf *, uint16_t type, uint32_t value);
void nl_msg_push_u64(struct ofpbuf *, uint16_t type, uint64_t value);
void nl_msg_push_be16(struct ofpbuf *, uint16_t type, ovs_be16 value);
void nl_msg_push_be32(struct ofpbuf *, uint16_t type, ovs_be32 value);
void nl_msg_push_be64(struct ofpbuf *, uint16_t type, ovs_be64 value);
void nl_msg_push_string(struct ofpbuf *, uint16_t type, const char *value);

/* Separating buffers into individual messages. */
struct nlmsghdr *nl_msg_next(struct ofpbuf *buffer, struct ofpbuf *msg);

/* Sizes of various attribute types, in bytes, including the attribute header
 * and padding. */
#define NL_ATTR_SIZE(PAYLOAD_SIZE) (NLA_HDRLEN + NLA_ALIGN(PAYLOAD_SIZE))
#define NL_A_U8_SIZE   NL_ATTR_SIZE(sizeof(uint8_t))
#define NL_A_U16_SIZE  NL_ATTR_SIZE(sizeof(uint16_t))
#define NL_A_U32_SIZE  NL_ATTR_SIZE(sizeof(uint32_t))
#define NL_A_U64_SIZE  NL_ATTR_SIZE(sizeof(uint64_t))
#define NL_A_BE16_SIZE NL_ATTR_SIZE(sizeof(ovs_be16))
#define NL_A_BE32_SIZE NL_ATTR_SIZE(sizeof(ovs_be32))
#define NL_A_BE64_SIZE NL_ATTR_SIZE(sizeof(ovs_be64))
#define NL_A_FLAG_SIZE NL_ATTR_SIZE(0)

bool nl_attr_oversized(size_t payload_size);

/* Netlink attribute types. */
enum nl_attr_type
{
    NL_A_NO_ATTR = 0,
    NL_A_UNSPEC,
    NL_A_U8,
    NL_A_U16,
    NL_A_BE16 = NL_A_U16,
    NL_A_U32,
    NL_A_BE32 = NL_A_U32,
    NL_A_U64,
    NL_A_BE64 = NL_A_U64,
    NL_A_STRING,
    NL_A_FLAG,
    NL_A_NESTED,
    N_NL_ATTR_TYPES
};

/* Netlink attribute iteration. */
static inline struct nlattr *
nl_attr_next(const struct nlattr *nla)
{
    return (void *) ((uint8_t *) nla + NLA_ALIGN(nla->nla_len));
}

static inline bool
nl_attr_is_valid(const struct nlattr *nla, size_t maxlen)
{
    return (maxlen >= sizeof *nla
            && nla->nla_len >= sizeof *nla
            && nla->nla_len <= maxlen);
}

static inline size_t
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
         (LEFT) -= nl_attr_len_pad(ITER, LEFT), (ITER) = nl_attr_next(ITER))

/* These variants are convenient for iterating nested attributes. */
#define NL_NESTED_FOR_EACH(ITER, LEFT, A)                               \
    NL_ATTR_FOR_EACH(ITER, LEFT, nl_attr_get(A), nl_attr_get_size(A))
#define NL_NESTED_FOR_EACH_UNSAFE(ITER, LEFT, A)                        \
    NL_ATTR_FOR_EACH_UNSAFE(ITER, LEFT, nl_attr_get(A), nl_attr_get_size(A))

/* Netlink attribute parsing. */
int nl_attr_type(const struct nlattr *);
const void *nl_attr_get(const struct nlattr *);
size_t nl_attr_get_size(const struct nlattr *);
const void *nl_attr_get_unspec(const struct nlattr *, size_t size);
bool nl_attr_get_flag(const struct nlattr *);
uint8_t nl_attr_get_u8(const struct nlattr *);
uint16_t nl_attr_get_u16(const struct nlattr *);
uint32_t nl_attr_get_u32(const struct nlattr *);
uint64_t nl_attr_get_u64(const struct nlattr *);
ovs_be16 nl_attr_get_be16(const struct nlattr *);
ovs_be32 nl_attr_get_be32(const struct nlattr *);
ovs_be64 nl_attr_get_be64(const struct nlattr *);
odp_port_t nl_attr_get_odp_port(const struct nlattr *);
const char *nl_attr_get_string(const struct nlattr *);
void nl_attr_get_nested(const struct nlattr *, struct ofpbuf *);

/* Netlink attribute policy.
 *
 * Specifies how to parse a single attribute from a Netlink message payload.
 */
struct nl_policy
{
    enum nl_attr_type type;
    size_t min_len, max_len;
    bool optional;
};

#define NL_POLICY_FOR(TYPE) \
    .type = NL_A_UNSPEC, .min_len = sizeof(TYPE), .max_len = sizeof(TYPE)

bool nl_attr_validate(const struct nlattr *, const struct nl_policy *);

bool nl_policy_parse(const struct ofpbuf *, size_t offset,
                     const struct nl_policy[],
                     struct nlattr *[], size_t n_attrs);
bool nl_parse_nested(const struct nlattr *, const struct nl_policy[],
                     struct nlattr *[], size_t n_attrs);

const struct nlattr *nl_attr_find(const struct ofpbuf *, size_t hdr_len,
                                  uint16_t type);
const struct nlattr *nl_attr_find_nested(const struct nlattr *, uint16_t type);
const struct nlattr *nl_attr_find__(const struct nlattr *attrs, size_t size,
                                    uint16_t type);

#endif /* netlink.h */
