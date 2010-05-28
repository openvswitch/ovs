/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

/* Netlink interface.
 *
 * Netlink is a datagram-based network protocol primarily for communication
 * between user processes and the kernel, and mainly on Linux.  Netlink is
 * specified in RFC 3549, "Linux Netlink as an IP Services Protocol".
 *
 * Netlink is not suitable for use in physical networks of heterogeneous
 * machines because host byte order is used throughout. */

#include <stdbool.h>
#include <sys/uio.h>
#include <stdint.h>

struct ofpbuf;
struct nl_sock;
struct nlattr;

/* Netlink sockets. */

int nl_sock_create(int protocol, int multicast_group,
                   size_t so_sndbuf, size_t so_rcvbuf,
                   struct nl_sock **);
void nl_sock_destroy(struct nl_sock *);

int nl_sock_send(struct nl_sock *, const struct ofpbuf *, bool wait);
int nl_sock_sendv(struct nl_sock *sock, const struct iovec iov[], size_t n_iov,
                  bool wait);
int nl_sock_recv(struct nl_sock *, struct ofpbuf **, bool wait);
int nl_sock_transact(struct nl_sock *, const struct ofpbuf *request,
                     struct ofpbuf **reply);

void nl_sock_wait(const struct nl_sock *, short int events);

/* Table dumping. */
struct nl_dump {
    struct nl_sock *sock;       /* Socket being dumped. */
    uint32_t seq;               /* Expected nlmsg_seq for replies. */
    struct ofpbuf *buffer;      /* Receive buffer currently being iterated. */
    int status;                 /* 0=OK, EOF=done, or positive errno value. */
};

void nl_dump_start(struct nl_dump *, struct nl_sock *,
                   const struct ofpbuf *request);
bool nl_dump_next(struct nl_dump *, struct ofpbuf *reply);
int nl_dump_done(struct nl_dump *);

/* Netlink messages. */

/* Accessing headers and data. */
struct nlmsghdr *nl_msg_nlmsghdr(const struct ofpbuf *);
struct genlmsghdr *nl_msg_genlmsghdr(const struct ofpbuf *);
bool nl_msg_nlmsgerr(const struct ofpbuf *, int *error);
void nl_msg_reserve(struct ofpbuf *, size_t);

/* Appending headers and raw data. */
void nl_msg_put_nlmsghdr(struct ofpbuf *, size_t expected_payload,
                         uint32_t type, uint32_t flags);
void nl_msg_put_genlmsghdr(struct ofpbuf *, size_t expected_payload,
                           int family, uint32_t flags,
                           uint8_t cmd, uint8_t version);
void nl_msg_put(struct ofpbuf *, const void *, size_t);
void *nl_msg_put_uninit(struct ofpbuf *, size_t);

/* Appending attributes. */
void *nl_msg_put_unspec_uninit(struct ofpbuf *, uint16_t type, size_t);
void nl_msg_put_unspec(struct ofpbuf *, uint16_t type, const void *, size_t);
void nl_msg_put_flag(struct ofpbuf *, uint16_t type);
void nl_msg_put_u8(struct ofpbuf *, uint16_t type, uint8_t value);
void nl_msg_put_u16(struct ofpbuf *, uint16_t type, uint16_t value);
void nl_msg_put_u32(struct ofpbuf *, uint16_t type, uint32_t value);
void nl_msg_put_u64(struct ofpbuf *, uint16_t type, uint64_t value);
void nl_msg_put_string(struct ofpbuf *, uint16_t type, const char *value);

size_t nl_msg_start_nested(struct ofpbuf *, uint16_t type);
void nl_msg_end_nested(struct ofpbuf *, size_t offset);
void nl_msg_put_nested(struct ofpbuf *, uint16_t type,
                       const void *data, size_t size);

/* Separating buffers into individual messages. */
struct nlmsghdr *nl_msg_next(struct ofpbuf *buffer, struct ofpbuf *msg);

/* Netlink attribute types. */
enum nl_attr_type
{
    NL_A_NO_ATTR = 0,
    NL_A_UNSPEC,
    NL_A_U8,
    NL_A_U16,
    NL_A_U32,
    NL_A_U64,
    NL_A_STRING,
    NL_A_FLAG,
    NL_A_NESTED,
    N_NL_ATTR_TYPES
};

/* Netlink attribute parsing. */
const void *nl_attr_get(const struct nlattr *);
size_t nl_attr_get_size(const struct nlattr *);
const void *nl_attr_get_unspec(const struct nlattr *, size_t size);
bool nl_attr_get_flag(const struct nlattr *);
uint8_t nl_attr_get_u8(const struct nlattr *);
uint16_t nl_attr_get_u16(const struct nlattr *);
uint32_t nl_attr_get_u32(const struct nlattr *);
uint64_t nl_attr_get_u64(const struct nlattr *);
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

bool nl_policy_parse(const struct ofpbuf *, size_t offset,
                     const struct nl_policy[],
                     struct nlattr *[], size_t n_attrs);
bool nl_parse_nested(const struct nlattr *, const struct nl_policy[],
                     struct nlattr *[], size_t n_attrs);

/* Miscellaneous. */

int nl_lookup_genl_family(const char *name, int *number);

#endif /* netlink.h */
