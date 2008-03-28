/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * 
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
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
#include <stdint.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/version.h>

#ifndef NLA_ALIGNTO
struct nlattr
{
    __u16           nla_len;
    __u16           nla_type;
};

#define NLA_ALIGNTO     4
#define NLA_ALIGN(len)      (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN      ((int) NLA_ALIGN(sizeof(struct nlattr)))

#endif 

struct buffer;
struct nl_sock;

/* Netlink sockets. */

int nl_sock_create(int protocol, int multicast_group,
                   size_t so_sndbuf, size_t so_rcvbuf,
                   struct nl_sock **);
void nl_sock_destroy(struct nl_sock *);

int nl_sock_send(struct nl_sock *, const struct buffer *, bool wait);
int nl_sock_sendv(struct nl_sock *sock, const struct iovec iov[], size_t n_iov,
                  bool wait);
int nl_sock_recv(struct nl_sock *, struct buffer **, bool wait);
int nl_sock_transact(struct nl_sock *, const struct buffer *request,
                     struct buffer **reply);

int nl_sock_fd(const struct nl_sock *);

/* Netlink messages. */

/* Accessing headers and data. */
struct nlmsghdr *nl_msg_nlmsghdr(const struct buffer *);
struct genlmsghdr *nl_msg_genlmsghdr(const struct buffer *);
bool nl_msg_nlmsgerr(const struct buffer *, int *error);
void nl_msg_reserve(struct buffer *, size_t);

/* Appending headers and raw data. */
void nl_msg_put_nlmsghdr(struct buffer *, struct nl_sock *,
                         size_t expected_payload,
                         uint32_t type, uint32_t flags);
void nl_msg_put_genlmsghdr(struct buffer *, struct nl_sock *,
                           size_t expected_payload, int family, uint32_t flags,
                           uint8_t cmd, uint8_t version);
void nl_msg_put(struct buffer *, const void *, size_t);
void *nl_msg_put_uninit(struct buffer *, size_t);

/* Appending attributes. */
void *nl_msg_put_unspec_uninit(struct buffer *, uint16_t type, size_t);
void nl_msg_put_unspec(struct buffer *, uint16_t type, const void *, size_t);
void nl_msg_put_flag(struct buffer *, uint16_t type);
void nl_msg_put_u8(struct buffer *, uint16_t type, uint8_t value);
void nl_msg_put_u16(struct buffer *, uint16_t type, uint16_t value);
void nl_msg_put_u32(struct buffer *, uint16_t type, uint32_t value);
void nl_msg_put_u64(struct buffer *, uint16_t type, uint64_t value);
void nl_msg_put_string(struct buffer *, uint16_t type, const char *value);
void nl_msg_put_nested(struct buffer *, uint16_t type, struct buffer *);

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
const void* nl_attr_get(const struct nlattr *);
size_t nl_attr_get_size(const struct nlattr *);
const void* nl_attr_get_unspec(const struct nlattr *, size_t size);
bool nl_attr_get_flag(const struct nlattr *);
uint8_t nl_attr_get_u8(const struct nlattr *);
uint16_t nl_attr_get_u16(const struct nlattr *);
uint32_t nl_attr_get_u32(const struct nlattr *);
uint64_t nl_attr_get_u64(const struct nlattr *);
const char *nl_attr_get_string(const struct nlattr *);

/* Netlink attribute policy.
 *
 * Specifies how to parse a single attribute from a Netlink message payload.
 *
 * See Nl_policy for example.
 */
struct nl_policy
{
    enum nl_attr_type type;
    size_t min_len, max_len;
    bool optional;
};

bool nl_policy_parse(const struct buffer *, const struct nl_policy[],
                     struct nlattr *[], size_t n_attrs);

/* Miscellaneous. */

int nl_lookup_genl_family(const char *name, int *number);

#endif /* netlink.h */
