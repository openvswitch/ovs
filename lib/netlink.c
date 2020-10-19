/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015 Nicira, Inc.
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

#include <config.h>
#include "netlink.h"
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unistd.h>
#include "coverage.h"
#include "flow.h"
#include "netlink-protocol.h"
#include "openvswitch/ofpbuf.h"
#include "timeval.h"
#include "unaligned.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(netlink);

/* A single (bad) Netlink message can in theory dump out many, many log
 * messages, so the burst size is set quite high here to avoid missing useful
 * information.  Also, at high logging levels we log *all* Netlink messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 600);

/* Returns the nlmsghdr at the head of 'msg'.
 *
 * 'msg' must be at least as large as a nlmsghdr. */
struct nlmsghdr *
nl_msg_nlmsghdr(const struct ofpbuf *msg)
{
    return ofpbuf_at_assert(msg, 0, NLMSG_HDRLEN);
}

/* Returns the genlmsghdr just past 'msg''s nlmsghdr.
 *
 * Returns a null pointer if 'msg' is not large enough to contain an nlmsghdr
 * and a genlmsghdr. */
struct genlmsghdr *
nl_msg_genlmsghdr(const struct ofpbuf *msg)
{
    return ofpbuf_at(msg, NLMSG_HDRLEN, GENL_HDRLEN);
}

/* If 'buffer' is a NLMSG_ERROR message, stores 0 in '*errorp' if it is an ACK
 * message, otherwise a positive errno value, and returns true.  If 'buffer' is
 * not an NLMSG_ERROR message, returns false.
 *
 * 'msg' must be at least as large as a nlmsghdr. */
bool
nl_msg_nlmsgerr(const struct ofpbuf *msg, int *errorp)
{
    if (nl_msg_nlmsghdr(msg)->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = ofpbuf_at(msg, NLMSG_HDRLEN, sizeof *err);
        int code = EPROTO;
        if (!err) {
            VLOG_ERR_RL(&rl, "received invalid nlmsgerr (%"PRIu32" bytes < %"PRIuSIZE")",
                        msg->size, NLMSG_HDRLEN + sizeof *err);
        } else if (err->error <= 0 && err->error > INT_MIN) {
            code = -err->error;
        }
        if (errorp) {
            *errorp = code;
        }
        return true;
    } else {
        return false;
    }
}

/* Ensures that 'b' has room for at least 'size' bytes plus netlink padding at
 * its tail end, reallocating and copying its data if necessary. */
void
nl_msg_reserve(struct ofpbuf *msg, size_t size)
{
    ofpbuf_prealloc_tailroom(msg, NLMSG_ALIGN(size));
}

/* Puts a nlmsghdr at the beginning of 'msg', which must be initially empty.
 * Uses the given 'type' and 'flags'.  'expected_payload' should be
 * an estimate of the number of payload bytes to be supplied; if the size of
 * the payload is unknown a value of 0 is acceptable.
 *
 * 'type' is ordinarily an enumerated value specific to the Netlink protocol
 * (e.g. RTM_NEWLINK, for NETLINK_ROUTE protocol).  For Generic Netlink, 'type'
 * is the family number obtained via nl_lookup_genl_family().
 *
 * 'flags' is a bit-mask that indicates what kind of request is being made.  It
 * is often NLM_F_REQUEST indicating that a request is being made, commonly
 * or'd with NLM_F_ACK to request an acknowledgement.
 *
 * Sets the new nlmsghdr's nlmsg_len, nlmsg_seq, and nlmsg_pid fields to 0 for
 * now.  Functions that send Netlink messages will fill these in just before
 * sending the message.
 *
 * nl_msg_put_genlmsghdr() is more convenient for composing a Generic Netlink
 * message. */
void
nl_msg_put_nlmsghdr(struct ofpbuf *msg,
                    size_t expected_payload, uint32_t type, uint32_t flags)
{
    struct nlmsghdr *nlmsghdr;

    ovs_assert(msg->size == 0);

    nl_msg_reserve(msg, NLMSG_HDRLEN + expected_payload);
    nlmsghdr = nl_msg_put_uninit(msg, NLMSG_HDRLEN);
    nlmsghdr->nlmsg_len = 0;
    nlmsghdr->nlmsg_type = type;
    nlmsghdr->nlmsg_flags = flags;
    nlmsghdr->nlmsg_seq = 0;
    nlmsghdr->nlmsg_pid = 0;
}

/* Puts a nlmsghdr and genlmsghdr at the beginning of 'msg', which must be
 * initially empty.  'expected_payload' should be an estimate of the number of
 * payload bytes to be supplied; if the size of the payload is unknown a value
 * of 0 is acceptable.
 *
 * 'family' is the family number obtained via nl_lookup_genl_family().
 *
 * 'flags' is a bit-mask that indicates what kind of request is being made.  It
 * is often NLM_F_REQUEST indicating that a request is being made, commonly
 * or'd with NLM_F_ACK to request an acknowledgement.
 *
 * 'cmd' is an enumerated value specific to the Generic Netlink family
 * (e.g. CTRL_CMD_NEWFAMILY for the GENL_ID_CTRL family).
 *
 * 'version' is a version number specific to the family and command (often 1).
 *
 * Sets the new nlmsghdr's nlmsg_pid field to 0 for now.  nl_sock_send() will
 * fill it in just before sending the message.
 *
 * nl_msg_put_nlmsghdr() should be used to compose Netlink messages that are
 * not Generic Netlink messages. */
void
nl_msg_put_genlmsghdr(struct ofpbuf *msg, size_t expected_payload,
                      int family, uint32_t flags, uint8_t cmd, uint8_t version)
{
    struct genlmsghdr *genlmsghdr;

    nl_msg_put_nlmsghdr(msg, GENL_HDRLEN + expected_payload, family, flags);
    ovs_assert(msg->size == NLMSG_HDRLEN);
    genlmsghdr = nl_msg_put_uninit(msg, GENL_HDRLEN);
    genlmsghdr->cmd = cmd;
    genlmsghdr->version = version;
    genlmsghdr->reserved = 0;
}

/* Appends the 'size' bytes of data in 'p', plus Netlink padding if needed, to
 * the tail end of 'msg'.  Data in 'msg' is reallocated and copied if
 * necessary. */
void
nl_msg_put(struct ofpbuf *msg, const void *data, size_t size)
{
    memcpy(nl_msg_put_uninit(msg, size), data, size);
}

/* Appends 'size' bytes of data, plus Netlink padding if needed, to the tail
 * end of 'msg', reallocating and copying its data if necessary.  Returns a
 * pointer to the first byte of the new data, which is left uninitialized. */
void *
nl_msg_put_uninit(struct ofpbuf *msg, size_t size)
{
    size_t pad = PAD_SIZE(size, NLMSG_ALIGNTO);
    char *p = ofpbuf_put_uninit(msg, size + pad);
    if (pad) {
        memset(p + size, 0, pad);
    }
    return p;
}

/* Prepends the 'size' bytes of data in 'p', plus Netlink padding if needed, to
 * the head end of 'msg'.  Data in 'msg' is reallocated and copied if
 * necessary. */
void
nl_msg_push(struct ofpbuf *msg, const void *data, size_t size)
{
    memcpy(nl_msg_push_uninit(msg, size), data, size);
}

/* Prepends 'size' bytes of data, plus Netlink padding if needed, to the head
 * end of 'msg', reallocating and copying its data if necessary.  Returns a
 * pointer to the first byte of the new data, which is left uninitialized. */
void *
nl_msg_push_uninit(struct ofpbuf *msg, size_t size)
{
    size_t pad = PAD_SIZE(size, NLMSG_ALIGNTO);
    char *p = ofpbuf_push_uninit(msg, size + pad);
    if (pad) {
        memset(p + size, 0, pad);
    }
    return p;
}

/* Appends a Netlink attribute of the given 'type' and room for 'size' bytes of
 * data as its payload, plus Netlink padding if needed, to the tail end of
 * 'msg', reallocating and copying its data if necessary.  Returns a pointer to
 * the first byte of data in the attribute, which is left uninitialized. */
void *
nl_msg_put_unspec_uninit(struct ofpbuf *msg, uint16_t type, size_t size)
{
    size_t total_size = NLA_HDRLEN + size;
    struct nlattr* nla = nl_msg_put_uninit(msg, total_size);
    ovs_assert(!nl_attr_oversized(size));
    nla->nla_len = total_size;
    nla->nla_type = type;
    return nla + 1;
}

/* Appends a Netlink attribute of the given 'type' and room for 'size' bytes of
 * data as its payload, plus Netlink padding if needed, to the tail end of
 * 'msg', reallocating and copying its data if necessary.  Returns a pointer to
 * the first byte of data in the attribute, which is zeroed. */
void *
nl_msg_put_unspec_zero(struct ofpbuf *msg, uint16_t type, size_t size)
{
    void *data = nl_msg_put_unspec_uninit(msg, type, size);
    memset(data, 0, size);
    return data;
}

/* Appends a Netlink attribute of the given 'type' and the 'size' bytes of
 * 'data' as its payload, to the tail end of 'msg', reallocating and copying
 * its data if necessary. */
void
nl_msg_put_unspec(struct ofpbuf *msg, uint16_t type,
                  const void *data, size_t size)
{
    void *ptr;

    ptr = nl_msg_put_unspec_uninit(msg, type, size);
    nullable_memcpy(ptr, data, size);
}

/* Appends a Netlink attribute of the given 'type' and no payload to 'msg'.
 * (Some Netlink protocols use the presence or absence of an attribute as a
 * Boolean flag.) */
void
nl_msg_put_flag(struct ofpbuf *msg, uint16_t type)
{
    nl_msg_put_unspec(msg, type, NULL, 0);
}

/* Appends a Netlink attribute of the given 'type' and the given 8-bit 'value'
 * to 'msg'. */
void
nl_msg_put_u8(struct ofpbuf *msg, uint16_t type, uint8_t value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given 16-bit host
 * byte order 'value' to 'msg'. */
void
nl_msg_put_u16(struct ofpbuf *msg, uint16_t type, uint16_t value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given 32-bit host
 * byte order 'value' to 'msg'. */
void
nl_msg_put_u32(struct ofpbuf *msg, uint16_t type, uint32_t value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given 64-bit host
 * byte order 'value' to 'msg'. */
void
nl_msg_put_u64(struct ofpbuf *msg, uint16_t type, uint64_t value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given 128-bit host
 * byte order 'value' to 'msg'. */
void
nl_msg_put_u128(struct ofpbuf *msg, uint16_t type, ovs_u128 value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given 16-bit network
 * byte order 'value' to 'msg'. */
void
nl_msg_put_be16(struct ofpbuf *msg, uint16_t type, ovs_be16 value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given 32-bit network
 * byte order 'value' to 'msg'. */
void
nl_msg_put_be32(struct ofpbuf *msg, uint16_t type, ovs_be32 value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given 64-bit network
 * byte order 'value' to 'msg'. */
void
nl_msg_put_be64(struct ofpbuf *msg, uint16_t type, ovs_be64 value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given 128-bit
 * network byte order 'value' to 'msg'. */
void
nl_msg_put_be128(struct ofpbuf *msg, uint16_t type, ovs_be128 value)
{
    nl_msg_put_unspec(msg, type, &value, sizeof value);
}

/* Appends a Netlink attribute of the given 'type' and the given IPv6
 * address order 'value' to 'msg'. */
void
nl_msg_put_in6_addr(struct ofpbuf *msg, uint16_t type,
                    const struct in6_addr *value)
{
    nl_msg_put_unspec(msg, type, value, sizeof *value);
}

/* Appends a Netlink attribute of the given 'type' and the given odp_port_t
 * 'value' to 'msg'. */
void
nl_msg_put_odp_port(struct ofpbuf *msg, uint16_t type, odp_port_t value)
{
    nl_msg_put_u32(msg, type, odp_to_u32(value));
}

/* Appends a Netlink attribute of the given 'type' with the 'len' characters
 * of 'value', followed by the null byte to 'msg'. */
void
nl_msg_put_string__(struct ofpbuf *msg, uint16_t type, const char *value,
                    size_t len)
{
    char *data = nl_msg_put_unspec_uninit(msg, type, len + 1);

    memcpy(data, value, len);
    data[len] = '\0';
}

/* Appends a Netlink attribute of the given 'type' and the given
 * null-terminated string 'value' to 'msg'. */
void
nl_msg_put_string(struct ofpbuf *msg, uint16_t type, const char *value)
{
    nl_msg_put_unspec(msg, type, value, strlen(value) + 1);
}

/* Prepends a Netlink attribute of the given 'type' and room for 'size' bytes
 * of data as its payload, plus Netlink padding if needed, to the head end of
 * 'msg', reallocating and copying its data if necessary.  Returns a pointer to
 * the first byte of data in the attribute, which is left uninitialized. */
void *
nl_msg_push_unspec_uninit(struct ofpbuf *msg, uint16_t type, size_t size)
{
    size_t total_size = NLA_HDRLEN + size;
    struct nlattr* nla = nl_msg_push_uninit(msg, total_size);
    ovs_assert(!nl_attr_oversized(size));
    nla->nla_len = total_size;
    nla->nla_type = type;
    return nla + 1;
}

/* Prepends a Netlink attribute of the given 'type' and the 'size' bytes of
 * 'data' as its payload, to the head end of 'msg', reallocating and copying
 * its data if necessary.  Returns a pointer to the first byte of data in the
 * attribute, which is left uninitialized. */
void
nl_msg_push_unspec(struct ofpbuf *msg, uint16_t type,
                  const void *data, size_t size)
{
    memcpy(nl_msg_push_unspec_uninit(msg, type, size), data, size);
}

/* Prepends a Netlink attribute of the given 'type' and no payload to 'msg'.
 * (Some Netlink protocols use the presence or absence of an attribute as a
 * Boolean flag.) */
void
nl_msg_push_flag(struct ofpbuf *msg, uint16_t type)
{
    nl_msg_push_unspec_uninit(msg, type, 0);
}

/* Prepends a Netlink attribute of the given 'type' and the given 8-bit 'value'
 * to 'msg'. */
void
nl_msg_push_u8(struct ofpbuf *msg, uint16_t type, uint8_t value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given 16-bit host
 * byte order 'value' to 'msg'. */
void
nl_msg_push_u16(struct ofpbuf *msg, uint16_t type, uint16_t value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given 32-bit host
 * byte order 'value' to 'msg'. */
void
nl_msg_push_u32(struct ofpbuf *msg, uint16_t type, uint32_t value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given 64-bit host
 * byte order 'value' to 'msg'. */
void
nl_msg_push_u64(struct ofpbuf *msg, uint16_t type, uint64_t value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given 128-bit host
 * byte order 'value' to 'msg'. */
void
nl_msg_push_u128(struct ofpbuf *msg, uint16_t type, ovs_u128 value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given 16-bit
 * network byte order 'value' to 'msg'. */
void
nl_msg_push_be16(struct ofpbuf *msg, uint16_t type, ovs_be16 value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given 32-bit
 * network byte order 'value' to 'msg'. */
void
nl_msg_push_be32(struct ofpbuf *msg, uint16_t type, ovs_be32 value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given 64-bit
 * network byte order 'value' to 'msg'. */
void
nl_msg_push_be64(struct ofpbuf *msg, uint16_t type, ovs_be64 value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given 128-bit
 * network byte order 'value' to 'msg'. */
void
nl_msg_push_be128(struct ofpbuf *msg, uint16_t type, ovs_be128 value)
{
    nl_msg_push_unspec(msg, type, &value, sizeof value);
}

/* Prepends a Netlink attribute of the given 'type' and the given
 * null-terminated string 'value' to 'msg'. */
void
nl_msg_push_string(struct ofpbuf *msg, uint16_t type, const char *value)
{
    nl_msg_push_unspec(msg, type, value, strlen(value) + 1);
}

/* Adds the header for nested Netlink attributes to 'msg', with the specified
 * 'type', and returns the header's offset within 'msg'.  The caller should add
 * the content for the nested Netlink attribute to 'msg' (e.g. using the other
 * nl_msg_*() functions), and then pass the returned offset to
 * nl_msg_end_nested() to finish up the nested attributes. */
size_t
nl_msg_start_nested(struct ofpbuf *msg, uint16_t type)
{
    size_t offset = msg->size;
    nl_msg_put_unspec_uninit(msg, type, 0);
    return offset;
}

/* Finalizes a nested Netlink attribute in 'msg'.  'offset' should be the value
 * returned by nl_msg_start_nested(). */
void
nl_msg_end_nested(struct ofpbuf *msg, size_t offset)
{
    struct nlattr *attr = ofpbuf_at_assert(msg, offset, sizeof *attr);
    ovs_assert(!nl_attr_oversized(msg->size - offset - NLA_HDRLEN));
    attr->nla_len = msg->size - offset;
}

/* Cancel a nested Netlink attribute in 'msg'.  'offset' should be the value
 * returned by nl_msg_start_nested(). */
void
nl_msg_cancel_nested(struct ofpbuf *msg, size_t offset)
{
    msg->size = offset;
}

/* Same as nls_msg_end_nested() when the nested Netlink contains non empty
 * message. Otherwise, drop the nested message header from 'msg'.
 *
 * Return true if the nested message has been dropped.  */
bool
nl_msg_end_non_empty_nested(struct ofpbuf *msg, size_t offset)
{
    nl_msg_end_nested(msg, offset);

    struct nlattr *attr = ofpbuf_at_assert(msg, offset, sizeof *attr);
    if (!nl_attr_get_size(attr)) {
        nl_msg_cancel_nested(msg, offset);
        return true;
    } else {
        return false;
    }
}

/* Appends a nested Netlink attribute of the given 'type', with the 'size'
 * bytes of content starting at 'data', to 'msg'. */
void
nl_msg_put_nested(struct ofpbuf *msg,
                  uint16_t type, const void *data, size_t size)
{
    size_t offset = nl_msg_start_nested(msg, type);
    nl_msg_put(msg, data, size);
    nl_msg_end_nested(msg, offset);
}

/* If 'buffer' begins with a valid "struct nlmsghdr", pulls the header and its
 * payload off 'buffer', stores header and payload in 'msg->data' and
 * 'msg->size', and returns a pointer to the header.
 *
 * If 'buffer' does not begin with a "struct nlmsghdr" or begins with one that
 * is invalid, returns NULL and clears 'buffer' and 'msg'. */
struct nlmsghdr *
nl_msg_next(struct ofpbuf *buffer, struct ofpbuf *msg)
{
    if (buffer->size >= sizeof(struct nlmsghdr)) {
        struct nlmsghdr *nlmsghdr = nl_msg_nlmsghdr(buffer);
        size_t len = nlmsghdr->nlmsg_len;
        if (len >= sizeof *nlmsghdr && len <= buffer->size) {
            ofpbuf_use_const(msg, nlmsghdr, len);
            ofpbuf_pull(buffer, len);
            return nlmsghdr;
        }
    }

    ofpbuf_clear(buffer);
    msg->data = NULL;
    msg->size = 0;
    return NULL;
}

/* Returns true if a Netlink attribute with a payload that is 'payload_size'
 * bytes long would be oversized, that is, if it's not possible to create an
 * nlattr of that size because its size wouldn't fit in the 16-bit nla_len
 * field. */
bool
nl_attr_oversized(size_t payload_size)
{
    return payload_size > UINT16_MAX - NLA_HDRLEN;
}

/* Attributes. */

/* Returns the bits of 'nla->nla_type' that are significant for determining its
 * type. */
int
nl_attr_type(const struct nlattr *nla)
{
    return nla->nla_type & NLA_TYPE_MASK;
}

/* Returns the first byte in the payload of attribute 'nla'. */
const void *
nl_attr_get(const struct nlattr *nla)
{
    ovs_assert(nla->nla_len >= NLA_HDRLEN);
    return nla + 1;
}

/* Returns the number of bytes in the payload of attribute 'nla'. */
size_t
nl_attr_get_size(const struct nlattr *nla)
{
    ovs_assert(nla->nla_len >= NLA_HDRLEN);
    return nla->nla_len - NLA_HDRLEN;
}

/* Asserts that 'nla''s payload is at least 'size' bytes long, and returns the
 * first byte of the payload. */
const void *
nl_attr_get_unspec(const struct nlattr *nla, size_t size)
{
    ovs_assert(nla->nla_len >= NLA_HDRLEN + size);
    return nla + 1;
}

/* Returns true if 'nla' is nonnull.  (Some Netlink protocols use the presence
 * or absence of an attribute as a Boolean flag.) */
bool
nl_attr_get_flag(const struct nlattr *nla)
{
    return nla != NULL;
}

#define NL_ATTR_GET_AS(NLA, TYPE) \
        (*(TYPE*) nl_attr_get_unspec(nla, sizeof(TYPE)))

/* Returns the 8-bit value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 1 byte long. */
uint8_t
nl_attr_get_u8(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, uint8_t);
}

/* Returns the 16-bit host byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 2 bytes long. */
uint16_t
nl_attr_get_u16(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, uint16_t);
}

/* Returns the 32-bit host byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 4 bytes long. */
uint32_t
nl_attr_get_u32(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, uint32_t);
}

/* Returns the 64-bit host byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 8 bytes long. */
uint64_t
nl_attr_get_u64(const struct nlattr *nla)
{
    const ovs_32aligned_u64 *x = nl_attr_get_unspec(nla, sizeof *x);
    return get_32aligned_u64(x);
}

/* Returns the 128-bit host byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 16 bytes long. */
ovs_u128
nl_attr_get_u128(const struct nlattr *nla)
{
    const ovs_32aligned_u128 *x = nl_attr_get_unspec(nla, sizeof *x);
    return get_32aligned_u128(x);
}

/* Returns the 16-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 2 bytes long. */
ovs_be16
nl_attr_get_be16(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, ovs_be16);
}

/* Returns the 32-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 4 bytes long. */
ovs_be32
nl_attr_get_be32(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, ovs_be32);
}

/* Returns the 64-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 8 bytes long. */
ovs_be64
nl_attr_get_be64(const struct nlattr *nla)
{
    const ovs_32aligned_be64 *x = nl_attr_get_unspec(nla, sizeof *x);
    return get_32aligned_be64(x);
}

/* Returns the 128-bit network byte order value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 16 bytes long. */
ovs_be128
nl_attr_get_be128(const struct nlattr *nla)
{
    const ovs_32aligned_be128 *x = nl_attr_get_unspec(nla, sizeof *x);
    return get_32aligned_be128(x);
}

/* Returns the IPv6 address value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 16 bytes long. */
struct in6_addr
nl_attr_get_in6_addr(const struct nlattr *nla)
{
    return NL_ATTR_GET_AS(nla, struct in6_addr);
}

/* Returns the 32-bit odp_port_t value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload is at least 4 bytes long. */
odp_port_t
nl_attr_get_odp_port(const struct nlattr *nla)
{
    return u32_to_odp(nl_attr_get_u32(nla));
}

/* Returns the null-terminated string value in 'nla''s payload.
 *
 * Asserts that 'nla''s payload contains a null-terminated string. */
const char *
nl_attr_get_string(const struct nlattr *nla)
{
    ovs_assert(nla->nla_len > NLA_HDRLEN);
    ovs_assert(memchr(nl_attr_get(nla), '\0', nla->nla_len - NLA_HDRLEN));
    return nl_attr_get(nla);
}

/* Initializes 'nested' to the payload of 'nla'. */
void
nl_attr_get_nested(const struct nlattr *nla, struct ofpbuf *nested)
{
    ofpbuf_use_const(nested, nl_attr_get(nla), nl_attr_get_size(nla));
}

/* Default minimum payload size for each type of attribute. */
static size_t
min_attr_len(enum nl_attr_type type)
{
    switch (type) {
    case NL_A_NO_ATTR: return 0;
    case NL_A_UNSPEC: return 0;
    case NL_A_U8: return 1;
    case NL_A_U16: return 2;
    case NL_A_U32: return 4;
    case NL_A_U64: return 8;
    case NL_A_U128: return 16;
    case NL_A_STRING: return 1;
    case NL_A_FLAG: return 0;
    case NL_A_IPV6: return 16;
    case NL_A_NESTED: return 0;
    case N_NL_ATTR_TYPES: default: OVS_NOT_REACHED();
    }
}

/* Default maximum payload size for each type of attribute. */
static size_t
max_attr_len(enum nl_attr_type type)
{
    switch (type) {
    case NL_A_NO_ATTR: return SIZE_MAX;
    case NL_A_UNSPEC: return SIZE_MAX;
    case NL_A_U8: return 1;
    case NL_A_U16: return 2;
    case NL_A_U32: return 4;
    case NL_A_U64: return 8;
    case NL_A_U128: return 16;
    case NL_A_STRING: return SIZE_MAX;
    case NL_A_FLAG: return SIZE_MAX;
    case NL_A_IPV6: return 16;
    case NL_A_NESTED: return SIZE_MAX;
    case N_NL_ATTR_TYPES: default: OVS_NOT_REACHED();
    }
}

bool
nl_attr_validate(const struct nlattr *nla, const struct nl_policy *policy)
{
    uint16_t type = nl_attr_type(nla);
    size_t min_len;
    size_t max_len;
    size_t len;

    if (policy->type == NL_A_NO_ATTR) {
        return true;
    }

    /* Figure out min and max length. */
    min_len = policy->min_len;
    if (!min_len) {
        min_len = min_attr_len(policy->type);
    }
    max_len = policy->max_len;
    if (!max_len) {
        max_len = max_attr_len(policy->type);
    }

    /* Verify length. */
    len = nl_attr_get_size(nla);
    if (len < min_len || len > max_len) {
        VLOG_DBG_RL(&rl, "attr %"PRIu16" length %"PRIuSIZE" not in "
                    "allowed range %"PRIuSIZE"...%"PRIuSIZE, type, len, min_len, max_len);
        return false;
    }

    /* Strings must be null terminated and must not have embedded nulls. */
    if (policy->type == NL_A_STRING) {
        if (((char *) nla)[nla->nla_len - 1]) {
            VLOG_DBG_RL(&rl, "attr %"PRIu16" lacks null at end", type);
            return false;
        }
        if (memchr(nla + 1, '\0', len - 1) != NULL) {
            VLOG_DBG_RL(&rl, "attr %"PRIu16" has bad length", type);
            return false;
        }
    }

    return true;
}

/* Parses the 'msg' starting at the given 'nla_offset' as a sequence of Netlink
 * attributes.  'policy[i]', for 0 <= i < n_attrs, specifies how the attribute
 * with nla_type == i is parsed; a pointer to attribute i is stored in
 * attrs[i].  Returns true if successful, false on failure.
 *
 * If the Netlink attributes in 'msg' follow a Netlink header and a Generic
 * Netlink header, then 'nla_offset' should be NLMSG_HDRLEN + GENL_HDRLEN. */
bool
nl_policy_parse(const struct ofpbuf *msg, size_t nla_offset,
                const struct nl_policy policy[],
                struct nlattr *attrs[], size_t n_attrs)
{
    struct nlattr *nla;
    size_t left;
    size_t i;

    memset(attrs, 0, n_attrs * sizeof *attrs);

    if (msg->size < nla_offset) {
        VLOG_DBG_RL(&rl, "missing headers in nl_policy_parse");
        return false;
    }

    NL_ATTR_FOR_EACH (nla, left, ofpbuf_at(msg, nla_offset, 0),
                      msg->size - nla_offset)
    {
        uint16_t type = nl_attr_type(nla);
        if (type < n_attrs && policy[type].type != NL_A_NO_ATTR) {
            const struct nl_policy *e = &policy[type];
            if (!nl_attr_validate(nla, e)) {
                return false;
            }
            if (attrs[type]) {
                VLOG_DBG_RL(&rl, "duplicate attr %"PRIu16, type);
            }
            attrs[type] = nla;
        }
    }
    if (left) {
        VLOG_DBG_RL(&rl, "attributes followed by garbage");
        return false;
    }

    for (i = 0; i < n_attrs; i++) {
        const struct nl_policy *e = &policy[i];
        if (!e->optional && e->type != NL_A_NO_ATTR && !attrs[i]) {
            VLOG_DBG_RL(&rl, "required attr %"PRIuSIZE" missing", i);
            return false;
        }
    }
    return true;
}

/* Parses the Netlink attributes within 'nla'.  'policy[i]', for 0 <= i <
 * n_attrs, specifies how the attribute with nla_type == i is parsed; a pointer
 * to attribute i is stored in attrs[i].  Returns true if successful, false on
 * failure. */
bool
nl_parse_nested(const struct nlattr *nla, const struct nl_policy policy[],
                struct nlattr *attrs[], size_t n_attrs)
{
    struct ofpbuf buf;

    nl_attr_get_nested(nla, &buf);
    return nl_policy_parse(&buf, 0, policy, attrs, n_attrs);
}

const struct nlattr *
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

/* Returns the first Netlink attribute within 'buf' with the specified 'type',
 * skipping a header of 'hdr_len' bytes at the beginning of 'buf'.
 *
 * This function does not validate the attribute's length. */
const struct nlattr *
nl_attr_find(const struct ofpbuf *buf, size_t hdr_len, uint16_t type)
{
    return nl_attr_find__(ofpbuf_at(buf, hdr_len, 0), buf->size - hdr_len,
                          type);
}

/* Returns the first Netlink attribute within 'nla' with the specified
 * 'type'.
 *
 * This function does not validate the attribute's length. */
const struct nlattr *
nl_attr_find_nested(const struct nlattr *nla, uint16_t type)
{
    return nl_attr_find__(nl_attr_get(nla), nl_attr_get_size(nla), type);
}
