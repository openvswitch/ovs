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

#ifndef NETLINK_PROTOCOL_H
#define NETLINK_PROTOCOL_H 1

/* Netlink protocol definitions.
 *
 * These definitions are equivalent to those in the Linux 2.6 kernel headers,
 * without requiring those headers to be available. */

#include <stdint.h>
#include <sys/socket.h>
#include "util.h"

#define NETLINK_GENERIC         16

struct sockaddr_nl {
    sa_family_t nl_family;
    unsigned short int nl_pad;
    uint32_t nl_pid;
    uint32_t nl_groups;
};
BUILD_ASSERT_DECL(sizeof(struct sockaddr_nl) == 12);

/* nlmsg_flags bits. */
#define NLM_F_REQUEST           0x001
#define NLM_F_MULTI             0x002
#define NLM_F_ACK               0x004
#define NLM_F_ECHO              0x008

#define NLM_F_ROOT              0x100
#define NLM_F_MATCH             0x200
#define NLM_F_ATOMIC            0x400
#define NLM_F_DUMP              (NLM_F_ROOT | NLM_F_MATCH)

/* nlmsg_type values. */
#define NLMSG_NOOP              1
#define NLMSG_ERROR             2
#define NLMSG_DONE              3
#define NLMSG_OVERRUN           4

#define NLMSG_MIN_TYPE          0x10

struct nlmsghdr {
    uint32_t nlmsg_len;
    uint16_t nlmsg_type;
    uint16_t nlmsg_flags;
    uint32_t nlmsg_seq;
    uint32_t nlmsg_pid;
};
BUILD_ASSERT_DECL(sizeof(struct nlmsghdr) == 16);

#define NLMSG_ALIGNTO 4
#define NLMSG_ALIGN(SIZE) ROUND_UP(SIZE, NLMSG_ALIGNTO)
#define NLMSG_HDRLEN ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))

struct nlmsgerr
{
        int error;
        struct nlmsghdr msg;
};
BUILD_ASSERT_DECL(sizeof(struct nlmsgerr) == 20);

#define NETLINK_ADD_MEMBERSHIP  1
#define NETLINK_DROP_MEMBERSHIP 2
#define NETLINK_PKTINFO         3

struct genlmsghdr {
    uint8_t cmd;
    uint8_t version;
    uint16_t reserved;
};
BUILD_ASSERT_DECL(sizeof(struct genlmsghdr) == 4);

#define GENL_HDRLEN NLMSG_ALIGN(sizeof(struct genlmsghdr))

struct nlattr {
    uint16_t nla_len;
    uint16_t nla_type;
};
BUILD_ASSERT_DECL(sizeof(struct nlattr) == 4);

#define NLA_ALIGNTO 4
#define NLA_ALIGN(SIZE) ROUND_UP(SIZE, NLA_ALIGNTO)
#define NLA_HDRLEN ((int) NLA_ALIGN(sizeof(struct nlattr)))

#define GENL_MIN_ID     NLMSG_MIN_TYPE
#define GENL_MAX_ID     1023

#define GENL_ID_CTRL            NLMSG_MIN_TYPE

enum {
        CTRL_CMD_UNSPEC,
        CTRL_CMD_NEWFAMILY,
        CTRL_CMD_DELFAMILY,
        CTRL_CMD_GETFAMILY,
        CTRL_CMD_NEWOPS,
        CTRL_CMD_DELOPS,
        CTRL_CMD_GETOPS,
        __CTRL_CMD_MAX,
};

#define CTRL_CMD_MAX (__CTRL_CMD_MAX - 1)

enum {
        CTRL_ATTR_UNSPEC,
        CTRL_ATTR_FAMILY_ID,
        CTRL_ATTR_FAMILY_NAME,
        CTRL_ATTR_VERSION,
        CTRL_ATTR_HDRSIZE,
        CTRL_ATTR_MAXATTR,
        CTRL_ATTR_OPS,
        __CTRL_ATTR_MAX,
};

#define CTRL_ATTR_MAX (__CTRL_ATTR_MAX - 1)

enum {
        CTRL_ATTR_OP_UNSPEC,
        CTRL_ATTR_OP_ID,
        CTRL_ATTR_OP_FLAGS,
        __CTRL_ATTR_OP_MAX,
};

#define CTRL_ATTR_OP_MAX (__CTRL_ATTR_OP_MAX - 1)

#endif /* netlink-protocol.h */
