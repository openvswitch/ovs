/*
 * Copyright (c) 2008, 2010, 2011, 2014 Nicira, Inc.
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

#ifndef NETLINK_PROTOCOL_H
#define NETLINK_PROTOCOL_H 1

/* Netlink protocol definitions.
 *
 * Netlink is a message framing format described in RFC 3549 and used heavily
 * in Linux to access the network stack.  Open vSwitch uses AF_NETLINK sockets
 * for this purpose on Linux.  But on all platforms, Open vSwitch uses Netlink
 * message framing internally for certain purposes.
 *
 * This header provides access to the Netlink message framing definitions
 * regardless of platform.  On Linux, it includes the proper headers directly;
 * on other platforms it directly defines the structures and macros itself.
 */

#include <stdint.h>
#include <sys/socket.h>
#include "util.h"

#ifdef HAVE_NETLINK
#include <linux/netlink.h>
#include <linux/genetlink.h>

#else
#define NETLINK_NETFILTER       12
#define NETLINK_GENERIC         16

/* nlmsg_flags bits. */
#define NLM_F_REQUEST           0x001
#define NLM_F_MULTI             0x002
#define NLM_F_ACK               0x004
#define NLM_F_ECHO              0x008

/* GET request flag.*/
#define NLM_F_ROOT              0x100
#define NLM_F_MATCH             0x200
#define NLM_F_ATOMIC            0x400
#define NLM_F_DUMP              (NLM_F_ROOT | NLM_F_MATCH)

/* NEW request flags. */
#define NLM_F_REPLACE           0x100
#define NLM_F_EXCL              0x200
#define NLM_F_CREATE            0x400

/* nlmsg_type values. */
#define NLMSG_NOOP              1
#define NLMSG_ERROR             2
#define NLMSG_DONE              3
#define NLMSG_OVERRUN           4

#define NLMSG_MIN_TYPE          0x10

#define MAX_LINKS               32

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
#endif  /* !HAVE_NETLINK */

/* These were introduced all together in 2.6.24. */
#ifndef NLA_TYPE_MASK
#define NLA_F_NESTED        (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK       ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
#endif

/* These were introduced all together in 2.6.14.  (We want our programs to
 * support the newer kernel features even if compiled with older headers.) */
#ifndef NETLINK_ADD_MEMBERSHIP
#define NETLINK_ADD_MEMBERSHIP 1
#define NETLINK_DROP_MEMBERSHIP 2
#endif

/* This was introduced in v4.2.  (We want our programs to support the newer
 * kernel features even if compiled with older headers.) */
#ifndef NETLINK_LISTEN_ALL_NSID
#define NETLINK_LISTEN_ALL_NSID 8
#endif

/* These were introduced all together in 2.6.23.  (We want our programs to
 * support the newer kernel features even if compiled with older headers.) */
#ifndef CTRL_ATTR_MCAST_GRP_MAX

#undef CTRL_ATTR_MAX
#define CTRL_ATTR_MAX 7
#define CTRL_ATTR_MCAST_GROUPS 7

enum {
    CTRL_ATTR_MCAST_GRP_UNSPEC,
    CTRL_ATTR_MCAST_GRP_NAME,
    CTRL_ATTR_MCAST_GRP_ID,
    __CTRL_ATTR_MCAST_GRP_MAX,
};

#define CTRL_ATTR_MCAST_GRP_MAX (__CTRL_ATTR_MCAST_GRP_MAX - 1)
#endif /* CTRL_ATTR_MCAST_GRP_MAX */

#endif /* netlink-protocol.h */
