/*
 * Copyright (c) 2008 Nicira Networks.
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
