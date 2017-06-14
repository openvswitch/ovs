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

#ifndef __NETLINK_PROTO_H_
#define __NETLINK_PROTO_H_ 1

/* Netlink protocol definitions.
 *
 * Netlink is a message framing format described in RFC 3549 and used heavily
 * in Linux to access the network stack.  Open vSwitch uses AF_NETLINK sockets
 * for this purpose on Linux.  On Windows platform too, Open vSwitch uses
 * netlink message format for userspace-kernelspace communication.
 *
 * This header provides access to the Netlink message framing definitions
 * regardless of platform.
 */
#include "Types.h"

#define BUILD_ASSERT(EXPR) \
        typedef char AssertOnCompileFailed[(EXPR) ? 1: -1]
#define BUILD_ASSERT_DECL(EXPR) BUILD_ASSERT(EXPR)

/* Returns X / Y, rounding up.  X must be nonnegative to round correctly. */
#define DIV_ROUND_UP(X, Y) (((X) + ((Y) - 1)) / (Y))

/* Returns X rounded up to the nearest multiple of Y. */
#define ROUND_UP(X, Y) (DIV_ROUND_UP(X, Y) * (Y))

/* Returns the least number that, when added to X, yields a multiple of Y. */
#define PAD_SIZE(X, Y) (ROUND_UP(X, Y) - (X))

/* Netlink message */

/* nlmsg_flags bits. */
#define NLM_F_REQUEST           0x001
#define NLM_F_MULTI             0x002
#define NLM_F_ACK               0x004
#define NLM_F_ECHO              0x008

#define NLM_F_ROOT              0x100
#define NLM_F_MATCH             0x200
#define NLM_F_EXCL              0x200
#define NLM_F_ATOMIC            0x400
#define NLM_F_CREATE            0x400
#define NLM_F_DUMP              (NLM_F_ROOT | NLM_F_MATCH)

/* nlmsg_type values. */
#define NLMSG_NOOP              1
#define NLMSG_ERROR             2
#define NLMSG_DONE              3
#define NLMSG_OVERRUN           4

#define NLMSG_MIN_TYPE          0x10

#define MAX_LINKS               32

#define NLMSG_ALIGNTO 4
#define NLMSG_ALIGN(SIZE) ROUND_UP(SIZE, NLMSG_ALIGNTO)

#define NLA_ALIGNTO 4
#define NLA_ALIGN(SIZE) ROUND_UP(SIZE, NLA_ALIGNTO)

typedef struct ovs_header OVS_HDR, *POVS_HDR;

typedef struct _NL_MSG_HDR {
    UINT32 nlmsgLen;
    UINT16 nlmsgType;
    UINT16 nlmsgFlags;
    UINT32 nlmsgSeq;
    UINT32 nlmsgPid;
} NL_MSG_HDR, *PNL_MSG_HDR;
BUILD_ASSERT_DECL(sizeof(NL_MSG_HDR) == 16);

typedef struct _NlMsgErr
{
    INT error;
    NL_MSG_HDR nlMsg;
} NL_MSG_ERR, *PNL_MSG_ERR;
BUILD_ASSERT_DECL(sizeof(NL_MSG_ERR) == 20);

typedef struct _GENL_MSG_HDR {
    UINT8 cmd;
    UINT8 version;
    UINT16 reserved;
} GENL_MSG_HDR, *PGENL_MSG_HDR;
BUILD_ASSERT_DECL(sizeof(GENL_MSG_HDR) == 4);

/* Netfilter Generic Message */
typedef struct _NF_GEN_MSG_HDR {
    UINT8 nfgenFamily;   /* AF_xxx */
    UINT8 version;       /* nfnetlink version */
    UINT16 resId;        /* resource id */
} NF_GEN_MSG_HDR, *PNF_GEN_MSG_HDR;
BUILD_ASSERT_DECL(sizeof(NF_GEN_MSG_HDR) == 4);

/* Netlink attributes */
typedef struct _NL_ATTR {
    UINT16 nlaLen;
    UINT16 nlaType;
} NL_ATTR, *PNL_ATTR;
BUILD_ASSERT_DECL(sizeof(NL_ATTR) == 4);

#ifndef NLA_TYPE_MASK
#define NLA_F_NESTED        (1 << 15)
#define NLA_F_NET_BYTEORDER (1 << 14)
#define NLA_TYPE_MASK       ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)
#endif

#define NLMSG_HDRLEN ((INT) NLMSG_ALIGN(sizeof(NL_MSG_HDR)))
#define GENL_HDRLEN NLMSG_ALIGN(sizeof(GENL_MSG_HDR))
#define NF_GEN_MSG_HDRLEN NLMSG_ALIGN(sizeof(NF_GEN_MSG_HDR))
#define OVS_HDRLEN NLMSG_ALIGN(sizeof(OVS_HDR))
#define NLA_HDRLEN ((UINT16) NLA_ALIGN(sizeof(NL_ATTR)))

#define NETLINK_NETFILTER       12
#define NETLINK_GENERIC         16

#endif /* NetlinProto.h */
