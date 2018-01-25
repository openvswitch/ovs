/*
 * Copyright (c) 2010, 2011, 2013, 2014, 2016, 2017 Nicira, Inc.
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

#ifndef OPENVSWITCH_TYPES_H
#define OPENVSWITCH_TYPES_H 1

#include <sys/types.h>
#include <stdint.h>
#include "openvswitch/compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __CHECKER__
#define OVS_BITWISE __attribute__((bitwise))
#define OVS_FORCE __attribute__((force))
#else
#define OVS_BITWISE
#define OVS_FORCE
#endif

/* The ovs_be<N> types indicate that an object is in big-endian, not
 * native-endian, byte order.  They are otherwise equivalent to uint<N>_t. */
typedef uint16_t OVS_BITWISE ovs_be16;
typedef uint32_t OVS_BITWISE ovs_be32;
typedef uint64_t OVS_BITWISE ovs_be64;

#define OVS_BE16_MAX ((OVS_FORCE ovs_be16) 0xffff)
#define OVS_BE32_MAX ((OVS_FORCE ovs_be32) 0xffffffff)
#define OVS_BE64_MAX ((OVS_FORCE ovs_be64) 0xffffffffffffffffULL)

/* These types help with a few funny situations:
 *
 *   - The Ethernet header is 14 bytes long, which misaligns everything after
 *     that.  One can put 2 "shim" bytes before the Ethernet header, but this
 *     helps only if there is exactly one Ethernet header.  If there are two,
 *     as with GRE and VXLAN (and if the inner header doesn't use this
 *     trick--GRE and VXLAN don't) then you have the choice of aligning the
 *     inner data or the outer data.  So it seems better to treat 32-bit fields
 *     in protocol headers as aligned only on 16-bit boundaries.
 *
 *   - ARP headers contain misaligned 32-bit fields.
 *
 *   - Netlink and OpenFlow contain 64-bit values that are only guaranteed to
 *     be aligned on 32-bit boundaries.
 *
 * lib/unaligned.h has helper functions for accessing these. */

/* A 32-bit value, in host byte order, that is only aligned on a 16-bit
 * boundary.  */
typedef struct {
#ifdef WORDS_BIGENDIAN
        uint16_t hi, lo;
#else
        uint16_t lo, hi;
#endif
} ovs_16aligned_u32;

/* A 32-bit value, in network byte order, that is only aligned on a 16-bit
 * boundary. */
typedef struct {
        ovs_be16 hi, lo;
} ovs_16aligned_be32;

/* A 64-bit value, in host byte order, that is only aligned on a 32-bit
 * boundary.  */
typedef struct {
#ifdef WORDS_BIGENDIAN
        uint32_t hi, lo;
#else
        uint32_t lo, hi;
#endif
} ovs_32aligned_u64;

/* A 128-bit value, in host byte order, that is only aligned on a 32-bit
 * boundary.  */
typedef struct {
    uint32_t u32[4];
} ovs_32aligned_u128;

/* A 128-bit value, in network byte order, that is only aligned on a 32-bit
 * boundary.  */
typedef struct {
    ovs_be32 be32[4];
} ovs_32aligned_be128;

typedef union {
    uint32_t u32[4];
    struct {
#ifdef WORDS_BIGENDIAN
        uint64_t hi, lo;
#else
        uint64_t lo, hi;
#endif
    } u64;
} ovs_u128;

typedef union {
    ovs_be32 be32[4];
    struct {
        ovs_be64 hi, lo;
    } be64;
} ovs_be128;

/* MSVC2015 doesn't support designated initializers when compiling C++,
 * and doesn't support ternary operators with non-designated initializers.
 * So we use these static definitions rather than using initializer macros. */
static const ovs_u128 OVS_U128_ZERO = { { 0, 0, 0, 0 } };
static const ovs_u128 OVS_U128_MAX = { { UINT32_MAX, UINT32_MAX,
                                         UINT32_MAX, UINT32_MAX } };
static const ovs_be128 OVS_BE128_MAX OVS_UNUSED = { { OVS_BE32_MAX, OVS_BE32_MAX,
                                           OVS_BE32_MAX, OVS_BE32_MAX } };
static const ovs_u128 OVS_U128_MIN OVS_UNUSED = { {0, 0, 0, 0} };
static const ovs_u128 OVS_BE128_MIN OVS_UNUSED = { {0, 0, 0, 0} };

#define OVS_U128_ZERO OVS_U128_MIN

/* A 64-bit value, in network byte order, that is only aligned on a 32-bit
 * boundary. */
typedef struct {
        ovs_be32 hi, lo;
} ovs_32aligned_be64;

/* Port numbers
 * ------------
 *
 * None of these types are directly interchangeable, hence the OVS_BITWISE
 * annotation.
 *
 * ofp_port_t is an OpenFlow 1.0 port number.  It uses a 16-bit range, even
 * though it is a 32-bit type.  This allows it to be overlaid on an odp_port_t
 * for a few situations where this is useful, e.g. in union flow_in_port.
 *
 * ofp11_port_t is an OpenFlow-1.1 port number.
 *
 * odp_port_t is a port number within a datapath (e.g. see lib/dpif.h).
 */
typedef uint32_t OVS_BITWISE ofp_port_t;
typedef uint32_t OVS_BITWISE odp_port_t;
typedef uint32_t OVS_BITWISE ofp11_port_t;

/* Macro functions that cast int types to ofp/odp/ofp11 types. */
#define OFP_PORT_C(X) ((OVS_FORCE ofp_port_t) (X))
#define ODP_PORT_C(X) ((OVS_FORCE odp_port_t) (X))
#define OFP11_PORT_C(X) ((OVS_FORCE ofp11_port_t) (X))

/* Using this struct instead of a bare array makes an ethernet address field
 * assignable.  The size of the array is also part of the type, so it is easier
 * to deal with. */
struct eth_addr {
    union {
        uint8_t ea[6];
        ovs_be16 be16[3];
    };
};

/* Ethernet address constant, e.g. ETH_ADDR_C(01,23,45,67,89,ab) is
 * 01:23:45:67:89:ab. */
#define ETH_ADDR_C(A,B,C,D,E,F) \
    { { { 0x##A, 0x##B, 0x##C, 0x##D, 0x##E, 0x##F } } }

/* Similar to struct eth_addr, for EUI-64 addresses. */
struct eth_addr64 {
    union {
        uint8_t ea64[8];
        ovs_be16 be16[4];
    };
};

/* EUI-64 address constant, e.g. ETH_ADDR_C(01,23,45,67,89,ab,cd,ef) is
 * 01:23:45:67:89:ab:cd:ef. */
#define ETH_ADDR64_C(A,B,C,D,E,F,G,H) \
    { { { 0x##A, 0x##B, 0x##C, 0x##D, 0x##E, 0x##F, 0x##G, 0x##H } } }

#ifdef __cplusplus
}
#endif

#endif /* openvswitch/types.h */
