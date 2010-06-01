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
#ifndef FLOW_H
#define FLOW_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "hash.h"
#include "openvswitch/xflow.h"
#include "packets.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct ds;
struct ofp_match;
struct ofpbuf;

typedef struct flow flow_t;
struct flow {
    uint32_t wildcards;         /* Wildcards. */
    uint32_t priority;          /* Priority. */
    uint32_t tun_id;            /* Encapsulating tunnel ID. */
    uint32_t nw_src;            /* IP source address. */
    uint32_t nw_dst;            /* IP destination address. */
    uint16_t in_port;           /* Input switch port. */
    uint16_t dl_vlan;           /* Input VLAN. */
    uint16_t dl_type;           /* Ethernet frame type. */
    uint16_t tp_src;            /* TCP/UDP source port. */
    uint16_t tp_dst;            /* TCP/UDP destination port. */
    uint8_t dl_src[ETH_ADDR_LEN]; /* Ethernet source address. */
    uint8_t dl_dst[ETH_ADDR_LEN]; /* Ethernet destination address. */
    uint8_t nw_proto;           /* IP protocol or low 8 bits of ARP opcode. */
    uint8_t dl_vlan_pcp;        /* Input VLAN priority. */
    uint8_t nw_tos;             /* IP ToS (DSCP field, 6 bits). */
};

/* Assert that there are FLOW_SIG_SIZE bytes of significant data in "struct
 * flow", followed by FLOW_PAD_SIZE bytes of padding. */
#define FLOW_SIG_SIZE 45
#define FLOW_PAD_SIZE 3
BUILD_ASSERT_DECL(offsetof(struct flow, nw_tos) == FLOW_SIG_SIZE - 1);
BUILD_ASSERT_DECL(sizeof(((struct flow *)0)->nw_tos) == 1);
BUILD_ASSERT_DECL(sizeof(struct flow) == FLOW_SIG_SIZE + FLOW_PAD_SIZE);

int flow_extract(struct ofpbuf *, uint32_t tun_id, uint16_t in_port, flow_t *);
void flow_extract_stats(const flow_t *flow, struct ofpbuf *packet, 
        struct xflow_flow_stats *stats);
void flow_to_match(const flow_t *,
                   bool tun_id_from_cookie, struct ofp_match *);
void flow_from_match(const struct ofp_match *, uint32_t priority,
                     bool tun_id_from_cookie, uint64_t cookie, flow_t *);
char *flow_to_string(const flow_t *);
void flow_format(struct ds *, const flow_t *);
void flow_print(FILE *, const flow_t *);
static inline int flow_compare(const flow_t *, const flow_t *);
static inline bool flow_equal(const flow_t *, const flow_t *);
static inline size_t flow_hash(const flow_t *, uint32_t basis);

static inline int
flow_compare(const flow_t *a, const flow_t *b)
{
    return memcmp(a, b, FLOW_SIG_SIZE);
}

static inline bool
flow_equal(const flow_t *a, const flow_t *b)
{
    return !flow_compare(a, b);
}

static inline size_t
flow_hash(const flow_t *flow, uint32_t basis)
{
    return hash_bytes(flow, FLOW_SIG_SIZE, basis);
}

/* Information on wildcards for a flow, as a supplement to flow_t. */
struct flow_wildcards {
    uint32_t nw_src_mask;       /* 1-bit in each significant nw_src bit. */
    uint32_t nw_dst_mask;       /* 1-bit in each significant nw_dst bit. */
};

/* Given the wildcard bit count in bits 'shift' through 'shift + 5' (inclusive)
 * of 'wildcards', returns a 32-bit bit mask with a 1 in each bit that must
 * match and a 0 in each bit that is wildcarded.
 *
 * The bits in 'wildcards' are in the format used in enum ofp_flow_wildcards: 0
 * is exact match, 1 ignores the LSB, 2 ignores the 2 least-significant bits,
 * ..., 32 and higher wildcard the entire field.  This is the *opposite* of the
 * usual convention where e.g. /24 indicates that 8 bits (not 24 bits) are
 * wildcarded.
 *
 * 'wildcards' is in host byte order.  The return value is in network byte
 * order. */
static inline uint32_t
flow_nw_bits_to_mask(uint32_t wildcards, int shift)
{
    wildcards = (wildcards >> shift) & 0x3f;
    return wildcards < 32 ? htonl(~((1u << wildcards) - 1)) : 0;
}

static inline void
flow_wildcards_init(struct flow_wildcards *wc, uint32_t wildcards)
{
    wildcards &= OVSFW_ALL;
    wc->nw_src_mask = flow_nw_bits_to_mask(wildcards, OFPFW_NW_SRC_SHIFT);
    wc->nw_dst_mask = flow_nw_bits_to_mask(wildcards, OFPFW_NW_DST_SHIFT);
}

#ifdef  __cplusplus
}
#endif

#endif /* flow.h */
