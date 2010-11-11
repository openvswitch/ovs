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
#include "openvswitch/datapath-protocol.h"
#include "util.h"

struct ds;
struct flow_wildcards;
struct ofp_match;
struct ofpbuf;

#define FLOW_N_REGS 3
BUILD_ASSERT_DECL(FLOW_N_REGS <= NXM_NX_MAX_REGS);

struct flow {
    uint32_t regs[FLOW_N_REGS]; /* Registers. */
    ovs_be32 tun_id;            /* Encapsulating tunnel ID. */
    ovs_be32 nw_src;            /* IP source address. */
    ovs_be32 nw_dst;            /* IP destination address. */
    uint16_t in_port;           /* Input switch port. */
    ovs_be16 dl_vlan;           /* Input VLAN. */
    ovs_be16 dl_type;           /* Ethernet frame type. */
    ovs_be16 tp_src;            /* TCP/UDP source port. */
    ovs_be16 tp_dst;            /* TCP/UDP destination port. */
    uint8_t dl_src[6];          /* Ethernet source address. */
    uint8_t dl_dst[6];          /* Ethernet destination address. */
    uint8_t nw_proto;           /* IP protocol or low 8 bits of ARP opcode. */
    uint8_t dl_vlan_pcp;        /* Input VLAN priority. */
    uint8_t nw_tos;             /* IP ToS (DSCP field, 6 bits). */
};

/* Assert that there are FLOW_SIG_SIZE bytes of significant data in "struct
 * flow", followed by FLOW_PAD_SIZE bytes of padding. */
#define FLOW_SIG_SIZE (37 + FLOW_N_REGS * 4)
#define FLOW_PAD_SIZE 3
BUILD_ASSERT_DECL(offsetof(struct flow, nw_tos) == FLOW_SIG_SIZE - 1);
BUILD_ASSERT_DECL(sizeof(((struct flow *)0)->nw_tos) == 1);
BUILD_ASSERT_DECL(sizeof(struct flow) == FLOW_SIG_SIZE + FLOW_PAD_SIZE);

int flow_extract(struct ofpbuf *, ovs_be32 tun_id, uint16_t in_port,
                 struct flow *);
void flow_extract_stats(const struct flow *flow, struct ofpbuf *packet,
        struct odp_flow_stats *stats);
void flow_to_match(const struct flow *, uint32_t wildcards, int flow_format,
                   struct ofp_match *);
void flow_from_match(const struct ofp_match *, int flow_format,
                     ovs_be64 cookie, struct flow *, struct flow_wildcards *);
char *flow_to_string(const struct flow *);
void flow_format(struct ds *, const struct flow *);
void flow_print(FILE *, const struct flow *);
static inline int flow_compare(const struct flow *, const struct flow *);
static inline bool flow_equal(const struct flow *, const struct flow *);
static inline size_t flow_hash(const struct flow *, uint32_t basis);

static inline int
flow_compare(const struct flow *a, const struct flow *b)
{
    return memcmp(a, b, FLOW_SIG_SIZE);
}

static inline bool
flow_equal(const struct flow *a, const struct flow *b)
{
    return !flow_compare(a, b);
}

static inline size_t
flow_hash(const struct flow *flow, uint32_t basis)
{
    return hash_bytes(flow, FLOW_SIG_SIZE, basis);
}

/* Open vSwitch internal-only wildcard bits.
 *
 * These are used only internally to Open vSwitch, in the 'wildcards' member of
 * struct flow_wildcards.  They never appear in the wire protocol in this
 * form. */

/* Set to 1 if any bits in any of the reg_masks are wildcarded.  This maintains
 * the invariant that 'wildcards' is nonzero if and only if any bits are
 * wildcarded. */
#define FWW_REGS (1u << 31)

/* Set to 1 if bit 0 (the multicast bit) of the flow's dl_dst is wildcarded.
 *
 * (We reinterpret OFPFW_DL_DST as excluding bit 0.  Both OFPFW_DL_DST and
 * FWW_ETH_MCAST have to be set to wildcard the entire Ethernet destination
 * address.) */
#define FWW_ETH_MCAST (1u << 30)

/* Avoid collisions. */
#define FWW_ALL (FWW_REGS | FWW_ETH_MCAST)
BUILD_ASSERT_DECL(!(FWW_ALL & OVSFW_ALL));

/* Information on wildcards for a flow, as a supplement to "struct flow".
 *
 * The flow_wildcards_*() functions below both depend on and maintain the
 * following important invariants:
 *
 * 1. 'wildcards' is nonzero if and only if at least one bit or field is
 *    wildcarded.
 *
 * 2. Bits in 'wildcards' not included in OVSFW_ALL or FWW_ALL are set to 0.
 *    (This is a corollary to invariant #1.)
 *
 * 3. The fields in 'wildcards' masked by OFPFW_NW_SRC_MASK and
 *    OFPFW_NW_DST_MASK have values between 0 and 32, inclusive.
 *
 * 4. The fields masked by OFPFW_NW_SRC_MASK and OFPFW_NW_DST_MASK correspond
 *    correctly to the masks in 'nw_src_mask' and 'nw_dst_mask', respectively.
 *
 * 5. FWW_REGS is set to 1 in 'wildcards' if and only if at least one bit in
 *    'reg_masks[]' is nonzero.  (This allows wildcarded 'reg_masks[]' to
 *    satisfy invariant #1.)
 *
 * 6. If FWW_REGS is set to 0 in 'wildcards', then the values of all of the
 *    other members can be correctly predicted based on 'wildcards' alone.
 */
struct flow_wildcards {
    uint32_t wildcards;         /* OFPFW_* | OVSFW_* | FWW_*. */
    uint32_t reg_masks[FLOW_N_REGS]; /* 1-bit in each significant regs bit. */
    ovs_be32 nw_src_mask;       /* 1-bit in each significant nw_src bit. */
    ovs_be32 nw_dst_mask;       /* 1-bit in each significant nw_dst bit. */
};

ovs_be32 flow_nw_bits_to_mask(uint32_t wildcards, int shift);
void flow_wildcards_init(struct flow_wildcards *, uint32_t wildcards);
void flow_wildcards_init_exact(struct flow_wildcards *);

bool flow_wildcards_set_nw_src_mask(struct flow_wildcards *, ovs_be32);
bool flow_wildcards_set_nw_dst_mask(struct flow_wildcards *, ovs_be32);
void flow_wildcards_set_reg_mask(struct flow_wildcards *,
                                 int idx, uint32_t mask);

void flow_wildcards_combine(struct flow_wildcards *dst,
                            const struct flow_wildcards *src1,
                            const struct flow_wildcards *src2);
bool flow_wildcards_has_extra(const struct flow_wildcards *,
                              const struct flow_wildcards *);

uint32_t flow_wildcards_hash(const struct flow_wildcards *);
bool flow_wildcards_equal(const struct flow_wildcards *,
                          const struct flow_wildcards *);

#endif /* flow.h */
