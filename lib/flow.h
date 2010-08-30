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
struct ofp_match;
struct ofpbuf;

typedef struct odp_flow_key flow_t;

int flow_extract(struct ofpbuf *, uint32_t tun_id, uint16_t in_port, flow_t *);
void flow_extract_stats(const flow_t *flow, struct ofpbuf *packet,
        struct odp_flow_stats *stats);
void flow_to_match(const flow_t *, uint32_t wildcards, bool tun_id_cookie,
                   struct ofp_match *);
void flow_from_match(const struct ofp_match *, bool tun_id_from_cookie,
                     uint64_t cookie, flow_t *, uint32_t *wildcards);
char *flow_to_string(const flow_t *);
void flow_format(struct ds *, const flow_t *);
void flow_print(FILE *, const flow_t *);
static inline int flow_compare(const flow_t *, const flow_t *);
static inline bool flow_equal(const flow_t *, const flow_t *);
static inline size_t flow_hash(const flow_t *, uint32_t basis);

static inline int
flow_compare(const flow_t *a, const flow_t *b)
{
    return memcmp(a, b, sizeof *a);
}

static inline bool
flow_equal(const flow_t *a, const flow_t *b)
{
    return !flow_compare(a, b);
}

static inline size_t
flow_hash(const flow_t *flow, uint32_t basis)
{
    BUILD_ASSERT_DECL(!(sizeof *flow % sizeof(uint32_t)));
    return hash_words((const uint32_t *) flow,
                      sizeof *flow / sizeof(uint32_t), basis);
}

/* Information on wildcards for a flow, as a supplement to flow_t. */
struct flow_wildcards {
    uint32_t wildcards;         /* enum ofp_flow_wildcards (in host order). */
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
    wc->wildcards = wildcards & OVSFW_ALL;
    wc->nw_src_mask = flow_nw_bits_to_mask(wc->wildcards, OFPFW_NW_SRC_SHIFT);
    wc->nw_dst_mask = flow_nw_bits_to_mask(wc->wildcards, OFPFW_NW_DST_SHIFT);
}

#endif /* flow.h */
