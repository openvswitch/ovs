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
#ifndef FLOW_H
#define FLOW_H 1

#include <sys/types.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "bitmap.h"
#include "byte-order.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "hash.h"
#include "util.h"

struct dpif_flow_stats;
struct ds;
struct flow_wildcards;
struct minimask;
struct dp_packet;
struct pkt_metadata;
struct match;

/* This sequence number should be incremented whenever anything involving flows
 * or the wildcarding of flows changes.  This will cause build assertion
 * failures in places which likely need to be updated. */
#define FLOW_WC_SEQ 35

/* Number of Open vSwitch extension 32-bit registers. */
#define FLOW_N_REGS 8
BUILD_ASSERT_DECL(FLOW_N_REGS <= NXM_NX_MAX_REGS);
BUILD_ASSERT_DECL(FLOW_N_REGS % 2 == 0); /* Even. */

/* Number of OpenFlow 1.5+ 64-bit registers.
 *
 * Each of these overlays a pair of Open vSwitch 32-bit registers, so there
 * are half as many of them.*/
#define FLOW_N_XREGS (FLOW_N_REGS / 2)

/* Used for struct flow's dl_type member for frames that have no Ethernet
 * type, that is, pure 802.2 frames. */
#define FLOW_DL_TYPE_NONE 0x5ff

/* Fragment bits, used for IPv4 and IPv6, always zero for non-IP flows. */
#define FLOW_NW_FRAG_ANY   (1 << 0) /* Set for any IP frag. */
#define FLOW_NW_FRAG_LATER (1 << 1) /* Set for IP frag with nonzero offset. */
#define FLOW_NW_FRAG_MASK  (FLOW_NW_FRAG_ANY | FLOW_NW_FRAG_LATER)

BUILD_ASSERT_DECL(FLOW_NW_FRAG_ANY == NX_IP_FRAG_ANY);
BUILD_ASSERT_DECL(FLOW_NW_FRAG_LATER == NX_IP_FRAG_LATER);

BUILD_ASSERT_DECL(FLOW_TNL_F_OAM == NX_TUN_FLAG_OAM);

const char *flow_tun_flag_to_string(uint32_t flags);

/* Maximum number of supported MPLS labels. */
#define FLOW_MAX_MPLS_LABELS 3

/*
 * A flow in the network.
 *
 * Must be initialized to all zeros to make any compiler-induced padding
 * zeroed.  Helps also in keeping unused fields (such as mutually exclusive
 * IPv4 and IPv6 addresses) zeroed out.
 *
 * The meaning of 'in_port' is context-dependent.  In most cases, it is a
 * 16-bit OpenFlow 1.0 port number.  In the software datapath interface (dpif)
 * layer and its implementations (e.g. dpif-netlink, dpif-netdev), it is
 * instead a 32-bit datapath port number.
 *
 * The fields are organized in four segments to facilitate staged lookup, where
 * lower layer fields are first used to determine if the later fields need to
 * be looked at.  This enables better wildcarding for datapath flows.
 *
 * NOTE: Order of the fields is significant, any change in the order must be
 * reflected in miniflow_extract()!
 */
struct flow {
    /* Metadata */
    struct flow_tnl tunnel;     /* Encapsulating tunnel parameters. */
    ovs_be64 metadata;          /* OpenFlow Metadata. */
    uint32_t regs[FLOW_N_REGS]; /* Registers. */
    uint32_t skb_priority;      /* Packet priority for QoS. */
    uint32_t pkt_mark;          /* Packet mark. */
    uint32_t dp_hash;           /* Datapath computed hash value. The exact
                                 * computation is opaque to the user space. */
    union flow_in_port in_port; /* Input port.*/
    uint32_t recirc_id;         /* Must be exact match. */
    uint16_t ct_state;          /* Connection tracking state. */
    uint16_t ct_zone;           /* Connection tracking zone. */
    uint32_t ct_mark;           /* Connection mark.*/
    uint8_t pad1[4];            /* Pad to 64 bits. */
    ovs_u128 ct_label;          /* Connection label. */
    uint32_t conj_id;           /* Conjunction ID. */
    ofp_port_t actset_output;   /* Output port in action set. */
    uint8_t pad2[2];            /* Pad to 64 bits. */

    /* L2, Order the same as in the Ethernet header! (64-bit aligned) */
    struct eth_addr dl_dst;     /* Ethernet destination address. */
    struct eth_addr dl_src;     /* Ethernet source address. */
    ovs_be16 dl_type;           /* Ethernet frame type. */
    ovs_be16 vlan_tci;          /* If 802.1Q, TCI | VLAN_CFI; otherwise 0. */
    ovs_be32 mpls_lse[ROUND_UP(FLOW_MAX_MPLS_LABELS, 2)]; /* MPLS label stack
                                                             (with padding). */
    /* L3 (64-bit aligned) */
    ovs_be32 nw_src;            /* IPv4 source address. */
    ovs_be32 nw_dst;            /* IPv4 destination address. */
    struct in6_addr ipv6_src;   /* IPv6 source address. */
    struct in6_addr ipv6_dst;   /* IPv6 destination address. */
    ovs_be32 ipv6_label;        /* IPv6 flow label. */
    uint8_t nw_frag;            /* FLOW_FRAG_* flags. */
    uint8_t nw_tos;             /* IP ToS (including DSCP and ECN). */
    uint8_t nw_ttl;             /* IP TTL/Hop Limit. */
    uint8_t nw_proto;           /* IP protocol or low 8 bits of ARP opcode. */
    struct in6_addr nd_target;  /* IPv6 neighbor discovery (ND) target. */
    struct eth_addr arp_sha;    /* ARP/ND source hardware address. */
    struct eth_addr arp_tha;    /* ARP/ND target hardware address. */
    ovs_be16 tcp_flags;         /* TCP flags. With L3 to avoid matching L4. */
    ovs_be16 pad3;              /* Pad to 64 bits. */

    /* L4 (64-bit aligned) */
    ovs_be16 tp_src;            /* TCP/UDP/SCTP source port/ICMP type. */
    ovs_be16 tp_dst;            /* TCP/UDP/SCTP destination port/ICMP code. */
    ovs_be32 igmp_group_ip4;    /* IGMP group IPv4 address.
                                 * Keep last for BUILD_ASSERT_DECL below. */
};
BUILD_ASSERT_DECL(sizeof(struct flow) % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(sizeof(struct flow_tnl) % sizeof(uint64_t) == 0);

#define FLOW_U64S (sizeof(struct flow) / sizeof(uint64_t))

/* Some flow fields are mutually exclusive or only appear within the flow
 * pipeline.  IPv6 headers are bigger than IPv4 and MPLS, and IPv6 ND packets
 * are bigger than TCP,UDP and IGMP packets. */
#define FLOW_MAX_PACKET_U64S (FLOW_U64S                                   \
    /* Unused in datapath */  - FLOW_U64_SIZE(regs)                       \
                              - FLOW_U64_SIZE(metadata)                   \
    /* L2.5/3 */              - FLOW_U64_SIZE(nw_src)  /* incl. nw_dst */ \
                              - FLOW_U64_SIZE(mpls_lse)                   \
    /* L4 */                  - FLOW_U64_SIZE(tp_src)                     \
                             )

/* Remember to update FLOW_WC_SEQ when changing 'struct flow'. */
BUILD_ASSERT_DECL(offsetof(struct flow, igmp_group_ip4) + sizeof(uint32_t)
                  == sizeof(struct flow_tnl) + 216
                  && FLOW_WC_SEQ == 35);

/* Incremental points at which flow classification may be performed in
 * segments.
 * This is located here since this is dependent on the structure of the
 * struct flow defined above:
 * Each offset must be on a distinct, successive U64 boundary strictly
 * within the struct flow. */
enum {
    FLOW_SEGMENT_1_ENDS_AT = offsetof(struct flow, dl_dst),
    FLOW_SEGMENT_2_ENDS_AT = offsetof(struct flow, nw_src),
    FLOW_SEGMENT_3_ENDS_AT = offsetof(struct flow, tp_src),
};
BUILD_ASSERT_DECL(FLOW_SEGMENT_1_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(FLOW_SEGMENT_2_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(FLOW_SEGMENT_3_ENDS_AT % sizeof(uint64_t) == 0);
BUILD_ASSERT_DECL(                     0 < FLOW_SEGMENT_1_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_1_ENDS_AT < FLOW_SEGMENT_2_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_2_ENDS_AT < FLOW_SEGMENT_3_ENDS_AT);
BUILD_ASSERT_DECL(FLOW_SEGMENT_3_ENDS_AT < sizeof(struct flow));

extern const uint8_t flow_segment_u64s[];

#define FLOW_U64_OFFSET(FIELD)                          \
    (offsetof(struct flow, FIELD) / sizeof(uint64_t))
#define FLOW_U64_OFFREM(FIELD)                          \
    (offsetof(struct flow, FIELD) % sizeof(uint64_t))

/* Number of 64-bit units spanned by a 'FIELD'. */
#define FLOW_U64_SIZE(FIELD)                                            \
    DIV_ROUND_UP(FLOW_U64_OFFREM(FIELD) + MEMBER_SIZEOF(struct flow, FIELD), \
                 sizeof(uint64_t))

void flow_extract(struct dp_packet *, struct flow *);

void flow_zero_wildcards(struct flow *, const struct flow_wildcards *);
void flow_unwildcard_tp_ports(const struct flow *, struct flow_wildcards *);
void flow_get_metadata(const struct flow *, struct match *flow_metadata);

const char *ct_state_to_string(uint32_t state);
char *flow_to_string(const struct flow *);
void format_flags(struct ds *ds, const char *(*bit_to_string)(uint32_t),
                  uint32_t flags, char del);
void format_flags_masked(struct ds *ds, const char *name,
                         const char *(*bit_to_string)(uint32_t),
                         uint32_t flags, uint32_t mask, uint32_t max_mask);
int parse_flags(const char *s, const char *(*bit_to_string)(uint32_t),
                char end, const char *field_name, char **res_string,
                uint32_t *res_flags, uint32_t allowed, uint32_t *res_mask);

void flow_format(struct ds *, const struct flow *);
void flow_print(FILE *, const struct flow *);
static inline int flow_compare_3way(const struct flow *, const struct flow *);
static inline bool flow_equal(const struct flow *, const struct flow *);
static inline size_t flow_hash(const struct flow *, uint32_t basis);

void flow_set_dl_vlan(struct flow *, ovs_be16 vid);
void flow_set_vlan_vid(struct flow *, ovs_be16 vid);
void flow_set_vlan_pcp(struct flow *, uint8_t pcp);

int flow_count_mpls_labels(const struct flow *, struct flow_wildcards *);
int flow_count_common_mpls_labels(const struct flow *a, int an,
                                  const struct flow *b, int bn,
                                  struct flow_wildcards *wc);
void flow_push_mpls(struct flow *, int n, ovs_be16 mpls_eth_type,
                    struct flow_wildcards *);
bool flow_pop_mpls(struct flow *, int n, ovs_be16 eth_type,
                   struct flow_wildcards *);
void flow_set_mpls_label(struct flow *, int idx, ovs_be32 label);
void flow_set_mpls_ttl(struct flow *, int idx, uint8_t ttl);
void flow_set_mpls_tc(struct flow *, int idx, uint8_t tc);
void flow_set_mpls_bos(struct flow *, int idx, uint8_t stack);
void flow_set_mpls_lse(struct flow *, int idx, ovs_be32 lse);

void flow_compose(struct dp_packet *, const struct flow *);

static inline uint64_t
flow_get_xreg(const struct flow *flow, int idx)
{
    return ((uint64_t) flow->regs[idx * 2] << 32) | flow->regs[idx * 2 + 1];
}

static inline void
flow_set_xreg(struct flow *flow, int idx, uint64_t value)
{
    flow->regs[idx * 2] = value >> 32;
    flow->regs[idx * 2 + 1] = value;
}

static inline int
flow_compare_3way(const struct flow *a, const struct flow *b)
{
    return memcmp(a, b, sizeof *a);
}

static inline bool
flow_equal(const struct flow *a, const struct flow *b)
{
    return !flow_compare_3way(a, b);
}

static inline size_t
flow_hash(const struct flow *flow, uint32_t basis)
{
    return hash_words64((const uint64_t *)flow,
                        sizeof *flow / sizeof(uint64_t), basis);
}

static inline uint16_t
ofp_to_u16(ofp_port_t ofp_port)
{
    return (OVS_FORCE uint16_t) ofp_port;
}

static inline uint32_t
odp_to_u32(odp_port_t odp_port)
{
    return (OVS_FORCE uint32_t) odp_port;
}

static inline uint32_t
ofp11_to_u32(ofp11_port_t ofp11_port)
{
    return (OVS_FORCE uint32_t) ofp11_port;
}

static inline ofp_port_t
u16_to_ofp(uint16_t port)
{
    return OFP_PORT_C(port);
}

static inline odp_port_t
u32_to_odp(uint32_t port)
{
    return ODP_PORT_C(port);
}

static inline ofp11_port_t
u32_to_ofp11(uint32_t port)
{
    return OFP11_PORT_C(port);
}

static inline uint32_t
hash_ofp_port(ofp_port_t ofp_port)
{
    return hash_int(ofp_to_u16(ofp_port), 0);
}

static inline uint32_t
hash_odp_port(odp_port_t odp_port)
{
    return hash_int(odp_to_u32(odp_port), 0);
}

/* Wildcards for a flow.
 *
 * A 1-bit in each bit in 'masks' indicates that the corresponding bit of
 * the flow is significant (must match).  A 0-bit indicates that the
 * corresponding bit of the flow is wildcarded (need not match). */
struct flow_wildcards {
    struct flow masks;
};

#define WC_MASK_FIELD(WC, FIELD) \
    memset(&(WC)->masks.FIELD, 0xff, sizeof (WC)->masks.FIELD)
#define WC_MASK_FIELD_MASK(WC, FIELD, MASK)     \
    ((WC)->masks.FIELD |= (MASK))
#define WC_UNMASK_FIELD(WC, FIELD) \
    memset(&(WC)->masks.FIELD, 0, sizeof (WC)->masks.FIELD)

void flow_wildcards_init_catchall(struct flow_wildcards *);

void flow_wildcards_init_for_packet(struct flow_wildcards *,
                                    const struct flow *);

void flow_wildcards_clear_non_packet_fields(struct flow_wildcards *);

bool flow_wildcards_is_catchall(const struct flow_wildcards *);

void flow_wildcards_set_reg_mask(struct flow_wildcards *,
                                 int idx, uint32_t mask);
void flow_wildcards_set_xreg_mask(struct flow_wildcards *,
                                  int idx, uint64_t mask);

void flow_wildcards_and(struct flow_wildcards *dst,
                        const struct flow_wildcards *src1,
                        const struct flow_wildcards *src2);
void flow_wildcards_or(struct flow_wildcards *dst,
                       const struct flow_wildcards *src1,
                       const struct flow_wildcards *src2);
bool flow_wildcards_has_extra(const struct flow_wildcards *,
                              const struct flow_wildcards *);
uint32_t flow_wildcards_hash(const struct flow_wildcards *, uint32_t basis);
bool flow_wildcards_equal(const struct flow_wildcards *,
                          const struct flow_wildcards *);
uint32_t flow_hash_5tuple(const struct flow *flow, uint32_t basis);
uint32_t flow_hash_symmetric_l4(const struct flow *flow, uint32_t basis);
uint32_t flow_hash_symmetric_l3l4(const struct flow *flow, uint32_t basis,
                         bool inc_udp_ports );

/* Initialize a flow with random fields that matter for nx_hash_fields. */
void flow_random_hash_fields(struct flow *);
void flow_mask_hash_fields(const struct flow *, struct flow_wildcards *,
                           enum nx_hash_fields);
uint32_t flow_hash_fields(const struct flow *, enum nx_hash_fields,
                          uint16_t basis);
const char *flow_hash_fields_to_str(enum nx_hash_fields);
bool flow_hash_fields_valid(enum nx_hash_fields);

uint32_t flow_hash_in_wildcards(const struct flow *,
                                const struct flow_wildcards *,
                                uint32_t basis);

bool flow_equal_except(const struct flow *a, const struct flow *b,
                       const struct flow_wildcards *);

/* Bitmap for flow values.  For each 1-bit the corresponding flow value is
 * explicitly specified, other values are zeroes.
 *
 * map_t must be wide enough to hold any member of struct flow. */
typedef unsigned long long map_t;
#define MAP_T_BITS (sizeof(map_t) * CHAR_BIT)
#define MAP_1 (map_t)1
#define MAP_MAX TYPE_MAXIMUM(map_t)

#define MAP_IS_SET(MAP, IDX) ((MAP) & (MAP_1 << (IDX)))

/* Iterate through the indices of all 1-bits in 'MAP'. */
#define MAP_FOR_EACH_INDEX(IDX, MAP)            \
    ULLONG_FOR_EACH_1(IDX, MAP)

#define FLOWMAP_UNITS DIV_ROUND_UP(FLOW_U64S, MAP_T_BITS)

struct flowmap {
    map_t bits[FLOWMAP_UNITS];
};

#define FLOWMAP_EMPTY_INITIALIZER { { 0 } }

static inline void flowmap_init(struct flowmap *);
static inline bool flowmap_equal(struct flowmap, struct flowmap);
static inline bool flowmap_is_set(const struct flowmap *, size_t idx);
static inline bool flowmap_are_set(const struct flowmap *, size_t idx,
                                   unsigned int n_bits);
static inline void flowmap_set(struct flowmap *, size_t idx,
                               unsigned int n_bits);
static inline void flowmap_clear(struct flowmap *, size_t idx,
                                 unsigned int n_bits);
static inline struct flowmap flowmap_or(struct flowmap, struct flowmap);
static inline struct flowmap flowmap_and(struct flowmap, struct flowmap);
static inline bool flowmap_is_empty(struct flowmap);
static inline unsigned int flowmap_n_1bits(struct flowmap);

#define FLOWMAP_HAS_FIELD(FM, FIELD)                                    \
    flowmap_are_set(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))

#define FLOWMAP_SET(FM, FIELD)                                      \
    flowmap_set(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))

#define FLOWMAP_SET__(FM, FIELD, SIZE)                  \
    flowmap_set(FM, FLOW_U64_OFFSET(FIELD),             \
                DIV_ROUND_UP(SIZE, sizeof(uint64_t)))

/* XXX: Only works for full 64-bit units. */
#define FLOWMAP_CLEAR(FM, FIELD)                                        \
    BUILD_ASSERT_DECL(FLOW_U64_OFFREM(FIELD) == 0);                     \
    BUILD_ASSERT_DECL(sizeof(((struct flow *)0)->FIELD) % sizeof(uint64_t) == 0); \
    flowmap_clear(FM, FLOW_U64_OFFSET(FIELD), FLOW_U64_SIZE(FIELD))

/* Iterate through all units in 'FMAP'. */
#define FLOWMAP_FOR_EACH_UNIT(UNIT)                     \
    for ((UNIT) = 0; (UNIT) < FLOWMAP_UNITS; (UNIT)++)

/* Iterate through all map units in 'FMAP'. */
#define FLOWMAP_FOR_EACH_MAP(MAP, FLOWMAP)                              \
    for (size_t unit__ = 0;                                       \
         unit__ < FLOWMAP_UNITS && ((MAP) = (FLOWMAP).bits[unit__], true); \
         unit__++)

struct flowmap_aux;
static inline bool flowmap_next_index(struct flowmap_aux *, size_t *idx);

#define FLOWMAP_AUX_INITIALIZER(FLOWMAP) { .unit = 0, .map = (FLOWMAP) }

/* Iterate through all struct flow u64 indices specified by 'MAP'.  This is a
 * slower but easier version of the FLOWMAP_FOR_EACH_MAP() &
 * MAP_FOR_EACH_INDEX() combination. */
#define FLOWMAP_FOR_EACH_INDEX(IDX, MAP)                            \
    for (struct flowmap_aux aux__ = FLOWMAP_AUX_INITIALIZER(MAP);   \
         flowmap_next_index(&aux__, &(IDX));)

/* Flowmap inline implementations. */
static inline void
flowmap_init(struct flowmap *fm)
{
    memset(fm, 0, sizeof *fm);
}

static inline bool
flowmap_equal(struct flowmap a, struct flowmap b)
{
    return !memcmp(&a, &b, sizeof a);
}

static inline bool
flowmap_is_set(const struct flowmap *fm, size_t idx)
{
    return (fm->bits[idx / MAP_T_BITS] & (MAP_1 << (idx % MAP_T_BITS))) != 0;
}

/* Returns 'true' if any of the 'n_bits' bits starting at 'idx' are set in
 * 'fm'.  'n_bits' can be at most MAP_T_BITS. */
static inline bool
flowmap_are_set(const struct flowmap *fm, size_t idx, unsigned int n_bits)
{
    map_t n_bits_mask = (MAP_1 << n_bits) - 1;
    size_t unit = idx / MAP_T_BITS;

    idx %= MAP_T_BITS;

    if (fm->bits[unit] & (n_bits_mask << idx)) {
        return true;
    }
    /* The seemingly unnecessary bounds check on 'unit' is a workaround for a
     * false-positive array out of bounds error by GCC 4.9. */
    if (unit + 1 < FLOWMAP_UNITS && idx + n_bits > MAP_T_BITS) {
        /* Check the remaining bits from the next unit. */
        return fm->bits[unit + 1] & (n_bits_mask >> (MAP_T_BITS - idx));
    }
    return false;
}

/* Set the 'n_bits' consecutive bits in 'fm', starting at bit 'idx'.
 * 'n_bits' can be at most MAP_T_BITS. */
static inline void
flowmap_set(struct flowmap *fm, size_t idx, unsigned int n_bits)
{
    map_t n_bits_mask = (MAP_1 << n_bits) - 1;
    size_t unit = idx / MAP_T_BITS;

    idx %= MAP_T_BITS;

    fm->bits[unit] |= n_bits_mask << idx;
    /* The seemingly unnecessary bounds check on 'unit' is a workaround for a
     * false-positive array out of bounds error by GCC 4.9. */
    if (unit + 1 < FLOWMAP_UNITS && idx + n_bits > MAP_T_BITS) {
        /* 'MAP_T_BITS - idx' bits were set on 'unit', set the remaining
         * bits from the next unit. */
        fm->bits[unit + 1] |= n_bits_mask >> (MAP_T_BITS - idx);
    }
}

/* Clears the 'n_bits' consecutive bits in 'fm', starting at bit 'idx'.
 * 'n_bits' can be at most MAP_T_BITS. */
static inline void
flowmap_clear(struct flowmap *fm, size_t idx, unsigned int n_bits)
{
    map_t n_bits_mask = (MAP_1 << n_bits) - 1;
    size_t unit = idx / MAP_T_BITS;

    idx %= MAP_T_BITS;

    fm->bits[unit] &= ~(n_bits_mask << idx);
    /* The seemingly unnecessary bounds check on 'unit' is a workaround for a
     * false-positive array out of bounds error by GCC 4.9. */
    if (unit + 1 < FLOWMAP_UNITS && idx + n_bits > MAP_T_BITS) {
        /* 'MAP_T_BITS - idx' bits were cleared on 'unit', clear the
         * remaining bits from the next unit. */
        fm->bits[unit + 1] &= ~(n_bits_mask >> (MAP_T_BITS - idx));
    }
}

/* OR the bits in the flowmaps. */
static inline struct flowmap
flowmap_or(struct flowmap a, struct flowmap b)
{
    struct flowmap map;
    size_t unit;

    FLOWMAP_FOR_EACH_UNIT (unit) {
        map.bits[unit] = a.bits[unit] | b.bits[unit];
    }
    return map;
}

/* AND the bits in the flowmaps. */
static inline struct flowmap
flowmap_and(struct flowmap a, struct flowmap b)
{
    struct flowmap map;
    size_t unit;

    FLOWMAP_FOR_EACH_UNIT (unit) {
        map.bits[unit] = a.bits[unit] & b.bits[unit];
    }
    return map;
}

static inline bool
flowmap_is_empty(struct flowmap fm)
{
    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, fm) {
        if (map) {
            return false;
        }
    }
    return true;
}

static inline unsigned int
flowmap_n_1bits(struct flowmap fm)
{
    unsigned int n_1bits = 0;
    size_t unit;

    FLOWMAP_FOR_EACH_UNIT (unit) {
        n_1bits += count_1bits(fm.bits[unit]);
    }
    return n_1bits;
}

struct flowmap_aux {
    size_t unit;
    struct flowmap map;
};

static inline bool
flowmap_next_index(struct flowmap_aux *aux, size_t *idx)
{
    for (;;) {
        map_t *map = &aux->map.bits[aux->unit];
        if (*map) {
            *idx = aux->unit * MAP_T_BITS + raw_ctz(*map);
            *map = zero_rightmost_1bit(*map);
            return true;
        }
        if (++aux->unit >= FLOWMAP_UNITS) {
            return false;
        }
    }
}


/* Compressed flow. */

/* A sparse representation of a "struct flow".
 *
 * A "struct flow" is fairly large and tends to be mostly zeros.  Sparse
 * representation has two advantages.  First, it saves memory and, more
 * importantly, minimizes the number of accessed cache lines.  Second, it saves
 * time when the goal is to iterate over only the nonzero parts of the struct.
 *
 * The map member hold one bit for each uint64_t in a "struct flow".  Each
 * 0-bit indicates that the corresponding uint64_t is zero, each 1-bit that it
 * *may* be nonzero (see below how this applies to minimasks).
 *
 * The values indicated by 'map' always follow the miniflow in memory.  The
 * user of the miniflow is responsible for always having enough storage after
 * the struct miniflow corresponding to the number of 1-bits in maps.
 *
 * Elements in values array are allowed to be zero.  This is useful for "struct
 * minimatch", for which ensuring that the miniflow and minimask members have
 * same maps allows optimization.  This allowance applies only to a miniflow
 * that is not a mask.  That is, a minimask may NOT have zero elements in its
 * values.
 *
 * A miniflow is always dynamically allocated so that the maps are followed by
 * at least as many elements as there are 1-bits in maps. */
struct miniflow {
    struct flowmap map;
    /* Followed by:
     *     uint64_t values[n];
     * where 'n' is miniflow_n_values(miniflow). */
};
BUILD_ASSERT_DECL(sizeof(struct miniflow) % sizeof(uint64_t) == 0);

#define MINIFLOW_VALUES_SIZE(COUNT) ((COUNT) * sizeof(uint64_t))

static inline uint64_t *miniflow_values(struct miniflow *mf)
{
    return (uint64_t *)(mf + 1);
}

static inline const uint64_t *miniflow_get_values(const struct miniflow *mf)
{
    return (const uint64_t *)(mf + 1);
}

struct pkt_metadata;

/* The 'dst' must follow with buffer space for FLOW_U64S 64-bit units.
 * 'dst->map' is ignored on input and set on output to indicate which fields
 * were extracted. */
void miniflow_extract(struct dp_packet *packet, struct miniflow *dst);
void miniflow_map_init(struct miniflow *, const struct flow *);
void flow_wc_map(const struct flow *, struct flowmap *);
size_t miniflow_alloc(struct miniflow *dsts[], size_t n,
                      const struct miniflow *src);
void miniflow_init(struct miniflow *, const struct flow *);
void miniflow_clone(struct miniflow *, const struct miniflow *,
                    size_t n_values);
struct miniflow * miniflow_create(const struct flow *);

void miniflow_expand(const struct miniflow *, struct flow *);

static inline uint64_t flow_u64_value(const struct flow *flow, size_t index)
{
    return ((uint64_t *)flow)[index];
}

static inline uint64_t *flow_u64_lvalue(struct flow *flow, size_t index)
{
    return &((uint64_t *)flow)[index];
}

static inline size_t
miniflow_n_values(const struct miniflow *flow)
{
    return flowmap_n_1bits(flow->map);
}

struct flow_for_each_in_maps_aux {
    const struct flow *flow;
    struct flowmap_aux map_aux;
};

static inline bool
flow_values_get_next_in_maps(struct flow_for_each_in_maps_aux *aux,
                             uint64_t *value)
{
    size_t idx;

    if (flowmap_next_index(&aux->map_aux, &idx)) {
        *value = flow_u64_value(aux->flow, idx);
        return true;
    }
    return false;
}

/* Iterate through all flow u64 values specified by 'MAPS'. */
#define FLOW_FOR_EACH_IN_MAPS(VALUE, FLOW, MAPS)            \
    for (struct flow_for_each_in_maps_aux aux__             \
             = { (FLOW), FLOWMAP_AUX_INITIALIZER(MAPS) };   \
         flow_values_get_next_in_maps(&aux__, &(VALUE));)

struct mf_for_each_in_map_aux {
    size_t unit;
    struct flowmap fmap;
    struct flowmap map;
    const uint64_t *values;
};

static inline bool
mf_get_next_in_map(struct mf_for_each_in_map_aux *aux,
                   uint64_t *value)
{
    map_t *map, *fmap;
    map_t rm1bit;

    while (OVS_UNLIKELY(!*(map = &aux->map.bits[aux->unit]))) {
        /* Skip remaining data in the previous unit. */
        aux->values += count_1bits(aux->fmap.bits[aux->unit]);
        if (++aux->unit == FLOWMAP_UNITS) {
            return false;
        }
    }

    rm1bit = rightmost_1bit(*map);
    *map -= rm1bit;
    fmap = &aux->fmap.bits[aux->unit];

    if (OVS_LIKELY(*fmap & rm1bit)) {
        map_t trash = *fmap & (rm1bit - 1);

        *fmap -= trash;
        /* count_1bits() is fast for systems where speed matters (e.g.,
         * DPDK), so we don't try avoid using it.
         * Advance 'aux->values' to point to the value for 'rm1bit'. */
        aux->values += count_1bits(trash);

        *value = *aux->values;
    } else {
        *value = 0;
    }
    return true;
}

/* Iterate through miniflow u64 values specified by 'FLOWMAP'. */
#define MINIFLOW_FOR_EACH_IN_FLOWMAP(VALUE, FLOW, FLOWMAP)          \
    for (struct mf_for_each_in_map_aux aux__ =                      \
        { 0, (FLOW)->map, (FLOWMAP), miniflow_get_values(FLOW) };   \
         mf_get_next_in_map(&aux__, &(VALUE));)

/* This can be used when it is known that 'idx' is set in 'map'. */
static inline const uint64_t *
miniflow_values_get__(const uint64_t *values, map_t map, size_t idx)
{
    return values + count_1bits(map & ((MAP_1 << idx) - 1));
}

/* This can be used when it is known that 'u64_idx' is set in
 * the map of 'mf'. */
static inline const uint64_t *
miniflow_get__(const struct miniflow *mf, size_t idx)
{
    const uint64_t *values = miniflow_get_values(mf);
    const map_t *map = mf->map.bits;

    while (idx >= MAP_T_BITS) {
        idx -= MAP_T_BITS;
        values += count_1bits(*map++);
    }
    return miniflow_values_get__(values, *map, idx);
}

#define MINIFLOW_IN_MAP(MF, IDX) flowmap_is_set(&(MF)->map, IDX)

/* Get the value of the struct flow 'FIELD' as up to 8 byte wide integer type
 * 'TYPE' from miniflow 'MF'. */
#define MINIFLOW_GET_TYPE(MF, TYPE, FIELD)                              \
    (MINIFLOW_IN_MAP(MF, FLOW_U64_OFFSET(FIELD))                        \
     ? ((OVS_FORCE const TYPE *)miniflow_get__(MF, FLOW_U64_OFFSET(FIELD))) \
     [FLOW_U64_OFFREM(FIELD) / sizeof(TYPE)]                            \
     : 0)

#define MINIFLOW_GET_U128(FLOW, FIELD)                                  \
    (ovs_u128) { .u64 = {                                               \
            (MINIFLOW_IN_MAP(FLOW, FLOW_U64_OFFSET(FIELD)) ?            \
             *miniflow_get__(FLOW, FLOW_U64_OFFSET(FIELD)) : 0),        \
            (MINIFLOW_IN_MAP(FLOW, FLOW_U64_OFFSET(FIELD) + 1) ?        \
             *miniflow_get__(FLOW, FLOW_U64_OFFSET(FIELD) + 1) : 0) } }

#define MINIFLOW_GET_U8(FLOW, FIELD)            \
    MINIFLOW_GET_TYPE(FLOW, uint8_t, FIELD)
#define MINIFLOW_GET_U16(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint16_t, FIELD)
#define MINIFLOW_GET_BE16(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be16, FIELD)
#define MINIFLOW_GET_U32(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint32_t, FIELD)
#define MINIFLOW_GET_BE32(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be32, FIELD)
#define MINIFLOW_GET_U64(FLOW, FIELD)           \
    MINIFLOW_GET_TYPE(FLOW, uint64_t, FIELD)
#define MINIFLOW_GET_BE64(FLOW, FIELD)          \
    MINIFLOW_GET_TYPE(FLOW, ovs_be64, FIELD)

static inline uint64_t miniflow_get(const struct miniflow *,
                                    unsigned int u64_ofs);
static inline uint32_t miniflow_get_u32(const struct miniflow *,
                                        unsigned int u32_ofs);
static inline ovs_be32 miniflow_get_be32(const struct miniflow *,
                                         unsigned int be32_ofs);
static inline uint16_t miniflow_get_vid(const struct miniflow *);
static inline uint16_t miniflow_get_tcp_flags(const struct miniflow *);
static inline ovs_be64 miniflow_get_metadata(const struct miniflow *);

bool miniflow_equal(const struct miniflow *a, const struct miniflow *b);
bool miniflow_equal_in_minimask(const struct miniflow *a,
                                const struct miniflow *b,
                                const struct minimask *);
bool miniflow_equal_flow_in_minimask(const struct miniflow *a,
                                     const struct flow *b,
                                     const struct minimask *);
uint32_t miniflow_hash_5tuple(const struct miniflow *flow, uint32_t basis);


/* Compressed flow wildcards. */

/* A sparse representation of a "struct flow_wildcards".
 *
 * See the large comment on struct miniflow for details.
 *
 * Note: While miniflow can have zero data for a 1-bit in the map,
 * a minimask may not!  We rely on this in the implementation. */
struct minimask {
    struct miniflow masks;
};

void minimask_init(struct minimask *, const struct flow_wildcards *);
struct minimask * minimask_create(const struct flow_wildcards *);
void minimask_combine(struct minimask *dst,
                      const struct minimask *a, const struct minimask *b,
                      uint64_t storage[FLOW_U64S]);

void minimask_expand(const struct minimask *, struct flow_wildcards *);

static inline uint32_t minimask_get_u32(const struct minimask *,
                                        unsigned int u32_ofs);
static inline ovs_be32 minimask_get_be32(const struct minimask *,
                                         unsigned int be32_ofs);
static inline uint16_t minimask_get_vid_mask(const struct minimask *);
static inline ovs_be64 minimask_get_metadata_mask(const struct minimask *);

bool minimask_equal(const struct minimask *a, const struct minimask *b);
bool minimask_has_extra(const struct minimask *, const struct minimask *);


/* Returns true if 'mask' matches every packet, false if 'mask' fixes any bits
 * or fields. */
static inline bool
minimask_is_catchall(const struct minimask *mask)
{
    /* For every 1-bit in mask's map, the corresponding value is non-zero,
     * so the only way the mask can not fix any bits or fields is for the
     * map the be zero. */
    return flowmap_is_empty(mask->masks.map);
}

/* Returns the uint64_t that would be at byte offset '8 * u64_ofs' if 'flow'
 * were expanded into a "struct flow". */
static inline uint64_t miniflow_get(const struct miniflow *flow,
                                    unsigned int u64_ofs)
{
    return MINIFLOW_IN_MAP(flow, u64_ofs) ? *miniflow_get__(flow, u64_ofs) : 0;
}

static inline uint32_t miniflow_get_u32(const struct miniflow *flow,
                                        unsigned int u32_ofs)
{
    uint64_t value = miniflow_get(flow, u32_ofs / 2);

#if WORDS_BIGENDIAN
    return (u32_ofs & 1) ? value : value >> 32;
#else
    return (u32_ofs & 1) ? value >> 32 : value;
#endif
}

static inline ovs_be32 miniflow_get_be32(const struct miniflow *flow,
                                         unsigned int be32_ofs)
{
    return (OVS_FORCE ovs_be32)miniflow_get_u32(flow, be32_ofs);
}

/* Returns the VID within the vlan_tci member of the "struct flow" represented
 * by 'flow'. */
static inline uint16_t
miniflow_get_vid(const struct miniflow *flow)
{
    ovs_be16 tci = MINIFLOW_GET_BE16(flow, vlan_tci);
    return vlan_tci_to_vid(tci);
}

/* Returns the uint32_t that would be at byte offset '4 * u32_ofs' if 'mask'
 * were expanded into a "struct flow_wildcards". */
static inline uint32_t
minimask_get_u32(const struct minimask *mask, unsigned int u32_ofs)
{
    return miniflow_get_u32(&mask->masks, u32_ofs);
}

static inline ovs_be32
minimask_get_be32(const struct minimask *mask, unsigned int be32_ofs)
{
    return (OVS_FORCE ovs_be32)minimask_get_u32(mask, be32_ofs);
}

/* Returns the VID mask within the vlan_tci member of the "struct
 * flow_wildcards" represented by 'mask'. */
static inline uint16_t
minimask_get_vid_mask(const struct minimask *mask)
{
    return miniflow_get_vid(&mask->masks);
}

/* Returns the value of the "tcp_flags" field in 'flow'. */
static inline uint16_t
miniflow_get_tcp_flags(const struct miniflow *flow)
{
    return ntohs(MINIFLOW_GET_BE16(flow, tcp_flags));
}

/* Returns the value of the OpenFlow 1.1+ "metadata" field in 'flow'. */
static inline ovs_be64
miniflow_get_metadata(const struct miniflow *flow)
{
    return MINIFLOW_GET_BE64(flow, metadata);
}

/* Returns the mask for the OpenFlow 1.1+ "metadata" field in 'mask'.
 *
 * The return value is all-1-bits if 'mask' matches on the whole value of the
 * metadata field, all-0-bits if 'mask' entirely wildcards the metadata field,
 * or some other value if the metadata field is partially matched, partially
 * wildcarded. */
static inline ovs_be64
minimask_get_metadata_mask(const struct minimask *mask)
{
    return MINIFLOW_GET_BE64(&mask->masks, metadata);
}

/* Perform a bitwise OR of miniflow 'src' flow data specified in 'subset' with
 * the equivalent fields in 'dst', storing the result in 'dst'.  'subset' must
 * be a subset of 'src's map. */
static inline void
flow_union_with_miniflow_subset(struct flow *dst, const struct miniflow *src,
                                struct flowmap subset)
{
    uint64_t *dst_u64 = (uint64_t *) dst;
    const uint64_t *p = miniflow_get_values(src);
    map_t map;

    FLOWMAP_FOR_EACH_MAP (map, subset) {
        size_t idx;

        MAP_FOR_EACH_INDEX(idx, map) {
            dst_u64[idx] |= *p++;
        }
        dst_u64 += MAP_T_BITS;
    }
}

/* Perform a bitwise OR of miniflow 'src' flow data with the equivalent
 * fields in 'dst', storing the result in 'dst'. */
static inline void
flow_union_with_miniflow(struct flow *dst, const struct miniflow *src)
{
    flow_union_with_miniflow_subset(dst, src, src->map);
}

static inline void
pkt_metadata_from_flow(struct pkt_metadata *md, const struct flow *flow)
{
    md->recirc_id = flow->recirc_id;
    md->dp_hash = flow->dp_hash;
    flow_tnl_copy__(&md->tunnel, &flow->tunnel);
    md->skb_priority = flow->skb_priority;
    md->pkt_mark = flow->pkt_mark;
    md->in_port = flow->in_port;
    md->ct_state = flow->ct_state;
    md->ct_zone = flow->ct_zone;
    md->ct_mark = flow->ct_mark;
    md->ct_label = flow->ct_label;
}

static inline bool is_ip_any(const struct flow *flow)
{
    return dl_type_is_ip_any(flow->dl_type);
}

static inline bool is_icmpv4(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IPPROTO_ICMP);
}

static inline bool is_icmpv6(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_IPV6)
            && flow->nw_proto == IPPROTO_ICMPV6);
}

static inline bool is_igmp(const struct flow *flow)
{
    return (flow->dl_type == htons(ETH_TYPE_IP)
            && flow->nw_proto == IPPROTO_IGMP);
}

static inline bool is_mld(const struct flow *flow)
{
    return is_icmpv6(flow)
           && (flow->tp_src == htons(MLD_QUERY)
               || flow->tp_src == htons(MLD_REPORT)
               || flow->tp_src == htons(MLD_DONE)
               || flow->tp_src == htons(MLD2_REPORT));
}

static inline bool is_mld_query(const struct flow *flow)
{
    return is_icmpv6(flow) && flow->tp_src == htons(MLD_QUERY);
}

static inline bool is_mld_report(const struct flow *flow)
{
    return is_mld(flow) && !is_mld_query(flow);
}

static inline bool is_stp(const struct flow *flow)
{
    return (eth_addr_equals(flow->dl_dst, eth_addr_stp)
            && flow->dl_type == htons(FLOW_DL_TYPE_NONE));
}

#endif /* flow.h */
