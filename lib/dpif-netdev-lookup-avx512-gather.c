/*
 * Copyright (c) 2020, Intel Corporation.
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

#ifdef __x86_64__
#if !defined(__CHECKER__)

#include <config.h>

#include "dpif-netdev.h"
#include "dpif-netdev-lookup.h"

#include "cmap.h"
#include "flow.h"
#include "pvector.h"
#include "openvswitch/vlog.h"

#include "immintrin.h"

/* Each AVX512 register (zmm register in assembly notation) can contain up to
 * 512 bits, which is equivalent to 8 uint64_t variables. This is the maximum
 * number of miniflow blocks that can be processed in a single pass of the
 * AVX512 code at a time.
 */
#define NUM_U64_IN_ZMM_REG (8)

/* This implementation of AVX512 gather allows up to 16 blocks of MF data to be
 * present in the blocks_cache, hence the multiply by 2 in the blocks count.
 */
#define MF_BLOCKS_PER_PACKET (NUM_U64_IN_ZMM_REG * 2)

/* Blocks cache size is the maximum number of miniflow blocks that this
 * implementation of lookup can handle.
 */
#define BLOCKS_CACHE_SIZE (NETDEV_MAX_BURST * MF_BLOCKS_PER_PACKET)

/* The gather instruction can handle a scale for the size of the items to
 * gather. For uint64_t data, this scale is 8.
 */
#define GATHER_SCALE_8 (8)


VLOG_DEFINE_THIS_MODULE(dpif_lookup_avx512_gather);

static inline __m512i
_mm512_popcnt_epi64_manual(__m512i v_in)
{
    static const uint8_t pop_lut[64] = {
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
        0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    };
    __m512i v_pop_lut = _mm512_loadu_si512(pop_lut);

    __m512i v_in_srl8 = _mm512_srli_epi64(v_in, 4);
    __m512i v_nibble_mask = _mm512_set1_epi8(0xF);
    __m512i v_in_lo = _mm512_and_si512(v_in, v_nibble_mask);
    __m512i v_in_hi = _mm512_and_si512(v_in_srl8, v_nibble_mask);

    __m512i v_lo_pop = _mm512_shuffle_epi8(v_pop_lut, v_in_lo);
    __m512i v_hi_pop = _mm512_shuffle_epi8(v_pop_lut, v_in_hi);
    __m512i v_u8_pop = _mm512_add_epi8(v_lo_pop, v_hi_pop);

    return _mm512_sad_epu8(v_u8_pop, _mm512_setzero_si512());
}

/* Wrapper function required to enable ISA. First check if the compiler
 * supports the ISA itself. If the ISA is supported, enable it via the
 * attribute target.  If the ISA is not supported by the compiler it indicates
 * the compiler is too old or is not capable of compiling the requested ISA
 * level, so fallback to the integer manual implementation.
 */
#if HAVE_AVX512VPOPCNTDQ
static inline __m512i
__attribute__((__target__("avx512vpopcntdq")))
_mm512_popcnt_epi64_wrapper(__m512i v_in)
{
    return _mm512_popcnt_epi64(v_in);
}
#else
static inline __m512i
_mm512_popcnt_epi64_wrapper(__m512i v_in)
{
    return _mm512_popcnt_epi64_manual(v_in);
}
#endif

static inline uint64_t
netdev_rule_matches_key(const struct dpcls_rule *rule,
                        const uint32_t mf_bits_total,
                        const uint64_t * block_cache)
{
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);
    const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);
    const uint32_t lane_mask = (1ULL << mf_bits_total) - 1;

    /* Always load a full cache line from blocks_cache. Other loads must be
     * trimmed to the amount of data required for mf_bits_total blocks.
     */
    uint32_t res_mask;

    /* To avoid a loop, we have two iterations of a block of code here.
     * Note the scope brackets { } are used to avoid accidental variable usage
     * in the second iteration.
     */
    {
        __m512i v_blocks = _mm512_loadu_si512(&block_cache[0]);
        __m512i v_mask   = _mm512_maskz_loadu_epi64(lane_mask, &maskp[0]);
        __m512i v_key    = _mm512_maskz_loadu_epi64(lane_mask, &keyp[0]);
        __m512i v_data = _mm512_and_si512(v_blocks, v_mask);
        res_mask = _mm512_mask_cmpeq_epi64_mask(lane_mask, v_data, v_key);
    }

    if (mf_bits_total > 8) {
        uint32_t lane_mask_gt8 = lane_mask >> 8;
        __m512i v_blocks = _mm512_loadu_si512(&block_cache[8]);
        __m512i v_mask   = _mm512_maskz_loadu_epi64(lane_mask_gt8, &maskp[8]);
        __m512i v_key    = _mm512_maskz_loadu_epi64(lane_mask_gt8, &keyp[8]);
        __m512i v_data = _mm512_and_si512(v_blocks, v_mask);
        uint32_t c = _mm512_mask_cmpeq_epi64_mask(lane_mask_gt8, v_data,
                                                  v_key);
        res_mask |= (c << 8);
    }

    /* Returns 1 assuming result of SIMD compare is all blocks matching. */
    return res_mask == lane_mask;
}

/* Takes u0 and u1 inputs, and gathers the next 8 blocks to be stored
 * contiguously into the blocks cache. Note that the pointers and bitmasks
 * passed into this function must be incremented for handling next 8 blocks.
 *
 * Register contents on entry:
 *   v_u0: register with all u64 lanes filled with u0 bits.
 *   v_u1: register with all u64 lanes filled with u1 bits.
 *   pkt_blocks: pointer to packet blocks.
 *   tbl_blocks: pointer to table blocks.
 *   tbl_mf_masks: pointer to miniflow bitmasks for this subtable.
 *   u1_bcast_msk: bitmask of lanes where u1 bits are used.
 *   pkt_mf_u0_pop: population count of bits in u0 of the packet.
 *   zero_mask: bitmask of lanes to zero as packet doesn't have mf bits set.
 *   u64_lanes_mask: bitmask of lanes to process.
 *   use_vpop: compile-time constant indicating if VPOPCNT instruction allowed.
 */
static inline ALWAYS_INLINE __m512i
avx512_blocks_gather(__m512i v_u0,
                     __m512i v_u1,
                     const void *pkt_blocks,
                     const void *tbl_blocks,
                     const void *tbl_mf_masks,
                     __mmask64 u1_bcast_msk,
                     const uint64_t pkt_mf_u0_pop,
                     __mmask64 zero_mask,
                     __mmask64 u64_lanes_mask,
                     const uint32_t use_vpop)
{
        /* Suggest to compiler to load tbl blocks ahead of gather(). */
        __m512i v_tbl_blocks = _mm512_maskz_loadu_epi64(u64_lanes_mask,
                                                        tbl_blocks);

        /* Blend u0 and u1 bits together for these 8 blocks. */
        __m512i v_pkt_bits = _mm512_mask_blend_epi64(u1_bcast_msk, v_u0, v_u1);

        /* Load pre-created tbl miniflow bitmasks, bitwise AND with them. */
        __m512i v_tbl_masks = _mm512_maskz_loadu_epi64(u64_lanes_mask,
                                                      tbl_mf_masks);
        __m512i v_masks = _mm512_and_si512(v_pkt_bits, v_tbl_masks);

        /* Calculate AVX512 popcount for u64 lanes using the native instruction
         * if available, or using emulation if not available.
         */
        __m512i v_popcnts;
        if (use_vpop) {
            v_popcnts = _mm512_popcnt_epi64_wrapper(v_masks);
        } else {
            v_popcnts = _mm512_popcnt_epi64_manual(v_masks);
        }

        /* Add popcounts and offset for u1 bits. */
        __m512i v_idx_u0_offset = _mm512_maskz_set1_epi64(u1_bcast_msk,
                                                          pkt_mf_u0_pop);
        __m512i v_indexes = _mm512_add_epi64(v_popcnts, v_idx_u0_offset);

        /* Gather u64 blocks from packet miniflow. */
        __m512i v_zeros = _mm512_setzero_si512();
        __m512i v_blocks = _mm512_mask_i64gather_epi64(v_zeros, u64_lanes_mask,
                                                       v_indexes, pkt_blocks,
                                                       GATHER_SCALE_8);

        /* Mask pkt blocks with subtable blocks, k-mask to zero lanes. */
        __m512i v_masked_blocks = _mm512_maskz_and_epi64(zero_mask, v_blocks,
                                                         v_tbl_blocks);
        return v_masked_blocks;
}

static inline uint32_t ALWAYS_INLINE
avx512_lookup_impl(struct dpcls_subtable *subtable,
                   uint32_t keys_map,
                   const struct netdev_flow_key *keys[],
                   struct dpcls_rule **rules,
                   const uint32_t bit_count_u0,
                   const uint32_t bit_count_u1,
                   const uint32_t use_vpop)
{
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)uint64_t block_cache[BLOCKS_CACHE_SIZE];
    uint32_t hashes[NETDEV_MAX_BURST];

    const uint32_t n_pkts = __builtin_popcountll(keys_map);
    ovs_assert(NETDEV_MAX_BURST >= n_pkts);

    const uint32_t bit_count_total = bit_count_u0 + bit_count_u1;
    const uint64_t bit_count_total_mask = (1ULL << bit_count_total) - 1;

    const uint64_t tbl_u0 = subtable->mask.mf.map.bits[0];
    const uint64_t tbl_u1 = subtable->mask.mf.map.bits[1];

    const uint64_t *tbl_blocks = miniflow_get_values(&subtable->mask.mf);
    const uint64_t *tbl_mf_masks = subtable->mf_masks;

    int i;
    ULLONG_FOR_EACH_1 (i, keys_map) {
        /* Create mask register with packet-specific u0 offset.
         * Note that as 16 blocks can be handled in total, the width of the
         * mask register must be >=16.
         */
        const uint64_t pkt_mf_u0_bits = keys[i]->mf.map.bits[0];
        const uint64_t pkt_mf_u0_pop = __builtin_popcountll(pkt_mf_u0_bits);
        const __mmask64 u1_bcast_mask = (UINT64_MAX << bit_count_u0);

        /* Broadcast u0, u1 bitmasks to 8x u64 lanes. */
        __m512i v_u0 = _mm512_set1_epi64(keys[i]->mf.map.bits[0]);
        __m512i v_u1 = _mm512_set1_epi64(keys[i]->mf.map.bits[1]);

        /* Zero out bits that pkt doesn't have:
         * - 2x pext() to extract bits from packet miniflow as needed by TBL
         * - Shift u1 over by bit_count of u0, OR to create zero bitmask
         */
        uint64_t u0_to_zero = _pext_u64(keys[i]->mf.map.bits[0], tbl_u0);
        uint64_t u1_to_zero = _pext_u64(keys[i]->mf.map.bits[1], tbl_u1);
        const uint64_t zero_mask_wip = (u1_to_zero << bit_count_u0) |
                                       u0_to_zero;
        const uint64_t zero_mask = zero_mask_wip & bit_count_total_mask;

        /* Get ptr to packet data blocks. */
        const uint64_t *pkt_blocks = miniflow_get_values(&keys[i]->mf);

        /* Store first 8 blocks cache, full cache line aligned. */
        __m512i v_blocks = avx512_blocks_gather(v_u0, v_u1,
                                                &pkt_blocks[0],
                                                &tbl_blocks[0],
                                                &tbl_mf_masks[0],
                                                u1_bcast_mask,
                                                pkt_mf_u0_pop,
                                                zero_mask,
                                                bit_count_total_mask,
                                                use_vpop);
        _mm512_storeu_si512(&block_cache[i * MF_BLOCKS_PER_PACKET], v_blocks);

        if (bit_count_total > 8) {
            /* Shift masks over by 8.
             * Pkt blocks pointer remains 0, it is incremented by popcount.
             * Move tbl and mf masks pointers forward.
             * Increase offsets by 8.
             * Re-run same gather code.
             */
            uint64_t zero_mask_gt8 = (zero_mask >> 8);
            uint64_t u1_bcast_mask_gt8 = (u1_bcast_mask >> 8);
            uint64_t bit_count_gt8_mask = bit_count_total_mask >> 8;

            __m512i v_blocks_gt8 = avx512_blocks_gather(v_u0, v_u1,
                                                    &pkt_blocks[0],
                                                    &tbl_blocks[8],
                                                    &tbl_mf_masks[8],
                                                    u1_bcast_mask_gt8,
                                                    pkt_mf_u0_pop,
                                                    zero_mask_gt8,
                                                    bit_count_gt8_mask,
                                                    use_vpop);
            _mm512_storeu_si512(&block_cache[(i * MF_BLOCKS_PER_PACKET) + 8],
                                v_blocks_gt8);
        }

    }

    /* Hash the now linearized blocks of packet metadata. */
    ULLONG_FOR_EACH_1 (i, keys_map) {
        uint64_t *block_ptr = &block_cache[i * MF_BLOCKS_PER_PACKET];
        uint32_t hash = hash_add_words64(0, block_ptr, bit_count_total);
        hashes[i] = hash_finish(hash, bit_count_total * 8);
    }

    /* Lookup: this returns a bitmask of packets where the hash table had
     * an entry for the given hash key. Presence of a hash key does not
     * guarantee matching the key, as there can be hash collisions.
     */
    uint32_t found_map;
    const struct cmap_node *nodes[NETDEV_MAX_BURST];
    found_map = cmap_find_batch(&subtable->rules, keys_map, hashes, nodes);

    /* Verify that packet actually matched rule. If not found, a hash
     * collision has taken place, so continue searching with the next node.
     */
    ULLONG_FOR_EACH_1 (i, found_map) {
        struct dpcls_rule *rule;

        CMAP_NODE_FOR_EACH (rule, cmap_node, nodes[i]) {
            const uint32_t cidx = i * MF_BLOCKS_PER_PACKET;
            uint32_t match = netdev_rule_matches_key(rule, bit_count_total,
                                                     &block_cache[cidx]);
            if (OVS_LIKELY(match)) {
                rules[i] = rule;
                subtable->hit_cnt++;
                goto next;
            }
        }

        /* None of the found rules was a match.  Clear the i-th bit to
         * search for this key in the next subtable. */
        ULLONG_SET0(found_map, i);
    next:
        ;                     /* Keep Sparse happy. */
    }

    return found_map;
}

/* Use a different pattern to conditionally use the VPOPCNTDQ target attribute
 * here.
 * The usual pattern using a '#if HAVE_AVX512VPOPCNTDQ' type check won't work
 * inside a macro.
 * Define VPOPCNTDQ_TARGET which will either be the "avx512vpopcntdq" target
 * attribute or nothing depending on AVX512VPOPCNTDQ support in the compiler.
 */
#if HAVE_AVX512VPOPCNTDQ
#define VPOPCNTDQ_TARGET __attribute__((__target__("avx512vpopcntdq")))
#else
#define VPOPCNTDQ_TARGET
#endif

/* Expand out specialized functions with U0 and U1 bit attributes. As the
 * AVX512 vpopcnt instruction is not supported on all AVX512 capable CPUs,
 * create two functions for each miniflow signature. This allows the runtime
 * CPU detection in probe() to select the ideal implementation.
 */
#define DECLARE_OPTIMIZED_LOOKUP_FUNCTION(U0, U1)                             \
    static uint32_t                                                           \
    dpcls_avx512_gather_mf_##U0##_##U1(struct dpcls_subtable *subtable,       \
                                       uint32_t keys_map,                     \
                                       const struct netdev_flow_key *keys[],  \
                                       struct dpcls_rule **rules)             \
    {                                                                         \
        const uint32_t use_vpop = 0;                                          \
        return avx512_lookup_impl(subtable, keys_map, keys, rules,            \
                                  U0, U1, use_vpop);                          \
    }                                                                         \
                                                                              \
    static uint32_t VPOPCNTDQ_TARGET                                          \
    dpcls_avx512_gather_mf_##U0##_##U1##_vpop(struct dpcls_subtable *subtable,\
                                       uint32_t keys_map,                     \
                                       const struct netdev_flow_key *keys[],  \
                                       struct dpcls_rule **rules)             \
    {                                                                         \
        const uint32_t use_vpop = 1;                                          \
        return avx512_lookup_impl(subtable, keys_map, keys, rules,            \
                                  U0, U1, use_vpop);                          \
    }                                                                         \

DECLARE_OPTIMIZED_LOOKUP_FUNCTION(9, 4)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(9, 1)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(8, 1)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(5, 3)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(5, 2)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(5, 1)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(4, 1)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(4, 0)

/* Check if a specialized function is valid for the required subtable.
 * The use_vpop variable is used to decide if the VPOPCNT instruction can be
 * used or not.
 */
#define CHECK_LOOKUP_FUNCTION(U0, U1, use_vpop)                               \
    ovs_assert((U0 + U1) <= (NUM_U64_IN_ZMM_REG * 2));                        \
    if (!f && u0_bits == U0 && u1_bits == U1) {                               \
        if (use_vpop) {                                                       \
            f = dpcls_avx512_gather_mf_##U0##_##U1##_vpop;                    \
        } else {                                                              \
            f = dpcls_avx512_gather_mf_##U0##_##U1;                           \
        }                                                                     \
    }

static uint32_t
dpcls_avx512_gather_mf_any(struct dpcls_subtable *subtable, uint32_t keys_map,
                           const struct netdev_flow_key *keys[],
                           struct dpcls_rule **rules)
{
    const uint32_t use_vpop = 0;
    return avx512_lookup_impl(subtable, keys_map, keys, rules,
                              subtable->mf_bits_set_unit0,
                              subtable->mf_bits_set_unit1,
                              use_vpop);
}

dpcls_subtable_lookup_func
dpcls_subtable_avx512_gather_probe__(uint32_t u0_bits, uint32_t u1_bits,
                                     bool use_vpop)
{
    dpcls_subtable_lookup_func f = NULL;

    CHECK_LOOKUP_FUNCTION(9, 4, use_vpop);
    CHECK_LOOKUP_FUNCTION(9, 1, use_vpop);
    CHECK_LOOKUP_FUNCTION(8, 1, use_vpop);
    CHECK_LOOKUP_FUNCTION(5, 3, use_vpop);
    CHECK_LOOKUP_FUNCTION(5, 2, use_vpop);
    CHECK_LOOKUP_FUNCTION(5, 1, use_vpop);
    CHECK_LOOKUP_FUNCTION(4, 1, use_vpop);
    CHECK_LOOKUP_FUNCTION(4, 0, use_vpop);

    /* Check if the _any looping version of the code can perform this miniflow
     * lookup. Performance gain may be less pronounced due to non-specialized
     * hashing, however there is usually a good performance win overall.
     */
    if (!f && (u0_bits + u1_bits) < (NUM_U64_IN_ZMM_REG * 2)) {
        f = dpcls_avx512_gather_mf_any;
        VLOG_INFO_ONCE("Using non-specialized AVX512 lookup for subtable"
                       " (%d,%d) and possibly others.", u0_bits, u1_bits);
    }

    return f;
}

#endif /* CHECKER */
#endif /* __x86_64__ */
