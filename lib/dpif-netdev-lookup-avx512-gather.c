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
#include "dpif-netdev-private.h"
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
#define BLOCKS_CACHE_SIZE (NETDEV_MAX_BURST * NUM_U64_IN_ZMM_REG)


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

static inline uint64_t
netdev_rule_matches_key(const struct dpcls_rule *rule,
                        const uint32_t mf_bits_total,
                        const uint64_t * block_cache)
{
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);
    const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);
    const uint32_t lane_mask = (1 << mf_bits_total) - 1;

    /* Always load a full cache line from blocks_cache. Other loads must be
     * trimmed to the amount of data required for mf_bits_total blocks.
     */
    __m512i v_blocks = _mm512_loadu_si512(&block_cache[0]);
    __m512i v_mask   = _mm512_maskz_loadu_epi64(lane_mask, &maskp[0]);
    __m512i v_key    = _mm512_maskz_loadu_epi64(lane_mask, &keyp[0]);

    __m512i v_data = _mm512_and_si512(v_blocks, v_mask);
    uint32_t res_mask = _mm512_mask_cmpeq_epi64_mask(lane_mask, v_data, v_key);

    /* returns 1 assuming result of SIMD compare is all blocks. */
    return res_mask == lane_mask;
}

static inline uint32_t ALWAYS_INLINE
avx512_lookup_impl(struct dpcls_subtable *subtable,
                   uint32_t keys_map,
                   const struct netdev_flow_key *keys[],
                   struct dpcls_rule **rules,
                   const uint32_t bit_count_u0,
                   const uint32_t bit_count_u1)
{
    OVS_ALIGNED_VAR(CACHE_LINE_SIZE)uint64_t block_cache[BLOCKS_CACHE_SIZE];

    const uint32_t bit_count_total = bit_count_u0 + bit_count_u1;
    int i;
    uint32_t hashes[NETDEV_MAX_BURST];
    const uint32_t n_pkts = __builtin_popcountll(keys_map);
    ovs_assert(NETDEV_MAX_BURST >= n_pkts);

    const uint64_t tbl_u0 = subtable->mask.mf.map.bits[0];
    const uint64_t tbl_u1 = subtable->mask.mf.map.bits[1];

    /* Load subtable blocks for masking later. */
    const uint64_t *tbl_blocks = miniflow_get_values(&subtable->mask.mf);
    const __m512i v_tbl_blocks = _mm512_loadu_si512(&tbl_blocks[0]);

    /* Load pre-created subtable masks for each block in subtable. */
    const __mmask8 bit_count_total_mask = (1 << bit_count_total) - 1;
    const __m512i v_mf_masks = _mm512_maskz_loadu_epi64(bit_count_total_mask,
                                                        subtable->mf_masks);

    ULLONG_FOR_EACH_1 (i, keys_map) {
        const uint64_t pkt_mf_u0_bits = keys[i]->mf.map.bits[0];
        const uint64_t pkt_mf_u0_pop = __builtin_popcountll(pkt_mf_u0_bits);

        /* Pre-create register with *PER PACKET* u0 offset. */
        const __mmask8 u1_bcast_mask = (UINT8_MAX << bit_count_u0);
        const __m512i v_idx_u0_offset = _mm512_maskz_set1_epi64(u1_bcast_mask,
                                                                pkt_mf_u0_pop);

        /* Broadcast u0, u1 bitmasks to 8x u64 lanes. */
        __m512i v_u0 = _mm512_set1_epi64(pkt_mf_u0_bits);
        __m512i v_pkt_bits = _mm512_mask_set1_epi64(v_u0, u1_bcast_mask,
                                         keys[i]->mf.map.bits[1]);

        /* Bitmask by pre-created masks. */
        __m512i v_masks = _mm512_and_si512(v_pkt_bits, v_mf_masks);

        /* Manual AVX512 popcount for u64 lanes. */
        __m512i v_popcnts = _mm512_popcnt_epi64_manual(v_masks);

        /* Offset popcounts for u1 with pre-created offset register. */
        __m512i v_indexes = _mm512_add_epi64(v_popcnts, v_idx_u0_offset);

        /* Gather u64 blocks from packet miniflow. */
        const __m512i v_zeros = _mm512_setzero_si512();
        const void *pkt_data = miniflow_get_values(&keys[i]->mf);
        __m512i v_all_blocks = _mm512_mask_i64gather_epi64(v_zeros,
                                   bit_count_total_mask, v_indexes,
                                   pkt_data, 8);

        /* Zero out bits that pkt doesn't have:
         * - 2x pext() to extract bits from packet miniflow as needed by TBL
         * - Shift u1 over by bit_count of u0, OR to create zero bitmask
         */
         uint64_t u0_to_zero = _pext_u64(keys[i]->mf.map.bits[0], tbl_u0);
         uint64_t u1_to_zero = _pext_u64(keys[i]->mf.map.bits[1], tbl_u1);
         uint64_t zero_mask = (u1_to_zero << bit_count_u0) | u0_to_zero;

        /* Mask blocks using AND with subtable blocks, use k-mask to zero
         * where lanes as required for this packet.
         */
        __m512i v_masked_blocks = _mm512_maskz_and_epi64(zero_mask,
                                                v_all_blocks, v_tbl_blocks);

        /* Store to blocks cache, full cache line aligned. */
        _mm512_storeu_si512(&block_cache[i * 8], v_masked_blocks);
    }

    /* Hash the now linearized blocks of packet metadata. */
    ULLONG_FOR_EACH_1 (i, keys_map) {
        uint64_t *block_ptr = &block_cache[i * 8];
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
            const uint32_t cidx = i * 8;
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

/* Expand out specialized functions with U0 and U1 bit attributes. */
#define DECLARE_OPTIMIZED_LOOKUP_FUNCTION(U0, U1)                             \
    static uint32_t                                                           \
    dpcls_avx512_gather_mf_##U0##_##U1(struct dpcls_subtable *subtable,       \
                                       uint32_t keys_map,                     \
                                       const struct netdev_flow_key *keys[],  \
                                       struct dpcls_rule **rules)             \
    {                                                                         \
        return avx512_lookup_impl(subtable, keys_map, keys, rules, U0, U1);   \
    }                                                                         \

DECLARE_OPTIMIZED_LOOKUP_FUNCTION(5, 1)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(4, 1)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(4, 0)

/* Check if a specialized function is valid for the required subtable. */
#define CHECK_LOOKUP_FUNCTION(U0, U1)                                         \
    ovs_assert((U0 + U1) <= NUM_U64_IN_ZMM_REG);                              \
    if (!f && u0_bits == U0 && u1_bits == U1) {                               \
        f = dpcls_avx512_gather_mf_##U0##_##U1;                               \
    }

static uint32_t
dpcls_avx512_gather_mf_any(struct dpcls_subtable *subtable, uint32_t keys_map,
                           const struct netdev_flow_key *keys[],
                           struct dpcls_rule **rules)
{
    return avx512_lookup_impl(subtable, keys_map, keys, rules,
                              subtable->mf_bits_set_unit0,
                              subtable->mf_bits_set_unit1);
}

dpcls_subtable_lookup_func
dpcls_subtable_avx512_gather_probe(uint32_t u0_bits, uint32_t u1_bits)
{
    dpcls_subtable_lookup_func f = NULL;

    int avx512f_available = dpdk_get_cpu_has_isa("x86_64", "avx512f");
    int bmi2_available = dpdk_get_cpu_has_isa("x86_64", "bmi2");
    if (!avx512f_available || !bmi2_available) {
        return NULL;
    }

    CHECK_LOOKUP_FUNCTION(5, 1);
    CHECK_LOOKUP_FUNCTION(4, 1);
    CHECK_LOOKUP_FUNCTION(4, 0);

    if (!f && (u0_bits + u1_bits) < NUM_U64_IN_ZMM_REG) {
        f = dpcls_avx512_gather_mf_any;
        VLOG_INFO("Using avx512_gather_mf_any for subtable (%d,%d)\n",
                  u0_bits, u1_bits);
    }

    return f;
}

#endif /* CHECKER */
#endif /* __x86_64__ */
