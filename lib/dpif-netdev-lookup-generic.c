/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014, 2016, 2017 Nicira, Inc.
 * Copyright (c) 2019, 2020 Intel Corporation.
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

#include <config.h>
#include "dpif-netdev.h"
#include "dpif-netdev-private.h"
#include "dpif-netdev-lookup.h"

#include "bitmap.h"
#include "cmap.h"

#include "dp-packet.h"
#include "dpif.h"
#include "dpif-netdev-perf.h"
#include "dpif-provider.h"
#include "flow.h"
#include "ovs-thread.h"
#include "packets.h"
#include "pvector.h"

VLOG_DEFINE_THIS_MODULE(dpif_lookup_generic);

/* Lookup functions below depends on the internal structure of flowmap. */
BUILD_ASSERT_DECL(FLOWMAP_UNITS == 2);

struct block_array {
    uint32_t count; /* Number of items allocated in 'blocks' */
    uint64_t blocks[];
};

DEFINE_PER_THREAD_MALLOCED_DATA(struct block_array *, block_array);

static inline uint64_t *
get_blocks_scratch(uint32_t required_count)
{
    struct block_array *array = block_array_get();

    /* Check if this thread already has a large enough array allocated.
     * This is a predictable and unlikely branch, as it occurs only once at
     * startup, or if a subtable with higher block count is added.
     */
    if (OVS_UNLIKELY(!array || array->count < required_count)) {
        array = xrealloc(array, sizeof *array +
                         (required_count * sizeof array->blocks[0]));
        array->count = required_count;
        block_array_set_unsafe(array);
        VLOG_DBG("Block array resized to %"PRIu32, required_count);
    }

    return &array->blocks[0];
}

static inline void
netdev_flow_key_flatten_unit(const uint64_t *pkt_blocks,
                             const uint64_t *tbl_blocks,
                             const uint64_t *mf_masks,
                             uint64_t *blocks_scratch,
                             const uint64_t pkt_mf_bits,
                             const uint32_t count)
{
    uint32_t i;

    for (i = 0; i < count; i++) {
        uint64_t mf_mask = mf_masks[i];
        /* Calculate the block index for the packet metadata. */
        uint64_t idx_bits = mf_mask & pkt_mf_bits;
        const uint32_t pkt_idx = count_1bits(idx_bits);

        /* Check if the packet has the subtable miniflow bit set. If yes, the
         * block at the above pkt_idx will be stored, otherwise it is masked
         * out to be zero.
         */
        uint64_t pkt_has_mf_bit = (mf_mask + 1) & pkt_mf_bits;
        uint64_t no_bit = ((!pkt_has_mf_bit) > 0) - 1;

        /* Mask packet block by table block, and mask to zero if packet
         * doesn't actually contain this block of metadata.
         */
        blocks_scratch[i] = pkt_blocks[pkt_idx] & tbl_blocks[i] & no_bit;
    }
}

/* This function takes a packet, and subtable and writes an array of uint64_t
 * blocks. The blocks contain the metadata that the subtable matches on, in
 * the same order as the subtable, allowing linear iteration over the blocks.
 *
 * To calculate the blocks contents, the netdev_flow_key_flatten_unit function
 * is called twice, once for each "unit" of the miniflow. This call can be
 * inlined by the compiler for performance.
 *
 * Note that the u0_count and u1_count variables can be compile-time constants,
 * allowing the loop in the inlined flatten_unit() function to be compile-time
 * unrolled, or possibly removed totally by unrolling by the loop iterations.
 * The compile time optimizations enabled by this design improves performance.
 */
static inline void
netdev_flow_key_flatten(const struct netdev_flow_key *key,
                        const struct netdev_flow_key *mask,
                        const uint64_t *mf_masks,
                        uint64_t *blocks_scratch,
                        const uint32_t u0_count,
                        const uint32_t u1_count)
{
    /* Load mask from subtable, mask with packet mf, popcount to get idx. */
    const uint64_t *pkt_blocks = miniflow_get_values(&key->mf);
    const uint64_t *tbl_blocks = miniflow_get_values(&mask->mf);

    /* Packet miniflow bits to be masked by pre-calculated mf_masks. */
    const uint64_t pkt_bits_u0 = key->mf.map.bits[0];
    const uint32_t pkt_bits_u0_pop = count_1bits(pkt_bits_u0);
    const uint64_t pkt_bits_u1 = key->mf.map.bits[1];

    /* Unit 0 flattening */
    netdev_flow_key_flatten_unit(&pkt_blocks[0],
                                 &tbl_blocks[0],
                                 &mf_masks[0],
                                 &blocks_scratch[0],
                                 pkt_bits_u0,
                                 u0_count);

    /* Unit 1 flattening:
     * Move the pointers forward in the arrays based on u0 offsets, NOTE:
     * 1) pkt blocks indexed by actual popcount of u0, which is NOT always
     *    the same as the amount of bits set in the subtable.
     * 2) mf_masks, tbl_block and blocks_scratch are all "flat" arrays, so
     *    the index is always u0_count.
     */
    netdev_flow_key_flatten_unit(&pkt_blocks[pkt_bits_u0_pop],
                                 &tbl_blocks[u0_count],
                                 &mf_masks[u0_count],
                                 &blocks_scratch[u0_count],
                                 pkt_bits_u1,
                                 u1_count);
}

/* Compares a rule and the blocks representing a key, returns 1 on a match. */
static inline uint64_t
netdev_rule_matches_key(const struct dpcls_rule *rule,
                        const uint32_t mf_bits_total,
                        const uint64_t *blocks_scratch)
{
    const uint64_t *keyp = miniflow_get_values(&rule->flow.mf);
    const uint64_t *maskp = miniflow_get_values(&rule->mask->mf);
    uint64_t not_match = 0;

    for (int i = 0; i < mf_bits_total; i++) {
        not_match |= (blocks_scratch[i] & maskp[i]) != keyp[i];
    }

    /* Invert result to show match as 1. */
    return !not_match;
}

/* Const prop version of the function: note that mf bits total and u0 are
 * explicitly passed in here, while they're also available at runtime from the
 * subtable pointer. By making them compile time, we enable the compiler to
 * unroll loops and flatten out code-sequences based on the knowledge of the
 * mf_bits_* compile time values. This results in improved performance.
 *
 * Note: this function is marked with ALWAYS_INLINE to ensure the compiler
 * inlines the below code, and then uses the compile time constants to make
 * specialized versions of the runtime code. Without ALWAYS_INLINE, the
 * compiler might decide to not inline, and performance will suffer.
 */
static inline uint32_t ALWAYS_INLINE
lookup_generic_impl(struct dpcls_subtable *subtable,
                    uint32_t keys_map,
                    const struct netdev_flow_key *keys[],
                    struct dpcls_rule **rules,
                    const uint32_t bit_count_u0,
                    const uint32_t bit_count_u1)
{
    const uint32_t n_pkts = count_1bits(keys_map);
    ovs_assert(NETDEV_MAX_BURST >= n_pkts);
    uint32_t hashes[NETDEV_MAX_BURST];

    const uint32_t bit_count_total = bit_count_u0 + bit_count_u1;
    const uint32_t block_count_required = bit_count_total * NETDEV_MAX_BURST;
    uint64_t *mf_masks = subtable->mf_masks;
    int i;

    /* Blocks scratch is an optimization to re-use the same packet miniflow
     * block data when doing rule-verify. This reduces work done during lookup
     * and hence improves performance. The blocks_scratch array is stored as a
     * thread local variable, as each thread requires its own blocks memory.
     */
    uint64_t *blocks_scratch = get_blocks_scratch(block_count_required);

    /* Flatten the packet metadata into the blocks_scratch[] using subtable. */
    ULLONG_FOR_EACH_1 (i, keys_map) {
            netdev_flow_key_flatten(keys[i],
                                    &subtable->mask,
                                    mf_masks,
                                    &blocks_scratch[i * bit_count_total],
                                    bit_count_u0,
                                    bit_count_u1);
    }

    /* Hash the now linearized blocks of packet metadata. */
    ULLONG_FOR_EACH_1 (i, keys_map) {
        uint64_t *block_ptr = &blocks_scratch[i * bit_count_total];
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
            const uint32_t cidx = i * bit_count_total;
            uint32_t match = netdev_rule_matches_key(rule, bit_count_total,
                                                     &blocks_scratch[cidx]);

            if (OVS_LIKELY(match)) {
                rules[i] = rule;
                subtable->hit_cnt++;
                goto next;
            }
        }

        /* None of the found rules was a match.  Reset the i-th bit to
         * keep searching this key in the next subtable. */
        ULLONG_SET0(found_map, i);  /* Did not match. */
    next:
        ; /* Keep Sparse happy. */
    }

    return found_map;
}

/* Generic lookup function that uses runtime provided mf bits for iterating. */
static uint32_t
dpcls_subtable_lookup_generic(struct dpcls_subtable *subtable,
                              uint32_t keys_map,
                              const struct netdev_flow_key *keys[],
                              struct dpcls_rule **rules)
{
    /* Here the runtime subtable->mf_bits counts are used, which forces the
     * compiler to iterate normal for() loops. Due to this limitation in the
     * compilers available optimizations, this function has lower performance
     * than the below specialized functions.
     */
    return lookup_generic_impl(subtable, keys_map, keys, rules,
                               subtable->mf_bits_set_unit0,
                               subtable->mf_bits_set_unit1);
}

/* Expand out specialized functions with U0 and U1 bit attributes. */
#define DECLARE_OPTIMIZED_LOOKUP_FUNCTION(U0, U1)                             \
    static uint32_t                                                           \
    dpcls_subtable_lookup_mf_u0w##U0##_u1w##U1(                               \
                                         struct dpcls_subtable *subtable,     \
                                         uint32_t keys_map,                   \
                                         const struct netdev_flow_key *keys[],\
                                         struct dpcls_rule **rules)           \
    {                                                                         \
        return lookup_generic_impl(subtable, keys_map, keys, rules, U0, U1);  \
    }                                                                         \

DECLARE_OPTIMIZED_LOOKUP_FUNCTION(5, 1)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(4, 1)
DECLARE_OPTIMIZED_LOOKUP_FUNCTION(4, 0)

/* Check if a specialized function is valid for the required subtable. */
#define CHECK_LOOKUP_FUNCTION(U0, U1)                                          \
    if (!f && u0_bits == U0 && u1_bits == U1) {                               \
        f = dpcls_subtable_lookup_mf_u0w##U0##_u1w##U1;                       \
    }

/* Probe function to lookup an available specialized function.
 * If capable to run the requested miniflow fingerprint, this function returns
 * the most optimal implementation for that miniflow fingerprint.
 * @retval Non-NULL A valid function to handle the miniflow bit pattern
 * @retval NULL The requested miniflow is not supported by this implementation.
 */
dpcls_subtable_lookup_func
dpcls_subtable_generic_probe(uint32_t u0_bits, uint32_t u1_bits)
{
    dpcls_subtable_lookup_func f = NULL;

    CHECK_LOOKUP_FUNCTION(5, 1);
    CHECK_LOOKUP_FUNCTION(4, 1);
    CHECK_LOOKUP_FUNCTION(4, 0);

    if (f) {
        VLOG_DBG("Subtable using Generic Optimized for u0 %d, u1 %d\n",
                 u0_bits, u1_bits);
    } else {
        /* Always return the generic function. */
        f = dpcls_subtable_lookup_generic;
    }

    return f;
}
