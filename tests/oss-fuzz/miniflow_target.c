#include <config.h>
#include "classifier.h"
#include "fuzzer.h"
#include "dp-packet.h"
#include "flow.h"
#include "openvswitch/ofp-match.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/match.h"
#include "classifier-private.h"
#include "util.h"

static void
shuffle_u32s(uint32_t *p, size_t n)
{
    for (; n > 1; n--, p++) {
        uint32_t *q = &p[random_range(n)];
        uint32_t tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

/* Returns a copy of 'src'.  The caller must eventually free the returned
 * miniflow with free(). */
static struct miniflow *
miniflow_clone__(const struct miniflow *src)
{
    struct miniflow *dst;
    size_t data_size;

    data_size = miniflow_alloc(&dst, 1, src);
    miniflow_clone(dst, src, data_size / sizeof(uint64_t));
    return dst;
}

/* Returns a hash value for 'flow', given 'basis'. */
static inline uint32_t
miniflow_hash__(const struct miniflow *flow, uint32_t basis)
{
    const uint64_t *p = miniflow_get_values(flow);
    size_t n_values = miniflow_n_values(flow);
    struct flowmap hash_map = FLOWMAP_EMPTY_INITIALIZER;
    uint32_t hash = basis;
    size_t idx;

    FLOWMAP_FOR_EACH_INDEX (idx, flow->map) {
        uint64_t value = *p++;

        if (value) {
            hash = hash_add64(hash, value);
            flowmap_set(&hash_map, idx, 1);
        }
    }
    map_t map;
    FLOWMAP_FOR_EACH_MAP (map, hash_map) {
        hash = hash_add64(hash, map);
    }

    return hash_finish(hash, n_values);
}

static uint32_t
random_value(void)
{
    static const uint32_t values_[] =
        { 0xffffffff, 0xaaaaaaaa, 0x55555555, 0x80000000,
          0x00000001, 0xface0000, 0x00d00d1e, 0xdeadbeef };

    return values_[random_range(ARRAY_SIZE(values_))];
}

static bool
choose(unsigned int n, unsigned int *idxp)
{
    if (*idxp < n) {
        return true;
    } else {
        *idxp -= n;
        return false;
    }
}

#define FLOW_U32S (FLOW_U64S * 2)

static bool
init_consecutive_values(int n_consecutive, struct flow *flow,
                        unsigned int *idxp)
{
    uint32_t *flow_u32 = (uint32_t *) flow;

    if (choose(FLOW_U32S - n_consecutive + 1, idxp)) {
        int i;

        for (i = 0; i < n_consecutive; i++) {
            flow_u32[i + *idxp] = random_value();
        }
        return true;
    } else {
        return false;
    }
}

static bool
next_random_flow(struct flow *flow, unsigned int idx)
{
    uint32_t *flow_u32 = (uint32_t *) flow;

    memset(flow, 0, sizeof *flow);

    /* Empty flow. */
    if (choose(1, &idx)) {
        return true;
    }

    /* All flows with a small number of consecutive nonzero values. */
    for (int i = 1; i <= 4; i++) {
        if (init_consecutive_values(i, flow, &idx)) {
            return true;
        }
    }

    /* All flows with a large number of consecutive nonzero values. */
    for (int i = FLOW_U32S - 4; i <= FLOW_U32S; i++) {
        if (init_consecutive_values(i, flow, &idx)) {
            return true;
        }
    }

    /* All flows with exactly two nonconsecutive nonzero values. */
    if (choose((FLOW_U32S - 1) * (FLOW_U32S - 2) / 2, &idx)) {
        int ofs1;

        for (ofs1 = 0; ofs1 < FLOW_U32S - 2; ofs1++) {
            int ofs2;

            for (ofs2 = ofs1 + 2; ofs2 < FLOW_U32S; ofs2++) {
                if (choose(1, &idx)) {
                    flow_u32[ofs1] = random_value();
                    flow_u32[ofs2] = random_value();
                    return true;
                }
            }
        }
        OVS_NOT_REACHED();
    }

    /* 16 randomly chosen flows with N >= 3 nonzero values. */
    if (choose(16 * (FLOW_U32S - 4), &idx)) {
        int n = idx / 16 + 3;

        for (int i = 0; i < n; i++) {
            flow_u32[i] = random_value();
        }
        shuffle_u32s(flow_u32, FLOW_U32S);

        return true;
    }

    return false;
}

static void
any_random_flow(struct flow *flow)
{
    static unsigned int max;
    if (!max) {
        while (next_random_flow(flow, max)) {
            max++;
        }
    }

    next_random_flow(flow, random_range(max));
}

static void
toggle_masked_flow_bits(struct flow *flow, const struct flow_wildcards *mask)
{
    const uint32_t *mask_u32 = (const uint32_t *) &mask->masks;
    uint32_t *flow_u32 = (uint32_t *) flow;
    int i;

    for (i = 0; i < FLOW_U32S; i++) {
        if (mask_u32[i] != 0) {
            uint32_t bit;

            do {
                bit = 1u << random_range(32);
            } while (!(bit & mask_u32[i]));
            flow_u32[i] ^= bit;
        }
    }
}

static void
wildcard_extra_bits(struct flow_wildcards *mask)
{
    uint32_t *mask_u32 = (uint32_t *) &mask->masks;
    int i;

    for (i = 0; i < FLOW_U32S; i++) {
        if (mask_u32[i] != 0) {
            uint32_t bit;

            do {
                bit = 1u << random_range(32);
            } while (!(bit & mask_u32[i]));
            mask_u32[i] &= ~bit;
        }
    }
}

static void
test_miniflow(struct flow *flow)
{
    struct miniflow *miniflow, *miniflow2, *miniflow3;
    struct flow flow2, flow3;
    struct flow_wildcards mask;
    struct minimask *minimask;
    int i;

    const uint64_t *flow_u64 = (const uint64_t *) flow;

    /* Convert flow to miniflow. */
    miniflow = miniflow_create(flow);

    /* Obtain miniflow hash. */
    uint32_t hash = miniflow_hash_5tuple(miniflow, 0);
    ignore(hash);

    /* Check that the flow equals its miniflow. */
    for (i = 0; i < FLOW_MAX_VLAN_HEADERS; i++) {
        ovs_assert(miniflow_get_vid(miniflow, i) ==
               vlan_tci_to_vid(flow->vlans[i].tci));
    }
    for (i = 0; i < FLOW_U64S; i++) {
        ovs_assert(miniflow_get(miniflow, i) == flow_u64[i]);
    }

    /* Check that the miniflow equals itself. */
    ovs_assert(miniflow_equal(miniflow, miniflow));

    /* Convert miniflow back to flow and verify that it's the same. */
    miniflow_expand(miniflow, &flow2);
    ovs_assert(flow_equal(flow, &flow2));
    /* Check that copying a miniflow works properly. */
    miniflow2 = miniflow_clone__(miniflow);
    ovs_assert(miniflow_equal(miniflow, miniflow2));
    ovs_assert(miniflow_hash__(miniflow, 0) == miniflow_hash__(miniflow2, 0));
    miniflow_expand(miniflow2, &flow3);
    ovs_assert(flow_equal(flow, &flow3));

    /* Check that masked matches work as expected for identical flows and
         * miniflows. */
    do {
            next_random_flow(&mask.masks, 1);
    } while (flow_wildcards_is_catchall(&mask));
    minimask = minimask_create(&mask);
    ovs_assert(minimask_is_catchall(minimask)
           == flow_wildcards_is_catchall(&mask));
    ovs_assert(miniflow_equal_in_minimask(miniflow, miniflow2, minimask));
    ovs_assert(miniflow_equal_flow_in_minimask(miniflow, &flow2, minimask));
    ovs_assert(miniflow_hash_in_minimask(miniflow, minimask, 0x12345678) ==
           flow_hash_in_minimask(flow, minimask, 0x12345678));
    ovs_assert(minimask_hash(minimask, 0) ==
           miniflow_hash__(&minimask->masks, 0));

    /* Check that masked matches work as expected for differing flows and
     * miniflows. */
    toggle_masked_flow_bits(&flow2, &mask);
    ovs_assert(!miniflow_equal_flow_in_minimask(miniflow, &flow2, minimask));
    miniflow3 = miniflow_create(&flow2);
    ovs_assert(!miniflow_equal_in_minimask(miniflow, miniflow3, minimask));

    free(miniflow);
    free(miniflow2);
    free(miniflow3);
    free(minimask);
}

static void
test_minimask_has_extra(struct flow *flow)
{
    struct flow_wildcards catchall;
    struct minimask *minicatchall;

    flow_wildcards_init_catchall(&catchall);
    minicatchall = minimask_create(&catchall);
    ovs_assert(minimask_is_catchall(minicatchall));

    struct flow_wildcards mask;
    struct minimask *minimask;

    mask.masks = *flow;
    minimask = minimask_create(&mask);
    ovs_assert(!minimask_has_extra(minimask, minimask));
    ovs_assert(minimask_has_extra(minicatchall, minimask)
           == !minimask_is_catchall(minimask));
    if (!minimask_is_catchall(minimask)) {
        struct minimask *minimask2;

        wildcard_extra_bits(&mask);
        minimask2 = minimask_create(&mask);
        ovs_assert(minimask_has_extra(minimask2, minimask));
        ovs_assert(!minimask_has_extra(minimask, minimask2));
        free(minimask2);
    }

    free(minimask);
    free(minicatchall);
}

static void
test_minimask_combine(struct flow *flow)
{
    struct flow_wildcards catchall;
    struct minimask *minicatchall;

    flow_wildcards_init_catchall(&catchall);
    minicatchall = minimask_create(&catchall);
    ovs_assert(minimask_is_catchall(minicatchall));

    struct minimask *minimask, *minimask2;
    struct flow_wildcards mask, mask2, combined, combined2;
    struct {
        struct minimask minicombined;
        uint64_t storage[FLOW_U64S];
    } m;
    struct flow flow2;

    mask.masks = *flow;
    minimask = minimask_create(&mask);

    minimask_combine(&m.minicombined, minimask, minicatchall, m.storage);
    ovs_assert(minimask_is_catchall(&m.minicombined));

    any_random_flow(&flow2);
    mask2.masks = flow2;
    minimask2 = minimask_create(&mask2);

    minimask_combine(&m.minicombined, minimask, minimask2, m.storage);
    flow_wildcards_and(&combined, &mask, &mask2);
    minimask_expand(&m.minicombined, &combined2);
    ovs_assert(flow_wildcards_equal(&combined, &combined2));

    free(minimask);
    free(minimask2);

    free(minicatchall);
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct dp_packet packet;
    struct flow flow;
    dp_packet_use_const(&packet, data, size);
    flow_extract(&packet, &flow);

    /* Do miniflow tests. */
    test_miniflow(&flow);
    test_minimask_has_extra(&flow);
    test_minimask_combine(&flow);

    return 0;
}
