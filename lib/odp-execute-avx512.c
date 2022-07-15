/*
 * Copyright (c) 2022 Intel.
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
/* Sparse cannot handle the AVX512 instructions. */
#if !defined(__CHECKER__)

#include <config.h>
#include <errno.h>

#include "dp-packet.h"
#include "immintrin.h"
#include "odp-execute.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(odp_execute_avx512);

/* The below three build asserts make sure that l2_5_ofs, l3_ofs, and l4_ofs
 * fields remain in the same order and offset to l2_padd_size. This is needed
 * as the avx512_dp_packet_resize_l2() function will manipulate those fields at
 * a fixed memory index based on the l2_padd_size offset. */
BUILD_ASSERT_DECL(offsetof(struct dp_packet, l2_pad_size) +
                  MEMBER_SIZEOF(struct dp_packet, l2_pad_size) ==
                  offsetof(struct dp_packet, l2_5_ofs));

BUILD_ASSERT_DECL(offsetof(struct dp_packet, l2_5_ofs) +
                  MEMBER_SIZEOF(struct dp_packet, l2_5_ofs) ==
                  offsetof(struct dp_packet, l3_ofs));

BUILD_ASSERT_DECL(offsetof(struct dp_packet, l3_ofs) +
                           MEMBER_SIZEOF(struct dp_packet, l3_ofs) ==
                           offsetof(struct dp_packet, l4_ofs));

/* The below build assert makes sure it's safe to read/write 128-bits starting
 * at the l2_pad_size location. */
BUILD_ASSERT_DECL(sizeof(struct dp_packet) -
                  offsetof(struct dp_packet, l2_pad_size) >= sizeof(__m128i));

/* The below build assert makes sure the order of the fields needed by
 * the set masked functions shuffle operations do not change. This should not
 * happen as these are defined under the Linux uapi. */
BUILD_ASSERT_DECL(offsetof(struct ovs_key_ethernet, eth_src) +
                  MEMBER_SIZEOF(struct ovs_key_ethernet, eth_src) ==
                  offsetof(struct ovs_key_ethernet, eth_dst));

/* Array of callback functions, one for each masked operation. */
odp_execute_action_cb impl_set_masked_funcs[__OVS_KEY_ATTR_MAX];

static inline void ALWAYS_INLINE
avx512_dp_packet_resize_l2(struct dp_packet *b, int resize_by_bytes)
{
    /* Update packet size/data pointers, same as the scalar implementation. */
    if (resize_by_bytes >= 0) {
        dp_packet_push_uninit(b, resize_by_bytes);
    } else {
        dp_packet_pull(b, -resize_by_bytes);
    }

    /* The next step is to update the l2_5_ofs, l3_ofs and l4_ofs fields which
     * the scalar implementation does with the  dp_packet_adjust_layer_offset()
     * function. */

    /* Set the v_zero register to all zero's. */
    const __m128i v_zeros = _mm_setzero_si128();

    /* Set the v_u16_max register to all one's. */
    const __m128i v_u16_max = _mm_cmpeq_epi16(v_zeros, v_zeros);

    /* Each lane represents 16 bits in a 12-bit register. In this case the
     * first three 16-bit values, which will map to the l2_5_ofs, l3_ofs and
     * l4_ofs fields. */
    const uint8_t k_lanes = 0b1110;

    /* Set all 16-bit words in the 128-bits v_offset register to the value we
     * need to add/substract from the l2_5_ofs, l3_ofs, and l4_ofs fields. */
    __m128i v_offset = _mm_set1_epi16(abs(resize_by_bytes));

    /* Load 128 bits from the dp_packet structure starting at the l2_pad_size
     * offset. */
    void *adjust_ptr = &b->l2_pad_size;
    __m128i v_adjust_src = _mm_loadu_si128(adjust_ptr);

    /* Here is the tricky part, we only need to update the value of the three
     * fields if they are not UINT16_MAX. The following function will return
     * a mask of lanes (read fields) that are not UINT16_MAX. It will do this
     * by comparing only the lanes we requested, k_lanes, and if they match
     * v_u16_max, the bit will be set. */
    __mmask8 k_cmp = _mm_mask_cmpneq_epu16_mask(k_lanes, v_adjust_src,
                                                v_u16_max);

    /* Based on the bytes adjust (positive, or negative) it will do the actual
     * add or subtraction. These functions will only operate on the lanes
     * (fields) requested based on k_cmp, i.e:
     *   k_cmp = [l2_5_ofs, l3_ofs, l4_ofs]
     *   for field in kcmp
     *       v_adjust_src[field] = v_adjust_src[field] + v_offset
     */
    __m128i v_adjust_wip;

    if (resize_by_bytes >= 0) {
        v_adjust_wip = _mm_mask_add_epi16(v_adjust_src, k_cmp,
                                          v_adjust_src, v_offset);
    } else {
        v_adjust_wip = _mm_mask_sub_epi16(v_adjust_src, k_cmp,
                                          v_adjust_src, v_offset);
    }

    /* Here we write back the full 128-bits. */
    _mm_storeu_si128(adjust_ptr, v_adjust_wip);
}

/* This function performs the same operation on each packet in the batch as
 * the scalar eth_pop_vlan() function. */
static void
action_avx512_pop_vlan(struct dp_packet_batch *batch,
                       const struct nlattr *a OVS_UNUSED)
{
    struct dp_packet *packet;

    /* Set the v_zero register to all zero's. */
    const __m128i v_zeros = _mm_setzero_si128();

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct vlan_eth_header *veh = dp_packet_eth(packet);

        if (veh && dp_packet_size(packet) >= sizeof *veh &&
            eth_type_vlan(veh->veth_type)) {

            /* Load the first 128-bits of l2 header into the v_ether register.
             * This result in the veth_dst/src and veth_type/tci of the
             * vlan_eth_header structure to be loaded. */
            __m128i v_ether = _mm_loadu_si128((void *) veh);

            /* This creates a 256-bit value containing the first four fields
             * of the vlan_eth_header plus 128 zero-bit. The result will be the
             * lowest 128-bits after the right shift, hence we shift the data
             * 128(zero)-bits minus the VLAN_HEADER_LEN, so we are left with
             * only the veth_dst and veth_src fields. */
            __m128i v_realign = _mm_alignr_epi8(v_ether, v_zeros,
                                                sizeof(__m128i) -
                                                VLAN_HEADER_LEN);

            /* Write back the modified ethernet header. */
            _mm_storeu_si128((void *) veh, v_realign);

            /* As we removed the VLAN_HEADER we now need to adjust all the
             * offsets. */
            avx512_dp_packet_resize_l2(packet, -VLAN_HEADER_LEN);
        }
    }
}

/* This function performs the same operation on each packet in the batch as
 * the scalar eth_push_vlan() function. */
static void
action_avx512_push_vlan(struct dp_packet_batch *batch, const struct nlattr *a)
{
    struct dp_packet *packet;
    const struct ovs_action_push_vlan *vlan = nl_attr_get(a);
    ovs_be16 tpid, tci;

    /* This shuffle mask is used below, and each position tells where to
     * move the bytes to. So here, the fourth byte in v_ether is moved to
     * byte location 0 in v_shift. The fifth is moved to 1, etc., etc.
     * The 0xFF is special it tells to fill that position with 0. */
    static const uint8_t vlan_push_shuffle_mask[16] = {
        4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15, 0xFF, 0xFF, 0xFF, 0xFF
    };

    /* Load the shuffle mask in v_index. */
    __m128i v_index = _mm_loadu_si128((void *) vlan_push_shuffle_mask);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        tpid = vlan->vlan_tpid;
        tci = vlan->vlan_tci;

        /* As we are about to insert the VLAN_HEADER we now need to adjust all
         * the offsets. */
        avx512_dp_packet_resize_l2(packet, VLAN_HEADER_LEN);

        char *pkt_data = (char *) dp_packet_data(packet);

        /* Build up the VLAN TCI/TPID in a single uint32_t. */
        const uint32_t tci_proc = tci & htons(~VLAN_CFI);
        const uint32_t tpid_tci = (tci_proc << 16) | tpid;

        /* Load the first 128-bits of the packet into the v_ether register.
         * Note that this includes the 4 unused bytes (VLAN_HEADER_LEN). */
        __m128i v_ether = _mm_loadu_si128((void *) pkt_data);

        /* Move(shuffle) the veth_dst and veth_src data to create room for
         * the vlan header. */
        __m128i v_shift = _mm_shuffle_epi8(v_ether, v_index);

        /* Copy(insert) the 32-bit VLAN header, tpid_tci, at the 3rd 32-bit
         * word offset, i.e. ofssetof(vlan_eth_header, veth_type) */
        __m128i v_vlan_hdr = _mm_insert_epi32(v_shift, tpid_tci, 3);

        /* Write back the modified ethernet header. */
        _mm_storeu_si128((void *) pkt_data, v_vlan_hdr);
    }
}

/* This function performs the same operation on each packet in the batch as
 * the scalar odp_eth_set_addrs() function. */
static void
action_avx512_eth_set_addrs(struct dp_packet_batch *batch,
                            const struct nlattr *a)
{
    const struct ovs_key_ethernet *key, *mask;
    struct dp_packet *packet;

    a = nl_attr_get(a);
    key = nl_attr_get(a);
    mask = odp_get_key_mask(a, struct ovs_key_ethernet);

    /* Read the content of the key(src) and mask in the respective registers.
     * We only load the src and dest addresses, which is only 96-bits and not
     * 128-bits. */
    __m128i v_src = _mm_maskz_loadu_epi32(0x7,(void *) key);
    __m128i v_mask = _mm_maskz_loadu_epi32(0x7, (void *) mask);


    /* These shuffle masks are used below, and each position tells where to
     * move the bytes to. So here, the fourth sixth byte in
     * ovs_key_ethernet is moved to byte location 0 in v_src/v_mask.
     * The seventh is moved to 1, etc., etc.
     * This swap is needed to move the src and dest MAC addresses in the
     * same order as in the ethernet packet. */
    static const uint8_t eth_shuffle[16] = {
        6, 7, 8, 9, 10, 11, 0, 1,
        2, 3, 4, 5, 0xFF, 0xFF, 0xFF, 0xFF
    };

    /* Load the shuffle mask in v_shuf. */
    __m128i v_shuf = _mm_loadu_si128((void *) eth_shuffle);

    /* Swap the key/mask src and dest addresses to the ethernet order. */
    v_src = _mm_shuffle_epi8(v_src, v_shuf);
    v_mask = _mm_shuffle_epi8(v_mask, v_shuf);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {

        struct eth_header *eh = dp_packet_eth(packet);

        if (!eh) {
            continue;
        }

        /* Load the first 128-bits of the packet into the v_ether register. */
        __m128i v_dst = _mm_loadu_si128((void *) eh);

        /* AND the v_mask to the packet data (v_dst). */
        __m128i dst_masked = _mm_andnot_si128(v_mask, v_dst);

        /* OR the new addresses (v_src) with the masked packet addresses
         * (dst_masked). */
        __m128i res = _mm_or_si128(v_src, dst_masked);

        /* Write back the modified ethernet addresses. */
        _mm_storeu_si128((void *) eh, res);
    }
}

static void
action_avx512_set_masked(struct dp_packet_batch *batch, const struct nlattr *a)
{
    const struct nlattr *mask = nl_attr_get(a);
    enum ovs_key_attr attr_type = nl_attr_type(mask);

    if (attr_type <= OVS_KEY_ATTR_MAX && impl_set_masked_funcs[attr_type]) {
        impl_set_masked_funcs[attr_type](batch, a);
    } else {
        odp_execute_scalar_action(batch, a);
    }
}

int
action_avx512_init(struct odp_execute_action_impl *self OVS_UNUSED)
{
    if (!action_avx512_isa_probe()) {
        return -ENOTSUP;
    }

    /* Set function pointers for actions that can be applied directly, these
     * are identified by OVS_ACTION_ATTR_*. */
    self->funcs[OVS_ACTION_ATTR_POP_VLAN] = action_avx512_pop_vlan;
    self->funcs[OVS_ACTION_ATTR_PUSH_VLAN] = action_avx512_push_vlan;
    self->funcs[OVS_ACTION_ATTR_SET_MASKED] = action_avx512_set_masked;

    /* Set function pointers for the individual operations supported by the
     * SET_MASKED action. */
    impl_set_masked_funcs[OVS_KEY_ATTR_ETHERNET] = action_avx512_eth_set_addrs;

    return 0;
}

#endif /* Sparse */

#else /* __x86_64__ */

#include <config.h>
#include <errno.h>
#include "odp-execute-private.h"
/* Function itself is required to be called, even in e.g. 32-bit builds.
 * This dummy init function ensures 32-bit builds succeed too.
 */

int
action_avx512_init(struct odp_execute_action_impl *self OVS_UNUSED)
{
  return -ENOTSUP;
}

#endif
