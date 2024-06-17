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
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

#include "csum.h"
#include "dp-packet.h"
#include "immintrin.h"
#include "odp-execute.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "openvswitch/vlog.h"
#include "packets.h"

VLOG_DEFINE_THIS_MODULE(odp_execute_avx512);

/* The below build asserts make sure that the below fields remain in the same
 * order and offset to l2_pad_size. This is needed as the
 * avx512_dp_packet_resize_l2() function will manipulate those fields at a
 * fixed memory index based on the l2_pad_size offset. */
BUILD_ASSERT_DECL(offsetof(struct dp_packet, l2_pad_size) +
                  MEMBER_SIZEOF(struct dp_packet, l2_pad_size) ==
                  offsetof(struct dp_packet, l2_5_ofs));

BUILD_ASSERT_DECL(offsetof(struct dp_packet, l2_5_ofs) +
                  MEMBER_SIZEOF(struct dp_packet, l2_5_ofs) ==
                  offsetof(struct dp_packet, l3_ofs));

BUILD_ASSERT_DECL(offsetof(struct dp_packet, l3_ofs) +
                           MEMBER_SIZEOF(struct dp_packet, l3_ofs) ==
                           offsetof(struct dp_packet, l4_ofs));

BUILD_ASSERT_DECL(offsetof(struct dp_packet, l4_ofs) +
                           MEMBER_SIZEOF(struct dp_packet, l4_ofs) ==
                           offsetof(struct dp_packet, inner_l3_ofs));

BUILD_ASSERT_DECL(offsetof(struct dp_packet, inner_l3_ofs) +
                           MEMBER_SIZEOF(struct dp_packet, inner_l3_ofs) ==
                           offsetof(struct dp_packet, inner_l4_ofs));

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

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv4, ipv4_src) +
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_src) ==
                  offsetof(struct ovs_key_ipv4, ipv4_dst));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv4, ipv4_dst) +
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_dst) ==
                  offsetof(struct ovs_key_ipv4, ipv4_proto));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv4, ipv4_proto) +
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_proto) ==
                  offsetof(struct ovs_key_ipv4, ipv4_tos));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv4, ipv4_tos) +
                  MEMBER_SIZEOF(struct ovs_key_ipv4, ipv4_tos) ==
                  offsetof(struct ovs_key_ipv4, ipv4_ttl));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv6, ipv6_src) +
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_src) ==
                  offsetof(struct ovs_key_ipv6, ipv6_dst));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv6, ipv6_dst) +
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_dst) ==
                  offsetof(struct ovs_key_ipv6, ipv6_label));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv6, ipv6_label) +
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_label) ==
                  offsetof(struct ovs_key_ipv6, ipv6_proto));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv6, ipv6_proto) +
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_proto) ==
                  offsetof(struct ovs_key_ipv6, ipv6_tclass));

BUILD_ASSERT_DECL(offsetof(struct ovs_key_ipv6, ipv6_tclass) +
                  MEMBER_SIZEOF(struct ovs_key_ipv6, ipv6_tclass) ==
                  offsetof(struct ovs_key_ipv6, ipv6_hlimit));

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

    /* The next step is to update the l2_5_ofs to inner_l4_ofs fields which
     * the scalar implementation does with the  dp_packet_adjust_layer_offset()
     * function. */

    /* Set the v_zero register to all zero's. */
    const __m128i v_zeros = _mm_setzero_si128();

    /* Set the v_u16_max register to all one's. */
    const __m128i v_u16_max = _mm_cmpeq_epi16(v_zeros, v_zeros);

    /* Each lane represents 16 bits in a 128-bit register. Here the bitmask
     * starts at l2_5_ofs with a value of 0 indicating it is not modified. Then
     * five 1's to indicate modificaiton of all fields from l2_5_ofs to
     * inner_l4_ofs. */
    const uint8_t k_lanes = 0b111110;

    /* Set all 16-bit words in the 128-bits v_offset register to the value we
     * need to add/substract from the l2_5_ofs to inner_l4_ofs fields. */
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
     *   k_cmp = [l2_5_ofs, ..., inner_l4_ofs]
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

static inline uint16_t ALWAYS_INLINE
avx512_get_delta(__m256i old_header, __m256i new_header)
{
    __m256i v_zeros = _mm256_setzero_si256();

    /* These two shuffle masks, v_swap16a and v_swap16b, are to shuffle the
     * old and new header to add padding after each 16-bit value for the
     * following carry over addition. */
    __m256i v_swap16a = _mm256_setr_epi16(0x0100, 0xFFFF, 0x0302, 0xFFFF,
                                          0x0504, 0xFFFF, 0x0706, 0xFFFF,
                                          0x0100, 0xFFFF, 0x0302, 0xFFFF,
                                          0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
    __m256i v_swap16b = _mm256_setr_epi16(0x0908, 0xFFFF, 0x0B0A, 0xFFFF,
                                          0x0D0C, 0xFFFF, 0x0F0E, 0xFFFF,
                                          0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
                                          0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF);
    __m256i v_shuf_old1 = _mm256_shuffle_epi8(old_header, v_swap16a);
    __m256i v_shuf_old2 = _mm256_shuffle_epi8(old_header, v_swap16b);
    __m256i v_shuf_new1 = _mm256_shuffle_epi8(new_header, v_swap16a);
    __m256i v_shuf_new2 = _mm256_shuffle_epi8(new_header, v_swap16b);

    /* Add each part of the old and new headers together. */
    __m256i v_delta1 = _mm256_add_epi32(v_shuf_old1, v_shuf_new1);
    __m256i v_delta2 = _mm256_add_epi32(v_shuf_old2, v_shuf_new2);

    /* Add old and new header. */
    __m256i v_delta = _mm256_add_epi32(v_delta1, v_delta2);

    /* Perform horizontal add to go from 8x32-bits to 2x32-bits. */
    v_delta = _mm256_hadd_epi32(v_delta, v_zeros);
    v_delta = _mm256_hadd_epi32(v_delta, v_zeros);

    /* Shuffle 32-bit value from 3rd lane into first lane for final
     * horizontal add. */
    __m256i v_swap32a = _mm256_setr_epi32(0x0, 0x4, 0xF, 0xF,
                                          0xF, 0xF, 0xF, 0xF);
    v_delta = _mm256_permutexvar_epi32(v_swap32a, v_delta);

    v_delta = _mm256_hadd_epi32(v_delta, v_zeros);
    v_delta = _mm256_shuffle_epi8(v_delta, v_swap16a);
    v_delta = _mm256_hadd_epi32(v_delta, v_zeros);
    v_delta = _mm256_hadd_epi16(v_delta, v_zeros);

    /* Extract delta value. */
    return _mm256_extract_epi16(v_delta, 0);
}

/* This function will calculate the csum delta for the IPv4 addresses in the
 * new_header and old_header, assuming the csum field on the new_header was
 * updated. */
static inline uint16_t ALWAYS_INLINE
avx512_ipv4_addr_csum_delta(__m256i old_header, __m256i new_header)
{
    __m256i v_zeros = _mm256_setzero_si256();

    /* Set the v_ones register to all one's. */
    __m256i v_ones = _mm256_cmpeq_epi16(v_zeros, v_zeros);

    /* Combine the old and new header, i.e. adding in the new IP addresses
     * in the old header (oh). This is done by using the 0x03C 16-bit mask,
     * picking 16-bit word 7 till 10.  */
    __m256i v_blend_new = _mm256_mask_blend_epi16(0x03C0, old_header,
                                                  new_header);

    /* Invert the old_header register. */
    old_header =_mm256_andnot_si256(old_header, v_ones);

    /* Calculate the delta between the old and new header. */
    return avx512_get_delta(old_header, v_blend_new);
}

/* This function will calculate the csum delta between the new_header and
 * old_header, assuming the csum field on the new_header was not yet updated
 * or reset. It also assumes headers contain the first 20-bytes of the IPv4
 * header data, and the rest is zeroed out. */
static inline uint16_t ALWAYS_INLINE
avx512_ipv4_hdr_csum_delta(__m256i old_header, __m256i new_header)
{
    __m256i v_zeros = _mm256_setzero_si256();

    /* Set the v_ones register to all one's. */
    __m256i v_ones = _mm256_cmpeq_epi16(v_zeros, v_zeros);

    /* Invert the old_header register. */
    old_header =_mm256_andnot_si256(old_header, v_ones);

    /* Calculate the delta between the old and new header. */
    return avx512_get_delta(old_header, new_header);
}

/* This function performs the same operation on each packet in the batch as
 * the scalar odp_set_ipv4() function. */
static void
action_avx512_ipv4_set_addrs(struct dp_packet_batch *batch,
                             const struct nlattr *a)
{
    const struct ovs_key_ipv4 *key, *mask;
    struct dp_packet *packet;
    a = nl_attr_get(a);
    key = nl_attr_get(a);
    mask = odp_get_key_mask(a, struct ovs_key_ipv4);

    /* Read the content of the key(src) and mask in the respective registers.
     * We only load the size of the actual structure, which is only 96-bits. */
    __m256i v_key = _mm256_maskz_loadu_epi32(0x7, (void *) key);
    __m256i v_mask = _mm256_maskz_loadu_epi32(0x7, (void *) mask);

    /* This two shuffle masks, v_shuf32, v_shuffle, are to shuffle key and
     * mask to match the ip_header structure layout. */
    static const uint8_t ip_shuffle_mask[32] = {
            0xFF, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x06, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0x02, 0x03,
            0x00, 0x01, 0x02, 0x03, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    __m256i v_shuf32 = _mm256_setr_epi32(0x0, 0x2, 0xF, 0xF,
                                         0x1, 0xF, 0xF, 0xF);

    __m256i v_shuffle = _mm256_loadu_si256((void *) ip_shuffle_mask);

    /* Two shuffles are required for key and mask to match the layout of
     * the ip_header struct. The _shuffle_epi8 only works within 128-bit
     * lanes, so a permute is required to move src and dst into the correct
     * lanes. And then a shuffle is used to move the fields into the right
     * order. */
    __m256i v_key_shuf = _mm256_permutexvar_epi32(v_shuf32, v_key);
    v_key_shuf = _mm256_shuffle_epi8(v_key_shuf, v_shuffle);

    __m256i v_mask_shuf = _mm256_permutexvar_epi32(v_shuf32, v_mask);
    v_mask_shuf = _mm256_shuffle_epi8(v_mask_shuf, v_shuffle);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct ip_header *nh = dp_packet_l3(packet);

        /* Load the 20 bytes of the IPv4 header. Without options, which is the
         * most common case it's 20 bytes, but can be up to 60 bytes. */
        __m256i v_packet = _mm256_maskz_loadu_epi32(0x1F, (void *) nh);

        /* AND the v_pkt_mask to the packet data (v_packet). */
        __m256i v_pkt_masked = _mm256_andnot_si256(v_mask_shuf, v_packet);

        /* OR the new addresses (v_key_shuf) with the masked packet addresses
         * (v_pkt_masked). */
        __m256i v_new_hdr = _mm256_or_si256(v_key_shuf, v_pkt_masked);

        if (dp_packet_hwol_l3_ipv4(packet)) {
            dp_packet_ol_reset_ip_csum_good(packet);
        } else {
            ovs_be16 old_csum = ~nh->ip_csum;

            /* Update the IP checksum based on updated IP values. */
            uint16_t delta = avx512_ipv4_hdr_csum_delta(v_packet, v_new_hdr);
            uint32_t new_csum = old_csum + delta;

            delta = csum_finish(new_csum);

            /* Insert new checksum. */
            v_new_hdr = _mm256_insert_epi16(v_new_hdr, delta, 5);
        }

        /* If ip_src or ip_dst has been modified, L4 checksum needs to
         * be updated too. */
        if (mask->ipv4_src || mask->ipv4_dst) {

            uint16_t delta_checksum = avx512_ipv4_addr_csum_delta(v_packet,
                                                                  v_new_hdr);
            size_t l4_size = dp_packet_l4_size(packet);

            if (nh->ip_proto == IPPROTO_UDP && l4_size >= UDP_HEADER_LEN) {
                struct udp_header *uh = dp_packet_l4(packet);
                if (dp_packet_hwol_l4_is_udp(packet)) {
                    dp_packet_ol_reset_l4_csum_good(packet);
                } else if (uh->udp_csum) {
                    /* New UDP checksum. */
                    uint16_t old_udp_checksum = ~uh->udp_csum;
                    uint32_t udp_checksum = old_udp_checksum + delta_checksum;
                    udp_checksum = csum_finish(udp_checksum);

                    if (!udp_checksum) {
                        udp_checksum = htons(0xffff);
                    }
                    /* Insert new udp checksum. */
                    uh->udp_csum = udp_checksum;
                }
            } else if (nh->ip_proto == IPPROTO_TCP &&
                       l4_size >= TCP_HEADER_LEN) {
                if (dp_packet_hwol_l4_is_tcp(packet)) {
                    dp_packet_ol_reset_l4_csum_good(packet);
                } else {
                    /* New TCP checksum. */
                    struct tcp_header *th = dp_packet_l4(packet);
                    uint16_t old_tcp_checksum = ~th->tcp_csum;
                    uint32_t tcp_checksum = old_tcp_checksum + delta_checksum;
                    tcp_checksum = csum_finish(tcp_checksum);

                    th->tcp_csum = tcp_checksum;
                }
            }

            pkt_metadata_init_conn(&packet->md);
        }
        /* Write back the modified IPv4 addresses. */
        _mm256_mask_storeu_epi32((void *) nh, 0x1F, v_new_hdr);
    }
}

#if HAVE_AVX512VBMI
static inline uint16_t ALWAYS_INLINE
__attribute__((__target__("avx512vbmi")))
avx512_ipv6_sum_header(__m512i ip6_header)
{
    __m256i v_zeros = _mm256_setzero_si256();
    __m512i v_shuf_src_dst = _mm512_setr_epi64(0x01, 0x02, 0x03, 0x04,
                                               0xFF, 0xFF, 0xFF, 0xFF);

    /* Shuffle ip6 src and dst to beginning of register. */
    __m512i v_ip6_hdr_shuf = _mm512_permutexvar_epi64(v_shuf_src_dst,
                                                      ip6_header);

    /* Extract ip6 src and dst into smaller 256-bit wide register. */
    __m256i v_ip6_src_dst = _mm512_extracti64x4_epi64(v_ip6_hdr_shuf, 0);

    /* These two shuffle masks, v_swap16a and v_swap16b, are to shuffle the
     * src and dst fields and add padding after each 16-bit value for the
     * following carry over addition. */
    __m256i v_swap16a = _mm256_setr_epi16(0x0100, 0xFFFF, 0x0302, 0xFFFF,
                                          0x0504, 0xFFFF, 0x0706, 0xFFFF,
                                          0x0100, 0xFFFF, 0x0302, 0xFFFF,
                                          0x0504, 0xFFFF, 0x0706, 0xFFFF);
    __m256i v_swap16b = _mm256_setr_epi16(0x0908, 0xFFFF, 0x0B0A, 0xFFFF,
                                          0x0D0C, 0xFFFF, 0x0F0E, 0xFFFF,
                                          0x0908, 0xFFFF, 0x0B0A, 0xFFFF,
                                          0x0D0C, 0xFFFF, 0x0F0E, 0xFFFF);
    __m256i v_shuf_old1 = _mm256_shuffle_epi8(v_ip6_src_dst, v_swap16a);
    __m256i v_shuf_old2 = _mm256_shuffle_epi8(v_ip6_src_dst, v_swap16b);

    /* Add each part of the old and new headers together. */
    __m256i v_delta = _mm256_add_epi32(v_shuf_old1, v_shuf_old2);

    /* Perform horizontal add to go from 8x32-bits to 2x32-bits. */
    v_delta = _mm256_hadd_epi32(v_delta, v_zeros);
    v_delta = _mm256_hadd_epi32(v_delta, v_zeros);

    /* Shuffle 32-bit value from 3rd lane into first lane for final
     * horizontal add. */
    __m256i v_swap32a = _mm256_setr_epi32(0x0, 0x4, 0xF, 0xF,
                                          0xF, 0xF, 0xF, 0xF);

    v_delta = _mm256_permutexvar_epi32(v_swap32a, v_delta);

    v_delta = _mm256_hadd_epi32(v_delta, v_zeros);
    v_delta = _mm256_shuffle_epi8(v_delta, v_swap16a);
    v_delta = _mm256_hadd_epi32(v_delta, v_zeros);
    v_delta = _mm256_hadd_epi16(v_delta, v_zeros);

    /* Extract delta value. */
    return _mm256_extract_epi16(v_delta, 0);
}

static inline uint16_t ALWAYS_INLINE
__attribute__((__target__("avx512vbmi")))
avx512_ipv6_addr_csum_delta(__m512i v_packet, __m512i v_new_hdr,
                            bool rh_present)
{
    __m512i v_new_hdr_for_cksum = v_new_hdr;
    uint32_t csum_delta;
    uint16_t old_delta;
    uint16_t new_delta;

    if (rh_present) {
        v_new_hdr_for_cksum = _mm512_mask_blend_epi64(0x18, v_new_hdr,
                                                      v_packet);
    }

    old_delta = avx512_ipv6_sum_header(v_packet);
    new_delta = avx512_ipv6_sum_header(v_new_hdr_for_cksum);
    csum_delta = ((uint16_t) ~old_delta) + new_delta;

    return ~csum_finish(csum_delta);
}

/* This function performs the same operation on each packet in the batch as
 * the scalar odp_set_ipv6() function. */
static void
__attribute__((__target__("avx512vbmi")))
action_avx512_set_ipv6(struct dp_packet_batch *batch, const struct nlattr *a)
{
    const struct ovs_key_ipv6 *key, *mask;
    struct dp_packet *packet;

    a = nl_attr_get(a);
    key = nl_attr_get(a);
    mask = odp_get_key_mask(a, struct ovs_key_ipv6);

    /* Read the content of the key and mask in the respective registers. We
     * only load the size of the actual structure, which is only 40 bytes. */
    __m512i v_key = _mm512_maskz_loadu_epi64(0x1F, (void *) key);
    __m512i v_mask = _mm512_maskz_loadu_epi64(0x1F, (void *) mask);

    /* This shuffle mask v_shuffle, is to shuffle key and mask to match the
     * ip6_hdr structure layout. */
    static const uint8_t ip_shuffle_mask[64] = {
        0x20, 0x21, 0x22, 0x23, 0xFF, 0xFF, 0x24, 0x26,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0XFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0XFF, 0xFF
    };

    __m512i v_shuffle = _mm512_loadu_si512((void *) ip_shuffle_mask);

    /* This shuffle is required for key and mask to match the layout of the
     * ip6_hdr struct. */
    __m512i v_key_shuf = _mm512_permutexvar_epi8(v_shuffle, v_key);
    __m512i v_mask_shuf = _mm512_permutexvar_epi8(v_shuffle, v_mask);

    /* Set the v_zero register to all zero's. */
    const __m128i v_zeros = _mm_setzero_si128();

    /* Set the v_all_ones register to all one's. */
    const __m128i v_all_ones = _mm_cmpeq_epi16(v_zeros, v_zeros);

    /* Load ip6 src and dst masks respectively into 128-bit wide registers. */
    __m128i v_src = _mm_loadu_si128((void *) &mask->ipv6_src);
    __m128i v_dst = _mm_loadu_si128((void *) &mask->ipv6_dst);

    /* Perform a bitwise OR between src and dst registers. */
    __m128i v_or = _mm_or_si128(v_src, v_dst);

    /* Will return true if any bit has been set in v_or, else it will return
     * false. */
    bool do_checksum = !_mm_test_all_zeros(v_or, v_all_ones);

    DP_PACKET_BATCH_FOR_EACH (i, packet, batch) {
        struct ovs_16aligned_ip6_hdr *nh = dp_packet_l3(packet);

        /* Load the 40 bytes of the IPv6 header. */
        __m512i v_packet = _mm512_maskz_loadu_epi64(0x1F, (void *) nh);

        /* AND the v_pkt_mask to the packet data (v_packet). */
        __m512i v_pkt_masked = _mm512_andnot_si512(v_mask_shuf, v_packet);

        /* OR the new addresses (v_key_shuf) with the masked packet addresses
         * (v_pkt_masked). */
        __m512i v_new_hdr = _mm512_or_si512(v_key_shuf, v_pkt_masked);

        /* If ip6_src or ip6_dst has been modified, L4 checksum needs to be
         * updated. */
        uint8_t proto = 0;
        bool rh_present;
        bool do_csum = do_checksum;

        rh_present = packet_rh_present(packet, &proto, &do_csum);

        if (do_csum) {
            size_t l4_size = dp_packet_l4_size(packet);
            uint16_t delta_checksum;

            if (proto == IPPROTO_UDP && l4_size >= UDP_HEADER_LEN) {
                struct udp_header *uh = dp_packet_l4(packet);
                if (dp_packet_hwol_l4_is_udp(packet)) {
                    dp_packet_ol_reset_l4_csum_good(packet);
                } else if (uh->udp_csum) {
                    delta_checksum = avx512_ipv6_addr_csum_delta(v_packet,
                                                                 v_new_hdr,
                                                                 rh_present);
                    uint16_t old_udp_checksum = ~uh->udp_csum;
                    uint32_t udp_checksum = old_udp_checksum +
                                            delta_checksum;

                    udp_checksum = csum_finish(udp_checksum);

                    if (!udp_checksum) {
                        udp_checksum = htons(0xffff);
                    }

                    uh->udp_csum = udp_checksum;
                }

            } else if (proto == IPPROTO_TCP && l4_size >= TCP_HEADER_LEN) {
                if (dp_packet_hwol_l4_is_tcp(packet)) {
                    dp_packet_ol_reset_l4_csum_good(packet);
                } else {
                    delta_checksum = avx512_ipv6_addr_csum_delta(v_packet,
                                                                 v_new_hdr,
                                                                 rh_present);
                    struct tcp_header *th = dp_packet_l4(packet);
                    uint16_t old_tcp_checksum = ~th->tcp_csum;
                    uint32_t tcp_checksum = old_tcp_checksum + delta_checksum;

                    tcp_checksum = csum_finish(tcp_checksum);
                    th->tcp_csum = tcp_checksum;
                }
            } else if (proto == IPPROTO_ICMPV6 &&
                       l4_size >= sizeof(struct icmp6_header)) {
                delta_checksum = avx512_ipv6_addr_csum_delta(v_packet,
                                                             v_new_hdr,
                                                             rh_present);
                struct icmp6_header *icmp = dp_packet_l4(packet);
                uint16_t old_icmp6_checksum = ~icmp->icmp6_cksum;
                uint32_t icmp6_checksum = old_icmp6_checksum + delta_checksum;

                icmp6_checksum = csum_finish(icmp6_checksum);
                icmp->icmp6_cksum = icmp6_checksum;
            }

            pkt_metadata_init_conn(&packet->md);
        }
        /* Write back the modified IPv6 addresses. */
        _mm512_mask_storeu_epi64((void *) nh, 0x1F, v_new_hdr);

        /* Scalar method for setting IPv6 tclass field. */
        if (key->ipv6_tclass) {
            uint8_t old_tc = ntohl(get_16aligned_be32(&nh->ip6_flow)) >> 20;
            uint8_t key_tc = key->ipv6_tclass | (old_tc & ~mask->ipv6_tclass);

            packet_set_ipv6_tc(&nh->ip6_flow, key_tc);
        }
    }
}
#endif /* HAVE_AVX512VBMI */

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
    impl_set_masked_funcs[OVS_KEY_ATTR_IPV4] = action_avx512_ipv4_set_addrs;

#if HAVE_AVX512VBMI
    if (action_avx512vbmi_isa_probe()) {
        impl_set_masked_funcs[OVS_KEY_ATTR_IPV6] = action_avx512_set_ipv6;
    }
#endif

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
