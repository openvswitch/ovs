/*
 * Copyright (c) 2021 Intel.
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
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "cpu.h"
#include "dp-packet.h"
#include "dpif-netdev-private-dpcls.h"
#include "dpif-netdev-private-extract.h"
#include "dpif-netdev-private-thread.h"
#include "flow.h"
#include "openvswitch/vlog.h"
#include "ovs-thread.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_extract);

/* Variable to hold the default MFEX implementation. */
static ATOMIC(miniflow_extract_func) default_mfex_func;

#if MFEX_IMPL_AVX512_CHECK
static int32_t
avx512_isa_probe(bool needs_vbmi)
{
    static enum ovs_cpu_isa isa_required[] = {
        OVS_CPU_ISA_X86_AVX512F,
        OVS_CPU_ISA_X86_AVX512BW,
        OVS_CPU_ISA_X86_BMI2,
    };

    for (uint32_t i = 0; i < ARRAY_SIZE(isa_required); i++) {
        if (!cpu_has_isa(isa_required[i])) {
            return -ENOTSUP;
        }
    }

    if (needs_vbmi && !cpu_has_isa(OVS_CPU_ISA_X86_AVX512VBMI)) {
        return -ENOTSUP;
    }

    return 0;
}

/* Probe functions to check ISA requirements. */
static int32_t
mfex_avx512_probe(void)
{
    return avx512_isa_probe(false);
}

#if HAVE_AVX512VBMI
static int32_t
mfex_avx512_vbmi_probe(void)
{
    return avx512_isa_probe(true);
}
#endif
#endif

/* Implementations of available extract options and
 * the implementations are always in order of preference.
 */
static struct dpif_miniflow_extract_impl mfex_impls[] = {

    [MFEX_IMPL_AUTOVALIDATOR] = {
        .probe = NULL,
        .extract_func = dpif_miniflow_extract_autovalidator,
        .name = "autovalidator", },

    [MFEX_IMPL_SCALAR] = {
        .probe = NULL,
        .extract_func = NULL,
        .name = "scalar", },

    [MFEX_IMPL_STUDY] = {
        .probe = NULL,
        .extract_func = mfex_study_traffic,
        .name = "study", },

/* Compile in implementations only if the compiler ISA checks pass. */
#if MFEX_IMPL_AVX512_CHECK
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_IPv4_UDP] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_ip_udp,
        .name = "avx512_vbmi_ipv4_udp", },
#endif
    [MFEX_IMPL_IPv4_UDP] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_ip_udp,
        .name = "avx512_ipv4_udp", },
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_IPv4_TCP] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_ip_tcp,
        .name = "avx512_vbmi_ipv4_tcp", },
#endif
    [MFEX_IMPL_IPv4_TCP] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_ip_tcp,
        .name = "avx512_ipv4_tcp", },
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_DOT1Q_IPv4_UDP] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_dot1q_ip_udp,
        .name = "avx512_vbmi_dot1q_ipv4_udp", },
#endif
    [MFEX_IMPL_DOT1Q_IPv4_UDP] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_dot1q_ip_udp,
        .name = "avx512_dot1q_ipv4_udp", },
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_DOT1Q_IPv4_TCP] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_dot1q_ip_tcp,
        .name = "avx512_vbmi_dot1q_ipv4_tcp", },
#endif
    [MFEX_IMPL_DOT1Q_IPv4_TCP] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_dot1q_ip_tcp,
        .name = "avx512_dot1q_ipv4_tcp",
    },
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_IPv6_UDP] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_ipv6_udp,
        .name = "avx512_vbmi_ipv6_udp",
    },
#endif
    [MFEX_IMPL_IPv6_UDP] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_ipv6_udp,
        .name = "avx512_ipv6_udp",
    },
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_IPv6_TCP] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_ipv6_tcp,
        .name = "avx512_vbmi_ipv6_tcp",
    },
#endif
    [MFEX_IMPL_IPv6_TCP] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_ipv6_tcp,
        .name = "avx512_ipv6_tcp",
    },
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_DOT1Q_IPv6_TCP] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_dot1q_ipv6_tcp,
        .name = "avx512_vbmi_avx512_dot1q_ipv6_tcp",
    },
#endif
    [MFEX_IMPL_DOT1Q_IPv6_TCP] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_dot1q_ipv6_tcp,
        .name = "avx512_dot1q_ipv6_tcp",
    },
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_DOT1Q_IPv6_UDP] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_dot1q_ipv6_udp,
        .name = "avx512_vbmi_avx512_dot1q_ipv6_udp",
    },
#endif
    [MFEX_IMPL_DOT1Q_IPv6_UDP] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_dot1q_ipv6_udp,
        .name = "avx512_dot1q_ipv6_udp",
    },
#if HAVE_AVX512VBMI
    [MFEX_IMPL_VBMI_IPv4_NVGRE] = {
        .probe = mfex_avx512_vbmi_probe,
        .extract_func = mfex_avx512_vbmi_ip_nvgre,
        .name = "avx512_vbmi_ipv4_nvgre", },
#endif
    [MFEX_IMPL_IPv4_NVGRE] = {
        .probe = mfex_avx512_probe,
        .extract_func = mfex_avx512_ip_nvgre,
        .name = "avx512_ipv4_nvgre", },
#endif
};

BUILD_ASSERT_DECL(MFEX_IMPL_MAX == ARRAY_SIZE(mfex_impls));

void
dpif_miniflow_extract_init(void)
{
    atomic_uintptr_t *mfex_func = (void *)&default_mfex_func;
#ifdef MFEX_AUTOVALIDATOR_DEFAULT
    int mfex_idx = MFEX_IMPL_AUTOVALIDATOR;
#else
    int mfex_idx = MFEX_IMPL_SCALAR;
#endif

    /* Call probe on each impl, and cache the result. */
    for (int i = 0; i < MFEX_IMPL_MAX; i++) {
        bool avail = true;
        if (mfex_impls[i].probe) {
            /* Return zero is success, non-zero means error. */
            avail = (mfex_impls[i].probe() == 0);
        }
        VLOG_DBG("Miniflow Extract implementation '%s' %s available.",
                 mfex_impls[i].name, avail ? "is" : "is not");
        mfex_impls[i].available = avail;
    }

    /* For the first call, this will be choosen based on the
     * compile time flag.
     */
    VLOG_INFO("Default MFEX Extract implementation is %s.\n",
              mfex_impls[mfex_idx].name);
    atomic_store_relaxed(mfex_func, (uintptr_t) mfex_impls
                         [mfex_idx].extract_func);
}

miniflow_extract_func
dp_mfex_impl_get_default(void)
{
    miniflow_extract_func return_func;
    atomic_uintptr_t *mfex_func = (void *)&default_mfex_func;

    atomic_read_relaxed(mfex_func, (uintptr_t *) &return_func);

    return return_func;
}

int
dp_mfex_impl_set_default_by_name(const char *name)
{
    miniflow_extract_func new_default;
    atomic_uintptr_t *mfex_func = (void *)&default_mfex_func;

    int err = dp_mfex_impl_get_by_name(name, &new_default);

    if (!err) {
        atomic_store_relaxed(mfex_func, (uintptr_t) new_default);
    }

    return err;

}

void
dp_mfex_impl_get(struct ds *reply, struct dp_netdev_pmd_thread **pmd_list,
                 size_t pmd_list_size)
{
    /* Add all MFEX functions to reply string. */
    ds_put_cstr(reply, "Available MFEX implementations:\n");

    for (int i = 0; i < MFEX_IMPL_MAX; i++) {
        ds_put_format(reply, "  %s (available: %s pmds: ",
                      mfex_impls[i].name, mfex_impls[i].available ?
                      "True" : "False");

        for (size_t j = 0; j < pmd_list_size; j++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[j];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            if (pmd->miniflow_extract_opt == mfex_impls[i].extract_func) {
                ds_put_format(reply, "%u,", pmd->core_id);
            }
        }

        ds_chomp(reply, ',');

        if (ds_last(reply) == ' ') {
            ds_put_cstr(reply, "none");
        }

        ds_put_cstr(reply, ")\n");
    }

}

/* This function checks all available MFEX implementations, and selects and
 * returns the function pointer to the one requested by "name". If nothing
 * is found it returns error.
 */
int
dp_mfex_impl_get_by_name(const char *name, miniflow_extract_func *out_func)
{
    if (!name || !out_func) {
        return -EINVAL;
    }

    for (int i = 0; i < MFEX_IMPL_MAX; i++) {
        if (strcmp(mfex_impls[i].name, name) == 0) {
            /* Check available is set before exec. */
            if (!mfex_impls[i].available) {
                *out_func = NULL;
                return -ENODEV;
            }

            *out_func = mfex_impls[i].extract_func;
            return 0;
        }
    }

    return -ENOENT;
}

struct dpif_miniflow_extract_impl *
dpif_mfex_impl_info_get(void) {

    return mfex_impls;

}

uint32_t
dpif_miniflow_extract_autovalidator(struct dp_packet_batch *packets,
                                    struct netdev_flow_key *keys,
                                    uint32_t keys_size, odp_port_t in_port,
                                    struct dp_netdev_pmd_thread *pmd_handle)
{
    const size_t cnt = dp_packet_batch_size(packets);
    uint16_t good_l2_5_ofs[NETDEV_MAX_BURST];
    uint16_t good_l3_ofs[NETDEV_MAX_BURST];
    uint16_t good_l4_ofs[NETDEV_MAX_BURST];
    uint16_t good_l2_pad_size[NETDEV_MAX_BURST];
    struct dp_packet *packet;
    struct dp_netdev_pmd_thread *pmd = pmd_handle;
    struct netdev_flow_key test_keys[NETDEV_MAX_BURST];

    if (keys_size < cnt) {
        atomic_store_relaxed(&pmd->miniflow_extract_opt, NULL);
        VLOG_ERR("Invalid key size supplied, Key_size: %d less than"
                 "batch_size:  %" PRIuSIZE"\n", keys_size, cnt);
        VLOG_ERR("Autovalidatior is disabled.\n");
        return 0;
    }

    /* Run scalar miniflow_extract to get default result. */
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets) {
        pkt_metadata_init(&packet->md, in_port);
        miniflow_extract(packet, &keys[i].mf);

        /* Store known good metadata to compare with optimized metadata. */
        good_l2_5_ofs[i] = packet->l2_5_ofs;
        good_l3_ofs[i] = packet->l3_ofs;
        good_l4_ofs[i] = packet->l4_ofs;
        good_l2_pad_size[i] = packet->l2_pad_size;
    }

    uint32_t batch_failed = 0;
    /* Iterate through each version of miniflow implementations. */
    for (int j = MFEX_IMPL_START_IDX; j < MFEX_IMPL_MAX; j++) {
        if (!mfex_impls[j].available) {
            continue;
        }
        /* Reset keys and offsets before each implementation. */
        memset(test_keys, 0, keys_size * sizeof(struct netdev_flow_key));
        DP_PACKET_BATCH_FOR_EACH (i, packet, packets) {
            dp_packet_reset_offsets(packet);
        }
        /* Call optimized miniflow for each batch of packet. */
        uint32_t hit_mask = mfex_impls[j].extract_func(packets, test_keys,
                                                       keys_size, in_port,
                                                       pmd_handle);

        /* Do a miniflow compare for bits, blocks and offsets for all the
         * classified packets in the hitmask marked by set bits. */
        while (hit_mask) {
            /* Index for the set bit. */
            uint32_t i = raw_ctz(hit_mask);
            /* Set the index in hitmask to Zero. */
            hit_mask &= (hit_mask - 1);

            uint32_t failed = 0;

            struct ds log_msg = DS_EMPTY_INITIALIZER;
            ds_put_format(&log_msg, "MFEX autovalidator pkt %d\n", i);

            /* Check miniflow bits are equal. */
            if ((keys[i].mf.map.bits[0] != test_keys[i].mf.map.bits[0]) ||
                (keys[i].mf.map.bits[1] != test_keys[i].mf.map.bits[1])) {
                ds_put_format(&log_msg, "Autovalidation map failed\n"
                              "Good: 0x%llx 0x%llx    Test: 0x%llx 0x%llx\n",
                              keys[i].mf.map.bits[0],
                              keys[i].mf.map.bits[1],
                              test_keys[i].mf.map.bits[0],
                              test_keys[i].mf.map.bits[1]);
                failed = 1;
            }

            if (!miniflow_equal(&keys[i].mf, &test_keys[i].mf)) {
                uint32_t block_cnt = miniflow_n_values(&keys[i].mf);
                uint32_t test_block_cnt = miniflow_n_values(&test_keys[i].mf);

                ds_put_format(&log_msg, "Autovalidation blocks failed\n"
                              "Good hex:\n");
                ds_put_hex_dump(&log_msg, &keys[i].buf, block_cnt * 8, 0,
                                false);
                ds_put_format(&log_msg, "Test hex:\n");
                ds_put_hex_dump(&log_msg, &test_keys[i].buf,
                                test_block_cnt * 8, 0, false);
                failed = 1;
            }

            packet = packets->packets[i];
            if ((packet->l2_pad_size != good_l2_pad_size[i]) ||
                    (packet->l2_5_ofs != good_l2_5_ofs[i]) ||
                    (packet->l3_ofs != good_l3_ofs[i]) ||
                    (packet->l4_ofs != good_l4_ofs[i])) {
                ds_put_format(&log_msg,
                              "Autovalidation packet offsets failed\n");
                ds_put_format(&log_msg, "Good offsets: "
                              "l2_pad_size: %"PRIu16", l2_5_ofs: %"PRIu16", "
                              "l3_ofs: %"PRIu16", l4_ofs: %"PRIu16"\n",
                              good_l2_pad_size[i], good_l2_5_ofs[i],
                              good_l3_ofs[i], good_l4_ofs[i]);
                ds_put_format(&log_msg, "Test offsets: "
                              "l2_pad_size: %"PRIu16", l2_5_ofs: %"PRIu16", "
                              "l3_ofs: %"PRIu16", l4_ofs: %"PRIu16"\n",
                              packet->l2_pad_size, packet->l2_5_ofs,
                              packet->l3_ofs, packet->l4_ofs);
                failed = 1;
            }

            if (failed) {
                VLOG_ERR("Autovalidation for %s failed in pkt %d,"
                         " disabling.", mfex_impls[j].name, i);
                VLOG_ERR("Autovalidation failure details:\n%s",
                         ds_cstr(&log_msg));
                batch_failed = 1;
            }
            ds_destroy(&log_msg);
        }
    }

    /* Having dumped the debug info for the batch, disable autovalidator. */
    if (batch_failed) {
        atomic_store_relaxed(&pmd->miniflow_extract_opt, NULL);
    }

    /* Preserve packet correctness by storing back the good offsets in
     * packets back. */
    DP_PACKET_BATCH_FOR_EACH (i, packet, packets) {
        packet->l2_5_ofs = good_l2_5_ofs[i];
        packet->l3_ofs = good_l3_ofs[i];
        packet->l4_ofs = good_l4_ofs[i];
        packet->l2_pad_size = good_l2_pad_size[i];
    }

    /* Returning zero implies no packets were hit by autovalidation. This
     * simplifies unit-tests as changing --enable-mfex-default-autovalidator
     * would pass/fail. By always returning zero, autovalidator is a little
     * slower, but we gain consistency in testing. The auto-validator is only
     * meant to test different implementaions against a batch of packets
     * without incrementing hit counters.
     */
    return 0;
}
