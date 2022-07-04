/*
 * Copyright (c) 2020 Intel Corporation.
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
#include "dpif-netdev-lookup.h"

#include "cpu.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_lookup);
#define DPCLS_IMPL_AVX512_CHECK (__x86_64__ && HAVE_AVX512F \
    && HAVE_LD_AVX512_GOOD && HAVE_AVX512BW && __SSE4_2__)

#if DPCLS_IMPL_AVX512_CHECK
static dpcls_subtable_lookup_func
dpcls_subtable_avx512_gather_probe(uint32_t u0_bits, uint32_t u1_bits)
{
    if (!cpu_has_isa(OVS_CPU_ISA_X86_AVX512F)
        || !cpu_has_isa(OVS_CPU_ISA_X86_BMI2)) {
        return NULL;
    }

    return dpcls_subtable_avx512_gather_probe__(u0_bits, u1_bits,
        cpu_has_isa(OVS_CPU_ISA_X86_VPOPCNTDQ));
}
#endif

/* Actual list of implementations goes here */
static struct dpcls_subtable_lookup_info_t subtable_lookups[] = {
    /* The autovalidator implementation will not be used by default, it must
     * be enabled at compile time to be the default lookup implementation. The
     * user may enable it at runtime using the normal "prio-set" command if
     * desired. The compile time default switch is here to enable all unit
     * tests to transparently run with the autovalidator.
     */
#ifdef DPCLS_AUTOVALIDATOR_DEFAULT
    { .prio = 255,
#else
    { .prio = 0,
#endif
      .probe = dpcls_subtable_autovalidator_probe,
      .name = "autovalidator",
      .usage_cnt = ATOMIC_COUNT_INIT(0), },

    /* The default scalar C code implementation. */
    { .prio = 1,
      .probe = dpcls_subtable_generic_probe,
      .name = "generic",
      .usage_cnt = ATOMIC_COUNT_INIT(0), },

#if DPCLS_IMPL_AVX512_CHECK
    /* Only available on x86_64 bit builds with SSE 4.2 used for OVS core. */
    { .prio = 0,
      .probe = dpcls_subtable_avx512_gather_probe,
      .name = "avx512_gather",
      .usage_cnt = ATOMIC_COUNT_INIT(0), },
#else
    /* Disabling AVX512 at compile time, as compile time requirements not met.
     * This could be due to a number of reasons:
     *  1) core OVS is not compiled with SSE4.2 instruction set.
     *     The SSE42 instructions are required to use CRC32 ISA for high-
     *     performance hashing. Consider ./configure of OVS with -msse42 (or
     *     newer) to enable CRC32 hashing and higher performance.
     *  2) The assembler in binutils versions 2.30 and 2.31 has bugs in AVX512
     *     assembly. Compile time probes check for this assembler issue, and
     *     disable the HAVE_LD_AVX512_GOOD check if an issue is detected.
     *     Please upgrade binutils, or backport this binutils fix commit:
     *     2069ccaf8dc28ea699bd901fdd35d90613e4402a
     */
#endif
};

int
dpcls_subtable_lookup_info_get(struct dpcls_subtable_lookup_info_t **out_ptr)
{
    if (out_ptr == NULL) {
        return -1;
    }

    *out_ptr = subtable_lookups;
    return ARRAY_SIZE(subtable_lookups);
}

/* sets the priority of the lookup function with "name". */
int
dpcls_subtable_set_prio(const char *name, uint8_t priority)
{
    for (int i = 0; i < ARRAY_SIZE(subtable_lookups); i++) {
        if (strcmp(name, subtable_lookups[i].name) == 0) {
                subtable_lookups[i].prio = priority;
                VLOG_INFO("Subtable function '%s' set priority to %d\n",
                         name, priority);
                return 0;
        }
    }
    VLOG_WARN("Subtable function '%s' not found, failed to set priority\n",
              name);
    return -EINVAL;
}

dpcls_subtable_lookup_func
dpcls_subtable_get_best_impl(uint32_t u0_bit_count, uint32_t u1_bit_count,
                             struct dpcls_subtable_lookup_info_t **info)
{
    struct dpcls_subtable_lookup_info_t *best_info = NULL;
    dpcls_subtable_lookup_func best_func = NULL;
    int prio = -1;

    /* Iter over each subtable impl, and get highest priority one. */
    for (int i = 0; i < ARRAY_SIZE(subtable_lookups); i++) {
        struct dpcls_subtable_lookup_info_t *impl_info = &subtable_lookups[i];
        dpcls_subtable_lookup_func probed_func;

        if (impl_info->prio <= prio) {
            continue;
        }

        probed_func = subtable_lookups[i].probe(u0_bit_count,
                                                u1_bit_count);
        if (!probed_func) {
            continue;
        }

        best_func = probed_func;
        best_info = impl_info;
        prio = impl_info->prio;
    }

    /* Programming error - we must always return a valid func ptr. */
    ovs_assert(best_func != NULL && best_info != NULL);

    VLOG_DBG("Subtable lookup function '%s' with units (%d,%d), priority %d\n",
             best_info->name, u0_bit_count, u1_bit_count, prio);

    if (info) {
        *info = best_info;
    }
    return best_func;
}

void
dpcls_info_inc_usage(struct dpcls_subtable_lookup_info_t *info)
{
    if (info) {
        atomic_count_inc(&info->usage_cnt);
    }
}

void
dpcls_info_dec_usage(struct dpcls_subtable_lookup_info_t *info)
{
    if (info) {
        atomic_count_dec(&info->usage_cnt);
    }
}

void
dpcls_impl_print_stats(struct ds *reply)
{
    struct dpcls_subtable_lookup_info_t *lookup_funcs = NULL;
    int count = dpcls_subtable_lookup_info_get(&lookup_funcs);

    /* Add all DPCLS functions to reply string. */
    ds_put_cstr(reply, "Available dpcls implementations:\n");

    for (int i = 0; i < count; i++) {
        ds_put_format(reply, "  %s (Use count: %d, Priority: %d",
                      lookup_funcs[i].name,
                      atomic_count_get(&lookup_funcs[i].usage_cnt),
                      lookup_funcs[i].prio);

        if (ds_last(reply) == ' ') {
            ds_put_cstr(reply, "none");
        }

        ds_put_cstr(reply, ")\n");
    }

}
