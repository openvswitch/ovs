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

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_lookup);

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
      .name = "autovalidator", },

    /* The default scalar C code implementation. */
    { .prio = 1,
      .probe = dpcls_subtable_generic_probe,
      .name = "generic", },

#if (__x86_64__ && HAVE_AVX512F && HAVE_LD_AVX512_GOOD && __SSE4_2__)
    /* Only available on x86_64 bit builds with SSE 4.2 used for OVS core. */
    { .prio = 0,
      .probe = dpcls_subtable_avx512_gather_probe,
      .name = "avx512_gather", },
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

int32_t
dpcls_subtable_lookup_info_get(struct dpcls_subtable_lookup_info_t **out_ptr)
{
    if (out_ptr == NULL) {
        return -1;
    }

    *out_ptr = subtable_lookups;
    return ARRAY_SIZE(subtable_lookups);
}

/* sets the priority of the lookup function with "name". */
int32_t
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
dpcls_subtable_get_best_impl(uint32_t u0_bit_count, uint32_t u1_bit_count)
{
    /* Iter over each subtable impl, and get highest priority one. */
    int32_t prio = -1;
    const char *name = NULL;
    dpcls_subtable_lookup_func best_func = NULL;

    for (int i = 0; i < ARRAY_SIZE(subtable_lookups); i++) {
        int32_t probed_prio = subtable_lookups[i].prio;
        if (probed_prio > prio) {
            dpcls_subtable_lookup_func probed_func;
            probed_func = subtable_lookups[i].probe(u0_bit_count,
                                    u1_bit_count);
            if (probed_func) {
                best_func = probed_func;
                prio = probed_prio;
                name = subtable_lookups[i].name;
            }
        }
    }

    VLOG_DBG("Subtable lookup function '%s' with units (%d,%d), priority %d\n",
             name, u0_bit_count, u1_bit_count, prio);

    /* Programming error - we must always return a valid func ptr. */
    ovs_assert(best_func != NULL);

    return best_func;
}
