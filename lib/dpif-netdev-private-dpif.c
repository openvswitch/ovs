/*
 * Copyright (c) 2021 Intel Corporation.
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

#include "dpif-netdev-private-dpif.h"
#include "dpif-netdev-private-thread.h"

#include <errno.h>
#include <string.h>

#include "cpu.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/vlog.h"
#include "util.h"

VLOG_DEFINE_THIS_MODULE(dpif_netdev_impl);
#define DPIF_NETDEV_IMPL_AVX512_CHECK (__x86_64__ && HAVE_AVX512F \
    && HAVE_LD_AVX512_GOOD && __SSE4_2__)

enum dpif_netdev_impl_info_idx {
    DPIF_NETDEV_IMPL_SCALAR,
    DPIF_NETDEV_IMPL_AVX512
};

#if DPIF_NETDEV_IMPL_AVX512_CHECK
static int32_t
dp_netdev_input_outer_avx512_probe(void)
{
    if (!cpu_has_isa(OVS_CPU_ISA_X86_AVX512F)
        || !cpu_has_isa(OVS_CPU_ISA_X86_BMI2)) {
        return -ENOTSUP;
    }

    return 0;
}
#endif

/* Actual list of implementations goes here. */
static struct dpif_netdev_impl_info_t dpif_impls[] = {
    /* The default scalar C code implementation. */
    [DPIF_NETDEV_IMPL_SCALAR] = { .input_func = dp_netdev_input,
      .probe = NULL,
      .name = "dpif_scalar", },

#if DPIF_NETDEV_IMPL_AVX512_CHECK
    /* Only available on x86_64 bit builds with SSE 4.2 used for OVS core. */
    [DPIF_NETDEV_IMPL_AVX512] = { .input_func = dp_netdev_input_outer_avx512,
      .probe = dp_netdev_input_outer_avx512_probe,
      .name = "dpif_avx512", },
#endif
};

static dp_netdev_input_func default_dpif_func;

dp_netdev_input_func
dp_netdev_impl_get_default(void)
{
    /* For the first call, this will be NULL. Compute the compile time default.
     */
    if (!default_dpif_func) {
        int dpif_idx = DPIF_NETDEV_IMPL_SCALAR;

/* Configure-time overriding to run test suite on all implementations. */
#if DPIF_NETDEV_IMPL_AVX512_CHECK
#ifdef DPIF_AVX512_DEFAULT
        dp_netdev_input_func_probe probe;

        /* Check if the compiled default is compatible. */
        probe = dpif_impls[DPIF_NETDEV_IMPL_AVX512].probe;
        if (!probe || !probe()) {
            dpif_idx = DPIF_NETDEV_IMPL_AVX512;
        }
#endif
#endif

        VLOG_INFO("Default DPIF implementation is %s.\n",
                  dpif_impls[dpif_idx].name);
        default_dpif_func = dpif_impls[dpif_idx].input_func;
    }

    return default_dpif_func;
}

void
dp_netdev_impl_get(struct ds *reply, struct dp_netdev_pmd_thread **pmd_list,
                   size_t n)
{
    /* Add all dpif functions to reply string. */
    ds_put_cstr(reply, "Available DPIF implementations:\n");

    for (uint32_t i = 0; i < ARRAY_SIZE(dpif_impls); i++) {
        ds_put_format(reply, "  %s (pmds: ", dpif_impls[i].name);

        for (size_t j = 0; j < n; j++) {
            struct dp_netdev_pmd_thread *pmd = pmd_list[j];
            if (pmd->core_id == NON_PMD_CORE_ID) {
                continue;
            }

            if (pmd->netdev_input_func == dpif_impls[i].input_func) {
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

/* This function checks all available DPIF implementations, and selects the
 * returns the function pointer to the one requested by "name".
 */
static int32_t
dp_netdev_impl_get_by_name(const char *name, dp_netdev_input_func *out_func)
{
    ovs_assert(name);
    ovs_assert(out_func);

    uint32_t i;

    for (i = 0; i < ARRAY_SIZE(dpif_impls); i++) {
        if (strcmp(dpif_impls[i].name, name) == 0) {
            /* Probe function is optional - so check it is set before exec. */
            if (dpif_impls[i].probe) {
                int probe_err = dpif_impls[i].probe();
                if (probe_err) {
                    *out_func = NULL;
                    return probe_err;
                }
            }
            *out_func = dpif_impls[i].input_func;
            return 0;
        }
    }

    return -EINVAL;
}

int32_t
dp_netdev_impl_set_default_by_name(const char *name)
{
    dp_netdev_input_func new_default;

    int32_t err = dp_netdev_impl_get_by_name(name, &new_default);

    if (!err) {
        default_dpif_func = new_default;
    }

    return err;

}
