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

#include <config.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "cpu.h"
#include "dpdk.h"
#include "dp-packet.h"
#include "odp-execute.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "odp-util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(odp_execute_impl);
static int active_action_impl_index;

#if ACTION_IMPL_AVX512_CHECK
/* Probe functions to check ISA requirements. */
bool
action_avx512_isa_probe(void)
{
    static enum ovs_cpu_isa isa_required[] = {
        OVS_CPU_ISA_X86_AVX512F,
        OVS_CPU_ISA_X86_AVX512BW,
        OVS_CPU_ISA_X86_BMI2,
        OVS_CPU_ISA_X86_AVX512VL,
    };
    for (int i = 0; i < ARRAY_SIZE(isa_required); i++) {
        if (!cpu_has_isa(isa_required[i])) {
            return false;
        }
    }
    return true;
}

#else

bool
action_avx512_isa_probe(void)
{
   return false;
}

#endif

#if ACTION_IMPL_AVX512_CHECK && HAVE_AVX512VBMI
bool
action_avx512vbmi_isa_probe(void)
{
    return cpu_has_isa(OVS_CPU_ISA_X86_AVX512VBMI);
}
#else
bool
action_avx512vbmi_isa_probe(void)
{
    return false;
}
#endif

static struct odp_execute_action_impl action_impls[] = {
    [ACTION_IMPL_AUTOVALIDATOR] = {
        .available = false,
        .name = "autovalidator",
        .init_func = action_autoval_init,
    },

    [ACTION_IMPL_SCALAR] = {
        .available = false,
        .name = "scalar",
        .init_func = odp_action_scalar_init,
    },

#if ACTION_IMPL_AVX512_CHECK
    [ACTION_IMPL_AVX512] = {
        .available = false,
        .name = "avx512",
        .init_func = action_avx512_init,
    },
#endif
};

static void
action_impl_copy_funcs(struct odp_execute_action_impl *dest,
                       const struct odp_execute_action_impl *src)
{
    for (int i = 0; i < __OVS_ACTION_ATTR_MAX; i++) {
        atomic_store_relaxed(&dest->funcs[i], src->funcs[i]);
    }
}

struct odp_execute_action_impl *
odp_execute_action_set(const char *name)
{
    for (int i = 0; i < ACTION_IMPL_MAX; i++) {
        /* String compare, and set ptrs atomically. */
        if (!strcmp(action_impls[i].name, name)) {
            if (i != active_action_impl_index) {
                active_action_impl_index = i;
                VLOG_INFO("Action implementation set to %s", name);
            }
            return &action_impls[i];
        }
    }
    return NULL;
}

void
odp_execute_action_get_info(struct ds *string)
{
    ds_put_cstr(string, "Available Actions implementations:\n");
    for (int i = 0; i < ACTION_IMPL_MAX; i++) {
        ds_put_format(string, "  %s (available: %s, active: %s)\n",
                      action_impls[i].name,
                      action_impls[i].available ? "Yes" : "No",
                      i == active_action_impl_index ? "Yes" : "No");
    }
}

void
odp_execute_action_init(void)
{
    /* Each impl's function array is initialized to reflect the scalar
     * implementation. This simplifies adding optimized implementations,
     * as the autovalidator can always compare all actions.
     *
     * Below will check if impl is available and copies the scalar functions
     * to all other implementations. */
    for (int i = 0; i < ACTION_IMPL_MAX; i++) {
        bool avail = true;

        if (i != ACTION_IMPL_SCALAR) {
            action_impl_copy_funcs(&action_impls[i],
                                   &action_impls[ACTION_IMPL_SCALAR]);
        }

        if (action_impls[i].init_func) {
            /* Return zero is success, non-zero means error. */
            avail = (action_impls[i].init_func(&action_impls[i]) == 0);
        }

        action_impls[i].available = avail;

        VLOG_DBG("Actions implementation '%s' %s available.",
                 action_impls[i].name, avail ? "is" : "is not");

        /* The following is a run-time check to make sure a scalar
         * implementation exists for the given ISA implementation. This is to
         * make sure the autovalidator works as expected. */
        if (avail && i != ACTION_IMPL_SCALAR) {
            for (int j = 0; j < __OVS_ACTION_ATTR_MAX; j++) {
                /* No ovs_assert(), as it can be compiled out. */
                if (action_impls[ACTION_IMPL_SCALAR].funcs[j] == NULL
                    && action_impls[i].funcs[j] != NULL) {
                    ovs_assert_failure(OVS_SOURCE_LOCATOR, __func__,
                                       "Missing scalar action function!");
                }
            }
        }
    }
}

/* Init sequence required to be scalar first to pick up the default scalar
 * implementations, allowing over-riding of the optimized functions later. */
BUILD_ASSERT_DECL(ACTION_IMPL_SCALAR == 0);
BUILD_ASSERT_DECL(ACTION_IMPL_AUTOVALIDATOR == 1);

/* Loop over packets, and validate each one for the given action. */
static void
action_autoval_generic(struct dp_packet_batch *batch, const struct nlattr *a)
{
    struct odp_execute_action_impl *scalar = &action_impls[ACTION_IMPL_SCALAR];
    enum ovs_action_attr attr_type = nl_attr_type(a);
    struct dp_packet_batch original_batch;
    bool failed = false;

    dp_packet_batch_clone(&original_batch, batch);

    scalar->funcs[attr_type](batch, a);

    for (int impl = ACTION_IMPL_BEGIN; impl < ACTION_IMPL_MAX; impl++) {
        /* Clone original batch and execute implementation under test. */
        struct dp_packet_batch test_batch;

        dp_packet_batch_clone(&test_batch, &original_batch);
        action_impls[impl].funcs[attr_type](&test_batch, a);

        /* Loop over implementations, checking each one. */
        for (int pidx = 0; pidx < original_batch.count; pidx++) {
            struct dp_packet *good_pkt = batch->packets[pidx];
            struct dp_packet *test_pkt = test_batch.packets[pidx];

            struct ds log_msg = DS_EMPTY_INITIALIZER;

            /* Compare packet length and payload contents. */
            bool eq = dp_packet_equal(good_pkt, test_pkt);

            if (!eq) {
                ds_put_format(&log_msg, "Packet: %d\nAction : ", pidx);
                format_odp_actions(&log_msg, a, a->nla_len, NULL);
                ds_put_format(&log_msg, "\nGood hex:\n");
                ds_put_hex_dump(&log_msg, dp_packet_data(good_pkt),
                                dp_packet_size(good_pkt), 0, false);
                ds_put_format(&log_msg, "Test hex:\n");
                ds_put_hex_dump(&log_msg, dp_packet_data(test_pkt),
                                dp_packet_size(test_pkt), 0, false);

                failed = true;
            }

            /* Compare offsets and RSS */
            if (!dp_packet_compare_offsets(good_pkt, test_pkt, &log_msg)) {
                failed = true;
            }

            if (dp_packet_rss_valid(good_pkt)) {
                uint32_t good_hash = dp_packet_get_rss_hash(good_pkt);
                uint32_t test_hash = dp_packet_get_rss_hash(test_pkt);

                if (good_hash != test_hash) {
                    ds_put_format(&log_msg,
                                  "Autovalidation rss hash failed\n");
                    ds_put_format(&log_msg, "Good RSS hash : %u\n", good_hash);
                    ds_put_format(&log_msg, "Test RSS hash : %u\n", test_hash);

                    failed = true;
                }
            }

            /* Compare packet metadata. */
            if (memcmp(&good_pkt->md, &test_pkt->md, sizeof good_pkt->md)) {
                ds_put_format(&log_msg, "Autovalidation metadata failed\n");
                ds_put_format(&log_msg, "Good packet metadata:\n");
                ds_put_sparse_hex_dump(&log_msg, &good_pkt->md,
                                       sizeof good_pkt->md, 0, false);
                ds_put_format(&log_msg, "Test packet metadata:\n");
                ds_put_sparse_hex_dump(&log_msg, &test_pkt->md,
                                       sizeof test_pkt->md, 0, false);
                failed = true;
            }

            if (failed) {
                VLOG_ERR("Autovalidation of %s failed. Details:\n%s",
                         action_impls[impl].name, ds_cstr(&log_msg));
                ds_destroy(&log_msg);
                failed = false;
            }
        }
        dp_packet_delete_batch(&test_batch, true);
    }
    dp_packet_delete_batch(&original_batch, true);
}

void
odp_execute_scalar_action(struct dp_packet_batch *batch,
                          const struct nlattr *action)
{
    enum ovs_action_attr type = nl_attr_type(action);

    if (type <= OVS_ACTION_ATTR_MAX &&
        action_impls[ACTION_IMPL_SCALAR].funcs[type]) {

        action_impls[ACTION_IMPL_SCALAR].funcs[type](batch, action);
    }
}

int
action_autoval_init(struct odp_execute_action_impl *self)
{
    /* Set function pointers for actions that can be applied directly, these
     * are identified by OVS_ACTION_ATTR_*. */
    for (int i = 0; i < __OVS_ACTION_ATTR_MAX; i++) {
        if (action_impls[ACTION_IMPL_SCALAR].funcs[i]) {
            self->funcs[i] = action_autoval_generic;
        }
    }
    return 0;
}
