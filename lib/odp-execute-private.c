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

#include "dpdk.h"
#include "dp-packet.h"
#include "odp-execute-private.h"
#include "odp-netlink.h"
#include "odp-util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(odp_execute_impl);
static int active_action_impl_index;

static struct odp_execute_action_impl action_impls[] = {
    [ACTION_IMPL_SCALAR] = {
        .available = false,
        .name = "scalar",
        .init_func = odp_action_scalar_init,
    },
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
            active_action_impl_index = i;

            VLOG_INFO("Action implementation set to %s", name);
            return &action_impls[i];
        }
    }
    return NULL;
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

        VLOG_INFO("Action implementation %s (available: %s)",
                  action_impls[i].name, avail ? "Yes" : "No");

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
