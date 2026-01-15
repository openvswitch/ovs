/*
 * Copyright (c) 2025 Red Hat, Inc.
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

#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "tc.h"
#include "util.h"

/* dpif offload interface for the tc implementation. */
struct dpif_offload_tc {
    struct dpif_offload offload;

    /* Configuration specific variables. */
    struct ovsthread_once once_enable; /* Track first-time enablement. */
};

static struct dpif_offload_tc *
dpif_offload_tc_cast(const struct dpif_offload *offload)
{
    dpif_offload_assert_class(offload, &dpif_offload_tc_class);
    return CONTAINER_OF(offload, struct dpif_offload_tc, offload);
}

static int
dpif_offload_tc_open(const struct dpif_offload_class *offload_class,
                     struct dpif *dpif, struct dpif_offload **dpif_offload)
{
    struct dpif_offload_tc *offload_tc;

    offload_tc = xmalloc(sizeof *offload_tc);

    dpif_offload_init(&offload_tc->offload, offload_class, dpif);
    offload_tc->once_enable =
        (struct ovsthread_once) OVSTHREAD_ONCE_INITIALIZER;

    *dpif_offload = &offload_tc->offload;
    return 0;
}

static void
dpif_offload_tc_close(struct dpif_offload *dpif_offload)
{
    struct dpif_offload_tc *offload_tc = dpif_offload_tc_cast(dpif_offload);

    ovsthread_once_destroy(&offload_tc->once_enable);
    free(offload_tc);
}

static void
dpif_offload_tc_set_config(struct dpif_offload *offload,
                           const struct smap *other_cfg)
{
    struct dpif_offload_tc *offload_tc = dpif_offload_tc_cast(offload);

    if (smap_get_bool(other_cfg, "hw-offload", false)) {
        if (ovsthread_once_start(&offload_tc->once_enable)) {

            tc_set_policy(smap_get_def(other_cfg, "tc-policy",
                                       TC_POLICY_DEFAULT));

            ovsthread_once_done(&offload_tc->once_enable);
        }
    }
}

struct dpif_offload_class dpif_offload_tc_class = {
    .type = "tc",
    .supported_dpif_types = (const char *const[]) {"system", NULL},
    .open = dpif_offload_tc_open,
    .close = dpif_offload_tc_close,
    .set_config = dpif_offload_tc_set_config,
};
