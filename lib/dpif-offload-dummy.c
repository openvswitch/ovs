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

#include "dpif.h"
#include "dpif-offload.h"
#include "dpif-offload-provider.h"
#include "util.h"

static int
dpif_offload_dummy_open(const struct dpif_offload_class *offload_class,
                        struct dpif *dpif, struct dpif_offload **dpif_offload)
{
    struct dpif_offload *offload = xmalloc(sizeof *offload);

    dpif_offload_init(offload, offload_class, dpif);
    *dpif_offload = offload;
    return 0;
}

static void
dpif_offload_dummy_close(struct dpif_offload *dpif_offload)
{
    free(dpif_offload);
}

#define DEFINE_DPIF_DUMMY_CLASS(NAME, TYPE_STR)                        \
    struct dpif_offload_class NAME = {                                 \
        .type = TYPE_STR,                                              \
        .supported_dpif_types = (const char *const[]) {"dummy", NULL}, \
        .open = dpif_offload_dummy_open,                               \
        .close = dpif_offload_dummy_close,                             \
    }

DEFINE_DPIF_DUMMY_CLASS(dpif_offload_dummy_class, "dummy");
DEFINE_DPIF_DUMMY_CLASS(dpif_offload_dummy_x_class, "dummy_x");
