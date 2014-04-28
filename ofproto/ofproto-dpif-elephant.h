/*
 * Copyright (c) 2014 Nicira, Inc.
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

#ifndef OFPROTO_ELEPHANT_H
#define OFPROTO_ELEPHANT_H 1

#include <stdint.h>
#include "ovs-atomic.h"

/* xxx Do we want to define this here or in the C file? */
struct dpif_elephant {
    uint32_t mech;
    uint32_t arg1;
    uint32_t arg2;
    int dscp;

    struct ovs_refcount ref_cnt;
};

struct dpif_elephant *dpif_elephant_create(void);
struct dpif_elephant *dpif_elephant_ref(const struct dpif_elephant *);
void dpif_elephant_unref(struct dpif_elephant *);

void dpif_elephant_set_options(struct dpif_elephant *, uint64_t mech,
                               uint64_t arg1, uint64_t arg2, int dscp);

#endif /* elephant.h */
