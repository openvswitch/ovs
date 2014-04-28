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

#include <config.h>
#include "ofproto-dpif-elephant.h"
#include "ofproto.h"

struct dpif_elephant *
dpif_elephant_create(void)
{
    struct dpif_elephant *de;
    de = xzalloc(sizeof *de);
    ovs_refcount_init(&de->ref_cnt);
    return de;
}

struct dpif_elephant *
dpif_elephant_ref(const struct dpif_elephant *de_)
{
    struct dpif_elephant *de = CONST_CAST(struct dpif_elephant *, de_);
    if (de) {
        ovs_refcount_ref(&de->ref_cnt);
    }
    return de;
}

void
dpif_elephant_unref(struct dpif_elephant *de)
{
    if (de && ovs_refcount_unref(&de->ref_cnt) == 1) {
        /* xxx Do we need to blow away the kernel flows? */
        free(de);
    }
}

void
dpif_elephant_set_options(struct dpif_elephant *elephant, uint64_t mech,
                          uint64_t arg1, uint64_t arg2, int dscp)
{
    /* xxx Do we need to blow away the kernel flows? */
    elephant->mech = mech;
    elephant->arg1 = arg1;
    elephant->arg2 = arg2;
    elephant->dscp = dscp;
}
