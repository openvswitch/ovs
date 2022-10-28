/*
 * Copyright (c) 2022 Red Hat, Inc.
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

#include "lib/util.h"
#include "lib/uuidset.h"

#include "ovstest.h"

static void
test_uuidset_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    struct uuidset set = UUIDSET_INITIALIZER(&set);
    struct uuid uuids[2];

    for (size_t i = 0; i < ARRAY_SIZE(uuids); i++) {
        uuid_generate(&uuids[i]);
    }

    ovs_assert(uuidset_is_empty(&set));

    for (size_t i = 0; i < ARRAY_SIZE(uuids); i++) {
        struct uuid *u = &uuids[i];

        if (i == 0) {
            ovs_assert(uuidset_is_empty(&set));
        } else {
            ovs_assert(!uuidset_is_empty(&set));
        }
        ovs_assert(uuidset_count(&set) == i);
        ovs_assert(!uuidset_contains(&set, u));
        ovs_assert(!uuidset_find_and_delete(&set, u));

        /* Insert twice to check set property. */
        uuidset_insert(&set, u);
        uuidset_insert(&set, u);
        ovs_assert(uuidset_count(&set) == i + 1);

        struct uuidset_node *n = uuidset_find(&set, u);
        ovs_assert(n);
        uuidset_delete(&set, n);
        ovs_assert(uuidset_count(&set) == i);
        ovs_assert(!uuidset_contains(&set, u));

        uuidset_insert(&set, u);
        ovs_assert(uuidset_count(&set) == i + 1);
        ovs_assert(uuidset_contains(&set, u));
        ovs_assert(uuidset_find_and_delete(&set, u));
        ovs_assert(uuidset_count(&set) == i);
        ovs_assert(!uuidset_contains(&set, u));

        uuidset_insert(&set, u);
    }

    uuidset_destroy(&set);
}

OVSTEST_REGISTER("test-uuidset", test_uuidset_main);
