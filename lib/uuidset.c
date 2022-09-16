/*
 * Copyright (c) 2020, 2022 VMware, Inc.
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

#include "lib/uuidset.h"
#include "lib/util.h"

void
uuidset_init(struct uuidset *set)
{
    hmap_init(&set->uuids);
}

void
uuidset_destroy(struct uuidset *set)
{
    if (set) {
        uuidset_clear(set);
        hmap_destroy(&set->uuids);
    }
}

void uuidset_clear(struct uuidset *set)
{
    struct uuidset_node *node;

    HMAP_FOR_EACH_SAFE (node, hmap_node, &set->uuids) {
        uuidset_delete(set, node);
    }
}

struct uuidset_node *
uuidset_find(const struct uuidset *set, const struct uuid *uuid)
{
    struct uuidset_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, hmap_node, uuid_hash(uuid), &set->uuids) {
        if (uuid_equals(uuid, &node->uuid)) {
            return node;
        }
    }

    return NULL;
}

bool
uuidset_find_and_delete(struct uuidset *set, const struct uuid *uuid)
{
    struct uuidset_node *node = uuidset_find(set, uuid);
    if (node) {
        uuidset_delete(set, node);
    }
    return !!node;
}

void
uuidset_insert(struct uuidset *set, const struct uuid *uuid)
{
    if (!uuidset_find(set, uuid)) {
        struct uuidset_node *node = xmalloc(sizeof *node);
        node->uuid = *uuid;
        hmap_insert(&set->uuids, &node->hmap_node, uuid_hash(&node->uuid));
    }
}

void
uuidset_delete(struct uuidset *set, struct uuidset_node *node)
{
    hmap_remove(&set->uuids, &node->hmap_node);
    free(node);
}

struct uuid*
uuidset_array(const struct uuidset *set)
{
    struct uuid *array = xmalloc(uuidset_count(set) * sizeof *array);
    struct uuidset_node *node;
    size_t i = 0;

    UUIDSET_FOR_EACH (node, set) {
        array[i++] = node->uuid;
    }
    return array;
}
