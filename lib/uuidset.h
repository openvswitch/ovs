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

#ifndef OVN_UUIDSET_H
#define OVN_UUIDSET_H 1

#include "lib/uuid.h"
#include "openvswitch/hmap.h"

/* A node within a set of uuids. */
struct uuidset_node {
    struct hmap_node hmap_node;
    struct uuid uuid;
};

/* A set of UUIDs. */
struct uuidset {
    struct hmap uuids;
};

#define UUIDSET_INITIALIZER(UUIDSET) \
    { .uuids = HMAP_INITIALIZER(&(UUIDSET)->uuids) }

#define UUIDSET_FOR_EACH(NODE, SET) \
    HMAP_FOR_EACH (NODE, hmap_node, &(SET)->uuids)

#define UUIDSET_FOR_EACH_SAFE(NODE, SET) \
    HMAP_FOR_EACH_SAFE (NODE, hmap_node, &(SET)->uuids)

void uuidset_init(struct uuidset *);
void uuidset_destroy(struct uuidset *);
void uuidset_clear(struct uuidset *);
struct uuidset_node *uuidset_find(const struct uuidset *, const struct uuid *);
bool uuidset_find_and_delete(struct uuidset *, const struct uuid *);
void uuidset_insert(struct uuidset *, const struct uuid *);
void uuidset_delete(struct uuidset *, struct uuidset_node *);
struct uuid *uuidset_array(const struct uuidset *);

static inline bool
uuidset_is_empty(const struct uuidset *set)
{
    return hmap_is_empty(&set->uuids);
}

static inline size_t
uuidset_count(const struct uuidset *set)
{
    return hmap_count(&set->uuids);
}

static inline bool
uuidset_contains(const struct uuidset *set, const struct uuid *uuid)
{
    return !!uuidset_find(set, uuid);
}

#endif /* lib/uuidset.h */
