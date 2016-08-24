/*
 * Copyright (c) 2011, 2016 Nicira, Inc.
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

#ifndef HMAPX_H
#define HMAPX_H

#include "openvswitch/hmap.h"

struct hmapx_node {
    struct hmap_node hmap_node;
    void *data;
};

/* A set of "void *" pointers. */
struct hmapx {
    struct hmap map;
};

#define HMAPX_INITIALIZER(HMAPX) { HMAP_INITIALIZER(&(HMAPX)->map) }

/* Basics. */
void hmapx_init(struct hmapx *);
void hmapx_destroy(struct hmapx *);
void hmapx_clone(struct hmapx *, const struct hmapx *);
void hmapx_swap(struct hmapx *, struct hmapx *);
void hmapx_moved(struct hmapx *);

/* Count. */
bool hmapx_is_empty(const struct hmapx *);
size_t hmapx_count(const struct hmapx *);

/* Insertion. */
struct hmapx_node *hmapx_add(struct hmapx *, void *);
void hmapx_add_assert(struct hmapx *, void *);

/* Deletion. */
void hmapx_clear(struct hmapx *);
void hmapx_delete(struct hmapx *, struct hmapx_node *);
bool hmapx_find_and_delete(struct hmapx *, const void *);
void hmapx_find_and_delete_assert(struct hmapx *, const void *);

/* Search. */
struct hmapx_node *hmapx_find(const struct hmapx *, const void *);
bool hmapx_contains(const struct hmapx *, const void *);
bool hmapx_equals(const struct hmapx *, const struct hmapx *);

/* Iteration. */

/* Iterates through every hmapx_node in HMAPX. */
#define HMAPX_FOR_EACH(NODE, HMAPX)                                     \
    HMAP_FOR_EACH_INIT(NODE, hmap_node, &(HMAPX)->map,                  \
                       BUILD_ASSERT_TYPE(NODE, struct hmapx_node *),    \
                       BUILD_ASSERT_TYPE(HMAPX, struct hmapx *))

/* Safe when NODE may be freed (not needed when NODE may be removed from the
 * hash map but its members remain accessible and intact). */
#define HMAPX_FOR_EACH_SAFE(NODE, NEXT, HMAPX)                          \
    HMAP_FOR_EACH_SAFE_INIT(NODE, NEXT, hmap_node, &(HMAPX)->map,       \
                            BUILD_ASSERT_TYPE(NODE, struct hmapx_node *), \
                            BUILD_ASSERT_TYPE(NEXT, struct hmapx_node *), \
                            BUILD_ASSERT_TYPE(HMAPX, struct hmapx *))

#endif /* hmapx.h */
