/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2016, 2017 Nicira, Inc.
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

#ifndef SIMAP_H
#define SIMAP_H 1

#include "openvswitch/hmap.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* A map from strings to unsigned integers. */
struct simap {
    struct hmap map;            /* Contains "struct simap_node"s. */
};

struct simap_node {
    struct hmap_node node;      /* In struct simap's 'map' hmap. */
    char *name;
    unsigned int data;
};

#define SIMAP_INITIALIZER(SIMAP) { HMAP_INITIALIZER(&(SIMAP)->map) }

#define SIMAP_FOR_EACH(SIMAP_NODE, SIMAP)                               \
    HMAP_FOR_EACH_INIT (SIMAP_NODE, node, &(SIMAP)->map,                \
                        BUILD_ASSERT_TYPE(SIMAP_NODE, struct simap_node *), \
                        BUILD_ASSERT_TYPE(SIMAP, struct simap *))

#define SIMAP_FOR_EACH_SAFE(SIMAP_NODE, NEXT, SIMAP)                    \
    HMAP_FOR_EACH_SAFE_INIT (SIMAP_NODE, NEXT, node, &(SIMAP)->map,     \
                        BUILD_ASSERT_TYPE(SIMAP_NODE, struct simap_node *), \
                        BUILD_ASSERT_TYPE(NEXT, struct simap_node *),   \
                        BUILD_ASSERT_TYPE(SIMAP, struct simap *))

void simap_init(struct simap *);
void simap_destroy(struct simap *);
void simap_swap(struct simap *, struct simap *);
void simap_moved(struct simap *);
void simap_clear(struct simap *);

bool simap_is_empty(const struct simap *);
size_t simap_count(const struct simap *);

bool simap_put(struct simap *, const char *, unsigned int);
unsigned int simap_increase(struct simap *, const char *, unsigned int);

unsigned int simap_get(const struct simap *, const char *);
struct simap_node *simap_find(const struct simap *, const char *);
struct simap_node *simap_find_len(const struct simap *,
                                  const char *, size_t len);
bool simap_contains(const struct simap *, const char *);

void simap_delete(struct simap *, struct simap_node *);
bool simap_find_and_delete(struct simap *, const char *);

const struct simap_node **simap_sort(const struct simap *);
bool simap_equal(const struct simap *, const struct simap *);
uint32_t simap_hash(const struct simap *);

#ifdef  __cplusplus
}
#endif

#endif /* simap.h */
