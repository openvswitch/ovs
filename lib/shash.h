/*
 * Copyright (c) 2009, 2010, 2011, 2016 Nicira, Inc.
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

#ifndef SHASH_H
#define SHASH_H 1

#include "hmap.h"
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

struct shash_node {
    struct hmap_node node;
    char *name;
    void *data;
};

struct shash {
    struct hmap map;
};

#define SHASH_INITIALIZER(SHASH) { HMAP_INITIALIZER(&(SHASH)->map) }

#define SHASH_FOR_EACH(SHASH_NODE, SHASH)                               \
    HMAP_FOR_EACH_INIT (SHASH_NODE, node, &(SHASH)->map,                \
                        BUILD_ASSERT_TYPE(SHASH_NODE, struct shash_node *), \
                        BUILD_ASSERT_TYPE(SHASH, struct shash *))

#define SHASH_FOR_EACH_SAFE(SHASH_NODE, NEXT, SHASH)        \
    HMAP_FOR_EACH_SAFE_INIT (                               \
        SHASH_NODE, NEXT, node, &(SHASH)->map,              \
        BUILD_ASSERT_TYPE(SHASH_NODE, struct shash_node *), \
        BUILD_ASSERT_TYPE(NEXT, struct shash_node *),       \
        BUILD_ASSERT_TYPE(SHASH, struct shash *))

void shash_init(struct shash *);
void shash_destroy(struct shash *);
void shash_destroy_free_data(struct shash *);
void shash_swap(struct shash *, struct shash *);
void shash_moved(struct shash *);
void shash_clear(struct shash *);
void shash_clear_free_data(struct shash *);
bool shash_is_empty(const struct shash *);
size_t shash_count(const struct shash *);
struct shash_node *shash_add(struct shash *, const char *, const void *);
struct shash_node *shash_add_nocopy(struct shash *, char *, const void *);
bool shash_add_once(struct shash *, const char *, const void *);
void shash_add_assert(struct shash *, const char *, const void *);
void *shash_replace(struct shash *, const char *, const void *data);
void shash_delete(struct shash *, struct shash_node *);
char *shash_steal(struct shash *, struct shash_node *);
struct shash_node *shash_find(const struct shash *, const char *);
struct shash_node *shash_find_len(const struct shash *, const char *, size_t);
void *shash_find_data(const struct shash *, const char *);
void *shash_find_and_delete(struct shash *, const char *);
void *shash_find_and_delete_assert(struct shash *, const char *);
struct shash_node *shash_first(const struct shash *);
const struct shash_node **shash_sort(const struct shash *);
bool shash_equal_keys(const struct shash *, const struct shash *);
struct shash_node *shash_random_node(struct shash *);

#ifdef  __cplusplus
}
#endif

#endif /* shash.h */
