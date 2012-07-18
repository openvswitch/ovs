/* Copyright (c) 2012 Nicira, Inc.
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
 * limitations under the License.  */

#ifndef SMAP_H
#define SMAP_H 1

#include "hmap.h"

struct json;

/* A map from string to string. */
struct smap {
    struct hmap map;           /* Contains "struct smap_node"s. */
};

struct smap_node {
    struct hmap_node node;     /* In struct smap's 'map' hmap. */
    char *key;
    char *value;
};

#define SMAP_INITIALIZER(SMAP) { HMAP_INITIALIZER(&(SMAP)->map) }

#define SMAP_FOR_EACH(SMAP_NODE, SMAP) \
    HMAP_FOR_EACH (SMAP_NODE, node, &(SMAP)->map)

#define SMAP_FOR_EACH_SAFE(SMAP_NODE, NEXT, SMAP) \
    HMAP_FOR_EACH_SAFE (SMAP_NODE, NEXT, node, &(SMAP)->map)

void smap_init(struct smap *);
void smap_destroy(struct smap *);

struct smap_node *smap_add(struct smap *, const char *, const char *);
bool smap_add_once(struct smap *, const char *, const char *);
void smap_add_format(struct smap *, const char *key, const char *, ...)
    PRINTF_FORMAT(3, 4);
void smap_replace(struct smap *, const char *, const char *);

void smap_remove(struct smap *, const char *);
void smap_remove_node(struct smap *, struct smap_node *);
void smap_steal(struct smap *, struct smap_node *, char **keyp, char **valuep);
void smap_clear(struct smap *);

const char *smap_get(const struct smap *, const char *);
struct smap_node *smap_get_node(const struct smap *, const char *);
bool smap_get_bool(const struct smap *smap, const char *key, bool def);
int smap_get_int(const struct smap *smap, const char *key, int def);

bool smap_is_empty(const struct smap *);
size_t smap_count(const struct smap *);

void smap_clone(struct smap *dst, const struct smap *src);
const struct smap_node **smap_sort(const struct smap *);

void smap_from_json(struct smap *, const struct json *);
struct json *smap_to_json(const struct smap *);

#endif /* smap.h */
