/*
 * Copyright (c) 2017-2018 Nicira, Inc.
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
#include "openvswitch/namemap.h"
#include <ctype.h>
#include "hash.h"
#include "openvswitch/dynamic-string.h"
#include "openvswitch/json.h"

void
namemap_init(struct namemap *map)
{
    hmap_init(&map->by_name);
    hmap_init(&map->by_number);
}

struct namemap_node *
namemap_find_by_name(const struct namemap *map, const char *name)
{
    struct namemap_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, name_node, hash_string(name, 0),
                             &map->by_name) {
        if (!strcmp(name, node->name)) {
            return node;
        }
    }
    return NULL;
}

struct namemap_node *
namemap_find_by_number(const struct namemap *map, uint32_t number)
{
    struct namemap_node *node;

    HMAP_FOR_EACH_IN_BUCKET (node, number_node, hash_int(number, 0),
                             &map->by_number) {
        if (node->number == number) {
            return node;
        }
    }
    return NULL;
}

void
namemap_put(struct namemap *map, uint32_t number, const char *name)
{
    struct namemap_node *node;

    /* Look for duplicate name. */
    node = namemap_find_by_name(map, name);
    if (node) {
        if (node->number != number) {
            node->duplicate = true;
        }
        return;
    }

    /* Look for duplicate number. */
    node = namemap_find_by_number(map, number);
    if (node) {
        node->duplicate = true;
        return;
    }

    /* Add new node. */
    node = xmalloc(sizeof *node);
    hmap_insert(&map->by_number, &node->number_node, hash_int(number, 0));
    hmap_insert(&map->by_name, &node->name_node, hash_string(name, 0));
    node->number = number;
    node->name = xstrdup(name);
    node->duplicate = false;
}

void
namemap_destroy(struct namemap *map)
{
    if (map) {
        struct namemap_node *node, *next;

        HMAP_FOR_EACH_SAFE (node, next, name_node, &map->by_name) {
            hmap_remove(&map->by_name, &node->name_node);
            hmap_remove(&map->by_number, &node->number_node);
            free(node->name);
            free(node);
        }
        hmap_destroy(&map->by_name);
        hmap_destroy(&map->by_number);
    }
}

/* A table or port name doesn't need to be quoted if it is alphanumeric and
 * starts with a letter. */
static bool
name_needs_quotes(const char *name)
{
    if (!isalpha((unsigned char) name[0])) {
        return true;
    }

    for (const char *p = name + 1; *p; p++) {
        if (!isalnum((unsigned char) *p)) {
            return true;
        }
    }
    return false;
}

/* Appends port or table 'name' to 's', quoting it if necessary. */
void
namemap_put_name(const char *name, struct ds *s)
{
    if (name_needs_quotes(name)) {
        json_string_escape(name, s);
    } else {
        ds_put_cstr(s, name);
    }
}
