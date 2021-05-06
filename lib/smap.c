/* Copyright (c) 2012, 2014, 2015, 2016 Nicira, Inc.
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
 * limitations under the License. */

#include <config.h>
#include "smap.h"

#include <strings.h>

#include "hash.h"
#include "openvswitch/json.h"
#include "packets.h"
#include "util.h"
#include "uuid.h"

static struct smap_node *smap_add__(struct smap *, char *, void *,
                                    size_t hash);
static struct smap_node *smap_find__(const struct smap *, const char *key,
                                     size_t key_len, size_t hash);
static int compare_nodes_by_key(const void *, const void *);

/* Public Functions. */

void
smap_init(struct smap *smap)
{
    hmap_init(&smap->map);
}

void
smap_destroy(struct smap *smap)
{
    if (smap) {
        smap_clear(smap);
        hmap_destroy(&smap->map);
    }
}

/* Adds 'key' paired with 'value' to 'smap'.  It is the caller's responsibility
 * to avoid duplicate keys if desirable. */
struct smap_node *
smap_add(struct smap *smap, const char *key, const char *value)
{
    size_t key_len = strlen(key);
    return smap_add__(smap, xmemdup0(key, key_len), xstrdup(value),
                      hash_bytes(key, key_len, 0));
}

/* Adds 'key' paired with 'value' to 'smap'.  Takes ownership of 'key' and
 * 'value' (which will eventually be freed with free()).  It is the caller's
 * responsibility to avoid duplicate keys if desirable. */
struct smap_node *
smap_add_nocopy(struct smap *smap, char *key, char *value)
{
    return smap_add__(smap, key, value, hash_bytes(key, strlen(key), 0));
}

/* Attempts to add 'key' to 'smap' associated with 'value'.  If 'key' already
 * exists in 'smap', does nothing and returns false.  Otherwise, performs the
 * addition and returns true. */
bool
smap_add_once(struct smap *smap, const char *key, const char *value)
{
    if (!smap_get(smap, key)) {
        smap_add(smap, key, value);
        return true;
    } else {
        return false;
    }
}

/* Adds 'key' paired with a value derived from 'format' (similar to printf).
 * It is the caller's responsibility to avoid duplicate keys if desirable. */
void
smap_add_format(struct smap *smap, const char *key, const char *format, ...)
{
    size_t key_len;
    va_list args;
    char *value;

    va_start(args, format);
    value = xvasprintf(format, args);
    va_end(args);

    key_len = strlen(key);
    smap_add__(smap, xmemdup0(key, key_len), value,
               hash_bytes(key, key_len, 0));
}

/* Adds 'key' paired with a string representation of 'addr'. It is the
 * caller's responsibility to avoid duplicate keys if desirable. */
void
smap_add_ipv6(struct smap *smap, const char *key, struct in6_addr *addr)
{
    char buf[INET6_ADDRSTRLEN];
    ipv6_string_mapped(buf, addr);
    smap_add(smap, key, buf);
}

/* Searches for 'key' in 'smap'.  If it does not already exists, adds it.
 * Otherwise, changes its value to 'value'.  The caller retains ownership of
 * 'value'. */
void
smap_replace(struct smap *smap, const char *key, const char *value)
{
    smap_replace_nocopy(smap, key, xstrdup(value));
}

/* Searches for 'key' in 'smap'.  If it does not already exists, adds it.
 * Otherwise, changes its value to 'value'.  Takes ownership of 'value'. */
void
smap_replace_nocopy(struct smap *smap, const char *key, char *value)
{
    size_t  key_len = strlen(key);
    size_t hash = hash_bytes(key, key_len, 0);

    struct smap_node *node;

    node = smap_find__(smap, key, key_len, hash);
    if (node) {
        free(node->value);
        node->value = value;
    } else {
        smap_add__(smap, xmemdup0(key, key_len), value, hash);
    }
}

/* If 'key' is in 'smap', removes it.  Otherwise does nothing. */
void
smap_remove(struct smap *smap, const char *key)
{
    struct smap_node *node = smap_get_node(smap, key);

    if (node) {
        smap_remove_node(smap, node);
    }
}

/* Removes 'node' from 'smap'. */
void
smap_remove_node(struct smap *smap, struct smap_node *node)
{
    hmap_remove(&smap->map, &node->node);
    free(node->key);
    free(node->value);
    free(node);
}

/* Deletes 'node' from 'smap'.
 *
 * If 'keyp' is nonnull, stores the node's key in '*keyp' and transfers
 * ownership to the caller.  Otherwise, frees the node's key.  Similarly for
 * 'valuep' and the node's value. */
void
smap_steal(struct smap *smap, struct smap_node *node,
           char **keyp, char **valuep)
{
    if (keyp) {
        *keyp = node->key;
    } else {
        free(node->key);
    }

    if (valuep) {
        *valuep = node->value;
    } else {
        free(node->value);
    }

    hmap_remove(&smap->map, &node->node);
    free(node);
}

/* Removes all key-value pairs from 'smap'. */
void
smap_clear(struct smap *smap)
{
    struct smap_node *node, *next;

    SMAP_FOR_EACH_SAFE (node, next, smap) {
        smap_remove_node(smap, node);
    }
}

/* Returns the value associated with 'key' in 'smap'.
 * If 'smap' does not contain 'key', returns NULL. */
const char *
smap_get(const struct smap *smap, const char *key)
{
    return smap_get_def(smap, key, NULL);
}

/* Returns the value associated with 'key' in 'smap'.
 * If 'smap' does not contain 'key', returns 'def'. */
const char *
smap_get_def(const struct smap *smap, const char *key, const char *def)
{
    struct smap_node *node = smap_get_node(smap, key);
    return node ? node->value : def;
}

/* Returns the node associated with 'key' in 'smap', or NULL. */
struct smap_node *
smap_get_node(const struct smap *smap, const char *key)
{
    size_t key_len = strlen(key);
    return smap_find__(smap, key, key_len, hash_bytes(key, key_len, 0));
}

/* Gets the value associated with 'key' in 'smap' and converts it to a boolean.
 * If 'key' is not in 'smap', or its value is neither "true" nor "false",
 * returns 'def'. */
bool
smap_get_bool(const struct smap *smap, const char *key, bool def)
{
    const char *value = smap_get_def(smap, key, "");
    if (def) {
        return strcasecmp("false", value) != 0;
    } else {
        return !strcasecmp("true", value);
    }
}

/* Gets the value associated with 'key' in 'smap' and converts it to an int.
 * If 'key' is not in 'smap' or a valid integer can't be parsed from it's
 * value, returns 'def'. */
int
smap_get_int(const struct smap *smap, const char *key, int def)
{
    const char *value = smap_get(smap, key);
    int i_value;

    if (!value || !str_to_int(value, 10, &i_value)) {
        return def;
    }

    return i_value;
}

/* Gets the value associated with 'key' in 'smap' and converts it to an
 * unsigned int. If 'key' is not in 'smap' or a valid unsigned integer
 * can't be parsed from it's value, returns 'def'. */
unsigned int
smap_get_uint(const struct smap *smap, const char *key, unsigned int def)
{
    const char *value = smap_get(smap, key);
    unsigned int u_value;

    if (!value || !str_to_uint(value, 10, &u_value)) {
        return def;
    }

    return u_value;
}

/* Gets the value associated with 'key' in 'smap' and converts it to an
 * unsigned long long.  If 'key' is not in 'smap' or a valid number can't be
 * parsed from it's value, returns 'def'. */
unsigned long long int
smap_get_ullong(const struct smap *smap, const char *key,
                unsigned long long def)
{
    const char *value = smap_get(smap, key);
    unsigned long long ull_value;

    if (!value || !str_to_ullong(value, 10, &ull_value)) {
        return def;
    }

    return ull_value;
}

/* Gets the value associated with 'key' in 'smap' and converts it to a UUID
 * using uuid_from_string().  Returns true if successful, false if 'key' is not
 * in 'smap' or if 'key' does not have the correct syntax for a UUID. */
bool
smap_get_uuid(const struct smap *smap, const char *key, struct uuid *uuid)
{
    return uuid_from_string(uuid, smap_get_def(smap, key, ""));
}

/* Returns true of there are no elements in 'smap'. */
bool
smap_is_empty(const struct smap *smap)
{
    return hmap_is_empty(&smap->map);
}

/* Returns the number of elements in 'smap'. */
size_t
smap_count(const struct smap *smap)
{
    return hmap_count(&smap->map);
}

/* Initializes 'dst' as a clone of 'src. */
void
smap_clone(struct smap *dst, const struct smap *src)
{
    const struct smap_node *node;

    smap_init(dst);
    SMAP_FOR_EACH (node, src) {
        smap_add__(dst, xstrdup(node->key), xstrdup(node->value),
                   node->node.hash);
    }
}

/* Returns an array of nodes sorted on key or NULL if 'smap' is empty.  The
 * caller is responsible for freeing this array. */
const struct smap_node **
smap_sort(const struct smap *smap)
{
    if (smap_is_empty(smap)) {
        return NULL;
    } else {
        const struct smap_node **nodes;
        struct smap_node *node;
        size_t i, n;

        n = smap_count(smap);
        nodes = xmalloc(n * sizeof *nodes);
        i = 0;
        SMAP_FOR_EACH (node, smap) {
            nodes[i++] = node;
        }
        ovs_assert(i == n);

        qsort(nodes, n, sizeof *nodes, compare_nodes_by_key);

        return nodes;
    }
}

/* Adds each of the key-value pairs from 'json' (which must be a JSON object
 * whose values are strings) to 'smap'.
 *
 * The caller must have initialized 'smap'.
 *
 * The caller retains ownership of 'json' and everything in it. */
void
smap_from_json(struct smap *smap, const struct json *json)
{
    const struct shash_node *node;

    SHASH_FOR_EACH (node, json_object(json)) {
        const struct json *value = node->data;
        smap_add(smap, node->name, json_string(value));
    }
}

/* Returns a JSON object that maps from the keys in 'smap' to their values.
 *
 * The caller owns the returned value and must eventually json_destroy() it.
 *
 * The caller retains ownership of 'smap' and everything in it. */
struct json *
smap_to_json(const struct smap *smap)
{
    const struct smap_node *node;
    struct json *json;

    json = json_object_create();
    SMAP_FOR_EACH (node, smap) {
        json_object_put_string(json, node->key, node->value);
    }
    return json;
}

/* Returns true if the two maps are equal, meaning that they have the same set
 * of key-value pairs.
 */
bool
smap_equal(const struct smap *smap1, const struct smap *smap2)
{
    if (smap_count(smap1) != smap_count(smap2)) {
        return false;
    }

    const struct smap_node *node;
    SMAP_FOR_EACH (node, smap1) {
        const char *value2 = smap_get(smap2, node->key);
        if (!value2 || strcmp(node->value, value2)) {
            return false;
        }
    }
    return true;
}

/* Private Helpers. */

static struct smap_node *
smap_add__(struct smap *smap, char *key, void *value, size_t hash)
{
    struct smap_node *node = xmalloc(sizeof *node);
    node->key = key;
    node->value = value;
    hmap_insert(&smap->map, &node->node, hash);
    return node;
}

static struct smap_node *
smap_find__(const struct smap *smap, const char *key, size_t key_len,
            size_t hash)
{
    struct smap_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, node, hash, &smap->map) {
        if (!strncmp(node->key, key, key_len) && !node->key[key_len]) {
            return node;
        }
    }

    return NULL;
}

static int
compare_nodes_by_key(const void *a_, const void *b_)
{
    const struct smap_node *const *a = a_;
    const struct smap_node *const *b = b_;
    return strcmp((*a)->key, (*b)->key);
}
