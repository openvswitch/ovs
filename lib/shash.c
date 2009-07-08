/*
 * Copyright (c) 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#include "shash.h"
#include <assert.h>
#include "hash.h"

static size_t
hash_name(const char *name)
{
    return hash_string(name, 0);
}

void
shash_init(struct shash *sh)
{
    hmap_init(&sh->map);
}

void
shash_destroy(struct shash *sh)
{
    if (sh) {
        shash_clear(sh);
    }
}

void
shash_clear(struct shash *sh)
{
    struct shash_node *node, *next;

    HMAP_FOR_EACH_SAFE (node, next, struct shash_node, node, &sh->map) {
        hmap_remove(&sh->map, &node->node);
        free(node->name);
        free(node);
    }
}

/* It is the caller's responsible to avoid duplicate names, if that is
 * desirable. */
void
shash_add(struct shash *sh, const char *name, void *data)
{
    struct shash_node *node = xmalloc(sizeof *node);
    node->name = xstrdup(name);
    node->data = data;
    hmap_insert(&sh->map, &node->node, hash_name(name));
}

void
shash_delete(struct shash *sh, struct shash_node *node)
{
    hmap_remove(&sh->map, &node->node);
    free(node->name);
    free(node);
}

/* If there are duplicates, returns a random element. */
struct shash_node *
shash_find(const struct shash *sh, const char *name)
{
    struct shash_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, struct shash_node, node,
                             hash_name(name), &sh->map) {
        if (!strcmp(node->name, name)) {
            return node;
        }
    }
    return NULL;
}

void *
shash_find_data(const struct shash *sh, const char *name)
{
    struct shash_node *node = shash_find(sh, name);
    return node ? node->data : NULL;
}
