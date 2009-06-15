/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#include "hmap.h"
#include <assert.h>
#include <stdint.h>
#include "coverage.h"
#include "util.h"

/* Initializes 'hmap' as an empty hash table. */
void
hmap_init(struct hmap *hmap)
{
    hmap->buckets = &hmap->one;
    hmap->one = NULL;
    hmap->mask = 0;
    hmap->n = 0;
}

/* Frees memory reserved by 'hmap'.  It is the client's responsibility to free
 * the nodes themselves, if necessary. */
void
hmap_destroy(struct hmap *hmap)
{
    if (hmap && hmap->buckets != &hmap->one) {
        free(hmap->buckets);
    }
}

/* Exchanges hash maps 'a' and 'b'. */
void
hmap_swap(struct hmap *a, struct hmap *b)
{
    struct hmap tmp = *a;
    *a = *b;
    *b = tmp;
    if (a->buckets == &b->one) {
        a->buckets = &a->one;
    }
    if (b->buckets == &a->one) {
        b->buckets = &b->one;
    }
}

static void
resize(struct hmap *hmap, size_t new_mask)
{
    struct hmap tmp;
    size_t i;

    assert(!(new_mask & (new_mask + 1)));
    assert(new_mask != SIZE_MAX);

    hmap_init(&tmp);
    if (new_mask) {
        tmp.buckets = xmalloc(sizeof *tmp.buckets * (new_mask + 1));
        tmp.mask = new_mask;
        for (i = 0; i <= tmp.mask; i++) {
            tmp.buckets[i] = NULL;
        }
    }
    for (i = 0; i <= hmap->mask; i++) {
        struct hmap_node *node, *next;
        int count = 0;
        for (node = hmap->buckets[i]; node; node = next) {
            next = node->next;
            hmap_insert_fast(&tmp, node, node->hash);
            count++;
        }
        if (count > 5) {
            COVERAGE_INC(hmap_pathological);
        }
    }
    hmap_swap(hmap, &tmp);
    hmap_destroy(&tmp);
}

static size_t
calc_mask(size_t capacity)
{
    size_t mask = capacity / 2;
    mask |= mask >> 1;
    mask |= mask >> 2;
    mask |= mask >> 4;
    mask |= mask >> 8;
    mask |= mask >> 16;
#if SIZE_MAX > UINT32_MAX
    mask |= mask >> 32;
#endif

    /* If we need to dynamically allocate buckets we might as well allocate at
     * least 4 of them. */
    mask |= (mask & 1) << 1;

    return mask;
}

/* Expands 'hmap', if necessary, to optimize the performance of searches. */
void
hmap_expand(struct hmap *hmap)
{
    size_t new_mask = calc_mask(hmap->n);
    if (new_mask > hmap->mask) {
        COVERAGE_INC(hmap_expand);
        resize(hmap, new_mask);
    }
}

/* Shrinks 'hmap', if necessary, to optimize the performance of iteration. */
void
hmap_shrink(struct hmap *hmap)
{
    size_t new_mask = calc_mask(hmap->n);
    if (new_mask < hmap->mask) {
        COVERAGE_INC(hmap_shrink);
        resize(hmap, new_mask);
    }
}

/* Expands 'hmap', if necessary, to optimize the performance of searches when
 * it has up to 'n' elements.  (But iteration will be slow in a hash map whose
 * allocated capacity is much higher than its current number of nodes.)  */
void
hmap_reserve(struct hmap *hmap, size_t n)
{
    size_t new_mask = calc_mask(n);
    if (new_mask > hmap->mask) {
        COVERAGE_INC(hmap_reserve);
        resize(hmap, new_mask);
    }
}
