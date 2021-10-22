/*
 * Copyright (c) 2010, Andrea Mazzoleni. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
#include "tommyhashdyn.h"
#include "tommylist.h"

/******************************************************************************/
/* hashdyn */

void tommy_hashdyn_init(tommy_hashdyn* hashdyn)
{
    /* fixed initial size */
    hashdyn->bucket_bit = TOMMY_HASHDYN_BIT;
    hashdyn->bucket_max = (tommy_size_t)1 << hashdyn->bucket_bit;
    hashdyn->bucket_mask = hashdyn->bucket_max - 1;
    hashdyn->bucket = tommy_cast(tommy_hashdyn_node**, tommy_calloc(hashdyn->bucket_max, sizeof(tommy_hashdyn_node*)));

    hashdyn->count = 0;
}

void tommy_hashdyn_done(tommy_hashdyn* hashdyn)
{
    tommy_free(hashdyn->bucket);
}

/**
 * Resize the bucket vector.
 */
static void tommy_hashdyn_resize(tommy_hashdyn* hashdyn, tommy_size_t new_bucket_bit)
{
    tommy_size_t bucket_bit;
    tommy_size_t bucket_max;
    tommy_size_t new_bucket_max;
    tommy_size_t new_bucket_mask;
    tommy_hashdyn_node** new_bucket;

    bucket_bit = hashdyn->bucket_bit;
    bucket_max = hashdyn->bucket_max;

    new_bucket_max = (tommy_size_t)1 << new_bucket_bit;
    new_bucket_mask = new_bucket_max - 1;

    /* allocate the new vector using malloc() and not calloc() */
    /* because data is fully initialized in the update process */
    new_bucket = tommy_cast(tommy_hashdyn_node**, tommy_malloc(new_bucket_max * sizeof(tommy_hashdyn_node*)));

    /* reinsert all the elements */
    if (new_bucket_bit > bucket_bit) {
        tommy_size_t i;

        /* grow */
        for (i = 0; i < bucket_max; ++i) {
            tommy_hashdyn_node* j;

            /* setup the new two buckets */
            new_bucket[i] = 0;
            new_bucket[i + bucket_max] = 0;

            /* reinsert the bucket */
            j = hashdyn->bucket[i];
            while (j) {
                tommy_hashdyn_node* j_next = j->next;
                tommy_size_t pos = j->index & new_bucket_mask;
                if (new_bucket[pos])
                    tommy_list_insert_tail_not_empty(new_bucket[pos], j);
                else
                    tommy_list_insert_first(&new_bucket[pos], j);
                j = j_next;
            }
        }
    } else {
        tommy_size_t i;

        /* shrink */
        for (i = 0; i < new_bucket_max; ++i) {
            /* setup the new bucket with the lower bucket*/
            new_bucket[i] = hashdyn->bucket[i];

            /* concat the upper bucket */
            tommy_list_concat(&new_bucket[i], &hashdyn->bucket[i + new_bucket_max]);
        }
    }

    tommy_free(hashdyn->bucket);

    /* setup */
    hashdyn->bucket_bit = new_bucket_bit;
    hashdyn->bucket_max = new_bucket_max;
    hashdyn->bucket_mask = new_bucket_mask;
    hashdyn->bucket = new_bucket;
}

/**
 * Grow.
 */
tommy_inline void hashdyn_grow_step(tommy_hashdyn* hashdyn)
{
    /* grow if more than 50% full */
    if (hashdyn->count >= hashdyn->bucket_max / 2)
        tommy_hashdyn_resize(hashdyn, hashdyn->bucket_bit + 1);
}

/**
 * Shrink.
 */
tommy_inline void hashdyn_shrink_step(tommy_hashdyn* hashdyn)
{
    /* shrink if less than 12.5% full */
    if (hashdyn->count <= hashdyn->bucket_max / 8 && hashdyn->bucket_bit > TOMMY_HASHDYN_BIT)
        tommy_hashdyn_resize(hashdyn, hashdyn->bucket_bit - 1);
}

void tommy_hashdyn_insert(tommy_hashdyn* hashdyn, tommy_hashdyn_node* node, void* data, tommy_hash_t hash)
{
    tommy_size_t pos = hash & hashdyn->bucket_mask;

    tommy_list_insert_tail(&hashdyn->bucket[pos], node, data);

    node->index = hash;

    ++hashdyn->count;

    hashdyn_grow_step(hashdyn);
}

void* tommy_hashdyn_remove_existing(tommy_hashdyn* hashdyn, tommy_hashdyn_node* node)
{
    tommy_size_t pos = node->index & hashdyn->bucket_mask;

    tommy_list_remove_existing(&hashdyn->bucket[pos], node);

    --hashdyn->count;

    hashdyn_shrink_step(hashdyn);

    return node->data;
}

void* tommy_hashdyn_remove(tommy_hashdyn* hashdyn, tommy_search_func* cmp, const void* cmp_arg, tommy_hash_t hash)
{
    tommy_size_t pos = hash & hashdyn->bucket_mask;
    tommy_hashdyn_node* node = hashdyn->bucket[pos];

    while (node) {
        /* we first check if the hash matches, as in the same bucket we may have multiples hash values */
        if (node->index == hash && cmp(cmp_arg, node->data) == 0) {
            tommy_list_remove_existing(&hashdyn->bucket[pos], node);

            --hashdyn->count;

            hashdyn_shrink_step(hashdyn);

            return node->data;
        }
        node = node->next;
    }

    return 0;
}

void tommy_hashdyn_foreach(tommy_hashdyn* hashdyn, tommy_foreach_func* func)
{
    tommy_size_t bucket_max = hashdyn->bucket_max;
    tommy_hashdyn_node** bucket = hashdyn->bucket;
    tommy_size_t pos;

    for (pos = 0; pos < bucket_max; ++pos) {
        tommy_hashdyn_node* node = bucket[pos];

        while (node) {
            void* data = node->data;
            node = node->next;
            func(data);
        }
    }
}

void tommy_hashdyn_foreach_arg(tommy_hashdyn* hashdyn, tommy_foreach_arg_func* func, void* arg)
{
    tommy_size_t bucket_max = hashdyn->bucket_max;
    tommy_hashdyn_node** bucket = hashdyn->bucket;
    tommy_size_t pos;

    for (pos = 0; pos < bucket_max; ++pos) {
        tommy_hashdyn_node* node = bucket[pos];

        while (node) {
            void* data = node->data;
            node = node->next;
            func(arg, data);
        }
    }
}

tommy_size_t tommy_hashdyn_memory_usage(tommy_hashdyn* hashdyn)
{
    return hashdyn->bucket_max * (tommy_size_t)sizeof(hashdyn->bucket[0])
           + tommy_hashdyn_count(hashdyn) * (tommy_size_t)sizeof(tommy_hashdyn_node);
}
