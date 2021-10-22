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
#include "tommyhashtbl.h"
#include "tommylist.h"

#include <string.h> /* for memset */

/******************************************************************************/
/* hashtable */

void tommy_hashtable_init(tommy_hashtable* hashtable, tommy_size_t bucket_max)
{
    if (bucket_max < 16)
        bucket_max = 16;
    else
        bucket_max = tommy_roundup_pow2(bucket_max);

    hashtable->bucket_max = bucket_max;
    hashtable->bucket_mask = hashtable->bucket_max - 1;

    /* initialize the vector using malloc()+memset() instead of calloc() */
    /* to ensure that all the memory in really allocated immediately */
    /* by the OS, and not deferred at later time. */
    /* this improves performance, because we start with a fully initialized hashtable. */
    hashtable->bucket = tommy_cast(tommy_hashtable_node**, tommy_malloc(hashtable->bucket_max * sizeof(tommy_hashtable_node*)));
    memset(hashtable->bucket, 0, hashtable->bucket_max * sizeof(tommy_hashtable_node*));

    hashtable->count = 0;
}

void tommy_hashtable_done(tommy_hashtable* hashtable)
{
    tommy_free(hashtable->bucket);
}

void tommy_hashtable_insert(tommy_hashtable* hashtable, tommy_hashtable_node* node, void* data, tommy_hash_t hash)
{
    tommy_size_t pos = hash & hashtable->bucket_mask;

    tommy_list_insert_tail(&hashtable->bucket[pos], node, data);

    node->index = hash;

    ++hashtable->count;
}

void* tommy_hashtable_remove_existing(tommy_hashtable* hashtable, tommy_hashtable_node* node)
{
    tommy_size_t pos = node->index & hashtable->bucket_mask;

    tommy_list_remove_existing(&hashtable->bucket[pos], node);

    --hashtable->count;

    return node->data;
}

void* tommy_hashtable_remove(tommy_hashtable* hashtable, tommy_search_func* cmp, const void* cmp_arg, tommy_hash_t hash)
{
    tommy_size_t pos = hash & hashtable->bucket_mask;
    tommy_hashtable_node* node = hashtable->bucket[pos];

    while (node) {
        /* we first check if the hash matches, as in the same bucket we may have multiples hash values */
        if (node->index == hash && cmp(cmp_arg, node->data) == 0) {
            tommy_list_remove_existing(&hashtable->bucket[pos], node);

            --hashtable->count;

            return node->data;
        }
        node = node->next;
    }

    return 0;
}

void tommy_hashtable_foreach(tommy_hashtable* hashtable, tommy_foreach_func* func)
{
    tommy_size_t bucket_max = hashtable->bucket_max;
    tommy_hashtable_node** bucket = hashtable->bucket;
    tommy_size_t pos;

    for (pos = 0; pos < bucket_max; ++pos) {
        tommy_hashtable_node* node = bucket[pos];

        while (node) {
            void* data = node->data;
            node = node->next;
            func(data);
        }
    }
}

void tommy_hashtable_foreach_arg(tommy_hashtable* hashtable, tommy_foreach_arg_func* func, void* arg)
{
    tommy_size_t bucket_max = hashtable->bucket_max;
    tommy_hashtable_node** bucket = hashtable->bucket;
    tommy_size_t pos;

    for (pos = 0; pos < bucket_max; ++pos) {
        tommy_hashtable_node* node = bucket[pos];

        while (node) {
            void* data = node->data;
            node = node->next;
            func(arg, data);
        }
    }
}

tommy_size_t tommy_hashtable_memory_usage(tommy_hashtable* hashtable)
{
    return hashtable->bucket_max * (tommy_size_t)sizeof(hashtable->bucket[0])
           + tommy_hashtable_count(hashtable) * (tommy_size_t)sizeof(tommy_hashtable_node);
}
