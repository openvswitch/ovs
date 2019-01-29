/* Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/* Skiplist implementation based on:
 * "Skip List: A Probabilistic Alternative to Balanced Trees",
 * by William Pugh. */

#include <config.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "skiplist.h"
#include "random.h"
#include "util.h"

/*
 * A maximum height level of 32 should be more than sufficient for
 * anticipated use cases, delivering good expected performance with
 * up to 2**32 list nodes. Changes to this limit will also require
 * changes in skiplist_determine_level().
 */
#define SKIPLIST_MAX_LEVELS 32

/* Skiplist node container */
struct skiplist_node {
    const void *data;                 /* Pointer to saved data. */
    struct skiplist_node *forward[];  /* Links to the next nodes. */
};

/* Skiplist container */
struct skiplist {
    struct skiplist_node *header; /* Pointer to head node (not first
                                   * data node). */
    skiplist_comparator *cmp;     /* Pointer to the skiplist's comparison
                                   * function. */
    void *cfg;                    /* Pointer to optional comparison
                                   * configuration, used by the comparator. */
    int level;                    /* Maximum level currently in use. */
    uint32_t size;                /* Current number of nodes in skiplist. */
};

/* Create a new skiplist_node with given level and data. */
static struct skiplist_node *
skiplist_create_node(int level, const void *object)
{
    struct skiplist_node *new_node;
    size_t alloc_size = sizeof *new_node +
                        (level + 1) * sizeof new_node->forward[0];

    new_node = xmalloc(alloc_size);
    new_node->data = object;
    memset(new_node->forward, 0,
           (level + 1) * sizeof new_node->forward[0]);

    return new_node;
}

/*
 * Create a new skiplist, configured with given data comparison function
 * and configuration.
 */
struct skiplist *
skiplist_create(skiplist_comparator object_comparator, void *configuration)
{
    random_init();
    struct skiplist *sl;

    sl = xmalloc(sizeof (struct skiplist));
    sl->cfg = configuration;
    sl->size = 0;
    sl->level = 0;
    sl->cmp = object_comparator;
    sl->header = skiplist_create_node(SKIPLIST_MAX_LEVELS, NULL);

    return sl;
}

/*
 * Move the cursor forward to the first node with associated data greater than
 * or equal to "value".
 */
static struct skiplist_node *
skiplist_forward_to_(struct skiplist *sl, const void *value,
                     struct skiplist_node **update)
{
    struct skiplist_node *x = sl->header;
    int i;

    /* Loop invariant: x < value */
    for (i = sl->level; i >= 0; i--) {
        while (x->forward[i] &&
               sl->cmp(x->forward[i]->data, value, sl->cfg) < 0) {
            x = x->forward[i];
        }
        /* x < value <= x->forward[1] */
        if (update) {
            update[i] = x;
        }
    }
    /* x < value <= x->forward[1] */
    x = x->forward[0];
    return x;
}

struct skiplist_node *
skiplist_forward_to(struct skiplist *sl, const void *value)
{
    return skiplist_forward_to_(sl, value, NULL);
}

/* Find the first exact match of value in the skiplist. */
struct skiplist_node *
skiplist_find(struct skiplist *sl, const void *value)
{
    struct skiplist_node *x = skiplist_forward_to(sl, value);

    return x && sl->cmp(x->data, value, sl->cfg) == 0 ? x : NULL;
}

/*
 * Determine the level for a skiplist node by choosing a level N with
 * probability P(N) = 1/(2**(N+1)) in the range 0..32, with  the returned
 * level clamped at the current skiplist height plus 1.
 */
static int
skiplist_determine_level(struct skiplist *sl)
{
    int lvl;

    lvl = clz32(random_uint32());

    return MIN(lvl, sl->level + 1);
}

/* Insert data into a skiplist. */
void
skiplist_insert(struct skiplist *list, const void *value)
{
    struct skiplist_node *update[SKIPLIST_MAX_LEVELS + 1];
    struct skiplist_node *x = skiplist_forward_to_(list, value, update);
    int i, lvl;

    if (x && list->cmp(x->data, value, list->cfg) == 0) {
        x->data = value;
    } else {
        lvl = skiplist_determine_level(list);
        if (lvl > list->level) {
            for (i = list->level + 1; i <= lvl; i++) {
                update[i] = list->header;
            }
            list->level = lvl;
        }
        x = skiplist_create_node(lvl, value);
        for (i = 0; i <= lvl; i++) {
            x->forward[i] = update[i]->forward[i];
            update[i]->forward[i] = x;
        }
        list->size++;
    }
}

/* Remove first node with associated data equal to "value" from skiplist. */
void *
skiplist_delete(struct skiplist *list, const void *value)
{
    struct skiplist_node *update[SKIPLIST_MAX_LEVELS + 1];
    struct skiplist_node *x;
    void *data = NULL;
    int i;

    x = skiplist_forward_to_(list, value, update);

    if (x && list->cmp(x->data, value, list->cfg) == 0) {
        for (i = 0; i <= list->level; i++) {
            if (update[i]->forward[i] != x) {
                break;
            }
            update[i]->forward[i] = x->forward[i];
        }
        data = CONST_CAST(void *, x->data);

        free(x);

        while (list->level > 0 && !list->header->forward[list->level]) {
            list->level--;
        }
        list->size--;
    }
    return data;
}

/* Get the associated data value stored in a skiplist node. */
void *
skiplist_get_data(struct skiplist_node *node)
{
    return node ? CONST_CAST(void *, node->data) : NULL;
}

/* Get the number of items in a skiplist. */
uint32_t
skiplist_get_size(struct skiplist *sl)
{
    return sl->size;
}

/* Get the first node in a skiplist.  */
struct skiplist_node *
skiplist_first(struct skiplist *sl)
{
    return sl->header->forward[0];
}

/* Get a node's successor in a skiplist. */
struct skiplist_node *
skiplist_next(struct skiplist_node *node)
{
    return node ? node->forward[0] : NULL;
}

/*
 * Destroy a skiplist and free all nodes in the list.  If the "data_destroy"
 * function pointer is non-NULL, it will be called for each node as it is
 * removed to allow any needed cleanups to be performed on the associated
 * data.
 */
void
skiplist_destroy(struct skiplist *sl, void (*data_destroy)(void *))
{
    struct skiplist_node *node, *next;

    next = node = sl->header;
    while (next != NULL) {
        next = node->forward[0];
        if (data_destroy) {
            data_destroy(CONST_CAST(void *, node->data));
        }
        free(node);
        node = next;
    }
    free(sl);
}
