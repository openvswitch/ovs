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

/*
 * Skiplist implementationn based on:
 * "Skip List: A Probabilistic Alternative to Balanced Trees",
 * by William Pugh.
 */

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
 * The primary usage of the skiplists are the compound indexes
 * at the IDL.
 * For that use case 32 height levels is more than enough as
 * it could indexes a table with 4.294.967.296 rows.
 * In case that a new use case require more than that then this
 * number can be changed, but also the way in which the random
 * numbers are generated must be changed.
 */
#define SKIPLIST_MAX_LEVELS 32

/*
 * Skiplist node container
 */
struct skiplist_node {
    const void *data;           /* Pointer to saved data */
    uint64_t height;            /* Height of this node */
    struct skiplist_node *forward[];    /* Links to the next nodes */
};

/*
 * Skiplist container
 */

struct skiplist {
    struct skiplist_node *header;       /* Pointer to head node (not first
                                         * data node) */
    skiplist_comparator *cmp;   /* Pointer to the skiplist's comparison
                                 * function */
    void *cfg;                  /* Pointer to optional comparison
                                 * configuration, used by the comparator */
    int max_levels;             /* Max levels of the skiplist. */
    int64_t size;               /* Current size of the skiplist. */
    int64_t level;              /* Max number of levels used in this skiplist */
    void (*free_func) (void *); /* Function that free the value's memory */
};

static int skiplist_determine_level(struct skiplist *sl);

static struct skiplist_node *skiplist_create_node(int, const void *);

static struct skiplist_node *skiplist_forward_to_(struct skiplist *sl,
                                                  const void *value,
                                                  struct skiplist_node
                                                  **update);

/*
 * skiplist_create returns a new skiplist, configured with given max_levels,
 * data comparer and configuration.
 * Sets a probability of 0.5 (RAND_MAX / 2).
 */
struct skiplist *
skiplist_create(int max_levels, skiplist_comparator object_comparator,
                void *configuration)
{
    random_init();
    struct skiplist *sl;

    sl = xmalloc(sizeof (struct skiplist));
    sl->cfg = configuration;
    sl->max_levels = max_levels < SKIPLIST_MAX_LEVELS ?
        max_levels : SKIPLIST_MAX_LEVELS;
    sl->size = 0;
    sl->level = 0;
    sl->cmp = object_comparator;
    sl->header = skiplist_create_node(sl->max_levels, NULL);
    sl->free_func = NULL;

    return sl;
}

/*
 * Set a custom function that free the value's memory when
 * destroying the skiplist.
 */
void
skiplist_set_free_func(struct skiplist *sl, void (*func) (void *))
{
    sl->free_func = func;
}

/*
 * Determines the correspondent level for a skiplist node.
 * Guarantees that the returned integer is less or equal
 * to the current height of the skiplist plus 1.
 */
static int
skiplist_determine_level(struct skiplist *sl)
{
    int lvl = 0;
    uint32_t random_value = random_uint32();

    while ((random_value & 1) && lvl < sl->max_levels) {
        random_value >>= 1;
        lvl++;
    }
    return lvl;
}

/*
 * Creates a new skiplist_node with given levels and data.
 */
static struct skiplist_node *
skiplist_create_node(int levels, const void *object)
{
    struct skiplist_node *new_node = xmalloc(sizeof (struct skiplist_node) +
                                             (levels +
                                              1) *
                                             sizeof (struct skiplist_node *));
    new_node->data = object;
    new_node->height = levels;
    memset(new_node->forward, 0,
           (levels + 1) * sizeof (struct skiplist_node *));
    return new_node;
}

/*
 * Find the first exact match of value in the skiplist
 */
struct skiplist_node *
skiplist_find(struct skiplist *sl, const void *value)
{
    struct skiplist_node *x = skiplist_forward_to(sl, value);

    return x && sl->cmp(x->data, value, sl->cfg) == 0 ? x : NULL;
}

/*
 * Moves the cursor forward, to the first data equal or greater than value.
 */
struct skiplist_node *
skiplist_forward_to(struct skiplist *sl, const void *value)
{
    return skiplist_forward_to_(sl, value, NULL);
}

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

/*
 * Inserts data into skiplist.
 */
void
skiplist_insert(struct skiplist *list, const void *value)
{
    struct skiplist_node *update[SKIPLIST_MAX_LEVELS + 1] = { NULL };
    int i, lvl;
    struct skiplist_node *x = skiplist_forward_to_(list, value, update);

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

/*
 * Removes first ocurrence of data from skiplist.
 */
void *
skiplist_delete(struct skiplist *list, const void *value)
{
    struct skiplist_node *update[SKIPLIST_MAX_LEVELS + 1] = { NULL };
    void *data = NULL;
    int i;
    struct skiplist_node *x = list->header;

    x = skiplist_forward_to_(list, value, update);

    if (x && list->cmp(x->data, value, list->cfg) == 0) {
        for (i = 0; i <= list->level; i++) {
            if (!update[i]->forward[i] ||
                list->cmp(update[i]->forward[i]->data, value,
                          list->cfg) != 0) {
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

/*
 * Returns the value stored in the skiplist node
 */
void *
skiplist_get_data(struct skiplist_node *node)
{
    return node ? CONST_CAST(void *, node->data) : NULL;
}

/*
 * Returns the count of items in the skiplist
 */
int64_t
skiplist_get_size(struct skiplist *sl)
{
    return sl->size;
}

/*
 * Returns the first element in the skiplist
 */
struct skiplist_node *
skiplist_first(struct skiplist *sl)
{
    return sl->header->forward[0];
}

/*
 * Given a skiplist node, returns a pointer to the next skiplist node.
 */
struct skiplist_node *
skiplist_next(struct skiplist_node *node)
{
    return node ? node->forward[0] : NULL;
}

/*
 * Destroys the skiplist, and frees all the skiplist nodes.
 * If a free function was defined (with skiplist_set_free_func)
 * this frees the stored data with that function, otherwise the
 * data is not freed.
 */
void
skiplist_destroy(struct skiplist *sl)
{
    struct skiplist_node *node, *next;

    next = node = sl->header;
    while (next != NULL) {
        next = node->forward[0];
        if (sl->free_func) {
            sl->free_func(CONST_CAST(void *, node->data));
        }
        free(node);
        node = next;
    }
    free(sl);
}
