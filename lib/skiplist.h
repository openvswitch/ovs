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

#ifndef LIB_SKIPLIST_H_
#define LIB_SKIPLIST_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef int (skiplist_comparator)(const void *a, const void *b,
                                  const void *conf);

struct skiplist_node;

struct skiplist;

#define SKIPLIST_FOR_EACH (SKIPLIST_NODE, SKIPLIST) \
    for (SKIPLIST_NODE = skiplist_first(SKIPLIST); \
         SKIPLIST_NODE; \
         SKIPLIST_NODE = skiplist_next(SKIPLIST_NODE))

struct skiplist *skiplist_create(skiplist_comparator *object_comparator,
                                 void *configuration);
void skiplist_insert(struct skiplist *sl, const void *object);
void *skiplist_delete(struct skiplist *sl, const void *object);
struct skiplist_node *skiplist_find(struct skiplist *sl, const void *value);
void *skiplist_get_data(struct skiplist_node *node);
uint32_t skiplist_get_size(struct skiplist *sl);
struct skiplist_node *skiplist_forward_to(struct skiplist *sl,
                                          const void *value);
struct skiplist_node *skiplist_first(struct skiplist *sl);
struct skiplist_node *skiplist_next(struct skiplist_node *node);
void skiplist_destroy(struct skiplist *sl, void (*func)(void *));

#endif /* LIB_SKIPLIST_H_ */
