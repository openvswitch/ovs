/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
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
#ifndef LIST_H
#define LIST_H 1

/* Doubly linked list. */

#include <stdbool.h>
#include <stddef.h>
#include "util.h"

/* Doubly linked list head or element. */
struct list {
    struct list *prev;     /* Previous list element. */
    struct list *next;     /* Next list element. */
};

#define LIST_INITIALIZER(LIST) { LIST, LIST }

void list_init(struct list *);
void list_poison(struct list *);

/* List insertion. */
void list_insert(struct list *, struct list *);
void list_splice(struct list *before, struct list *first, struct list *last);
void list_push_front(struct list *, struct list *);
void list_push_back(struct list *, struct list *);
void list_replace(struct list *, const struct list *);
void list_moved(struct list *);
void list_move(struct list *dst, struct list *src);

/* List removal. */
struct list *list_remove(struct list *);
struct list *list_pop_front(struct list *);
struct list *list_pop_back(struct list *);

/* List elements. */
struct list *list_front(const struct list *);
struct list *list_back(const struct list *);

/* List properties. */
size_t list_size(const struct list *);
bool list_is_empty(const struct list *);
bool list_is_singleton(const struct list *);
bool list_is_short(const struct list *);

#define LIST_FOR_EACH(ITER, MEMBER, LIST)                               \
    for (ASSIGN_CONTAINER(ITER, (LIST)->next, MEMBER);                  \
         &(ITER)->MEMBER != (LIST);                                     \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.next, MEMBER))
#define LIST_FOR_EACH_CONTINUE(ITER, MEMBER, LIST)                      \
    for (ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.next, MEMBER);           \
         &(ITER)->MEMBER != (LIST);                                     \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.next, MEMBER))
#define LIST_FOR_EACH_REVERSE(ITER, MEMBER, LIST)                       \
    for (ASSIGN_CONTAINER(ITER, (LIST)->prev, MEMBER);                  \
         &(ITER)->MEMBER != (LIST);                                     \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER))
#define LIST_FOR_EACH_REVERSE_CONTINUE(ITER, MEMBER, LIST)              \
    for (ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER);           \
         &(ITER)->MEMBER != (LIST);                                     \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER))
#define LIST_FOR_EACH_SAFE(ITER, NEXT, MEMBER, LIST)               \
    for (ASSIGN_CONTAINER(ITER, (LIST)->next, MEMBER);             \
         (&(ITER)->MEMBER != (LIST)                                \
          ? ASSIGN_CONTAINER(NEXT, (ITER)->MEMBER.next, MEMBER), 1 \
          : 0);                                                    \
         (ITER) = (NEXT))

#endif /* list.h */
