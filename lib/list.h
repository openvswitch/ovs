/*
 * Copyright (c) 2008, 2009 Nicira Networks.
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
#ifndef LIST_H
#define LIST_H 1

/* Doubly linked list. */

#include <stdbool.h>
#include <stddef.h>
#include "util.h"

/* Doubly linked list head or element. */
struct list
  {
    struct list *prev;     /* Previous list element. */
    struct list *next;     /* Next list element. */
  };

#define LIST_INITIALIZER(LIST) { LIST, LIST }

void list_init(struct list *);

/* List insertion. */
void list_insert(struct list *, struct list *);
void list_splice(struct list *before, struct list *first, struct list *last);
void list_push_front(struct list *, struct list *);
void list_push_back(struct list *, struct list *);
void list_replace(struct list *, const struct list *);
void list_moved(struct list *);

/* List removal. */
struct list *list_remove(struct list *);
struct list *list_pop_front(struct list *);
struct list *list_pop_back(struct list *);

/* List elements. */
struct list *list_front(struct list *);
struct list *list_back(struct list *);

/* List properties. */
size_t list_size(const struct list *);
bool list_is_empty(const struct list *);

#define LIST_FOR_EACH(ITER, STRUCT, MEMBER, LIST)                   \
    for (ITER = CONTAINER_OF((LIST)->next, STRUCT, MEMBER);         \
         &(ITER)->MEMBER != (LIST);                                 \
         ITER = CONTAINER_OF((ITER)->MEMBER.next, STRUCT, MEMBER))
#define LIST_FOR_EACH_REVERSE(ITER, STRUCT, MEMBER, LIST)           \
    for (ITER = CONTAINER_OF((LIST)->prev, STRUCT, MEMBER);         \
         &(ITER)->MEMBER != (LIST);                                 \
         ITER = CONTAINER_OF((ITER)->MEMBER.prev, STRUCT, MEMBER))
#define LIST_FOR_EACH_SAFE(ITER, NEXT, STRUCT, MEMBER, LIST)        \
    for (ITER = CONTAINER_OF((LIST)->next, STRUCT, MEMBER);         \
         (NEXT = CONTAINER_OF((ITER)->MEMBER.next, STRUCT, MEMBER), \
          &(ITER)->MEMBER != (LIST));                               \
         ITER = NEXT)

#endif /* list.h */
