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

#define LIST_ELEM__(ELEM, STRUCT, MEMBER, LIST)                 \
        (ELEM != LIST ? CONTAINER_OF(ELEM, STRUCT, MEMBER) : NULL)
#define LIST_FOR_EACH(ITER, STRUCT, MEMBER, LIST)                   \
    for (ITER = LIST_ELEM__((LIST)->next, STRUCT, MEMBER, LIST);    \
         ITER != NULL;                                              \
         ITER = LIST_ELEM__((ITER)->MEMBER.next, STRUCT, MEMBER, LIST))
#define LIST_FOR_EACH_SAFE(ITER, NEXT, STRUCT, MEMBER, LIST)            \
    for (ITER = LIST_ELEM__((LIST)->next, STRUCT, MEMBER, LIST);        \
         (ITER != NULL                                                  \
          ? (NEXT = LIST_ELEM__((ITER)->MEMBER.next, STRUCT, MEMBER, LIST), 1) \
          : 0),                                                         \
         ITER = NEXT)

#endif /* list.h */
