/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013, 2014 Nicira, Inc.
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
#ifndef RCULIST_H
#define RCULIST_H 1

/* A single writer multiple RCU-reader doubly linked list.
 *
 * RCU readers may iterate over the list at the same time as a writer is
 * modifying the list.  Multiple writers can be supported by use of mutual
 * exclusion, but rculist does not provide that, as the user of rculist
 * typically does that already.
 *
 * To be RCU-friendly, the struct rculist instances must be freed via
 * ovsrcu_postpone().
 *
 * The API is almost the same as for struct ovs_list, with the following
 * exeptions:
 *
 * - The 'prev' pointer may not be accessed by the user.
 * - The 'next' pointer should be accessed via rculist_next() by readers, and
 *   rculist_next_protected() by the writer.
 * - No rculist_moved(): due to the memory management limitation stated above,
 *   rculist instances may not be reallocated, as realloc may instantly free
 *   the old memory.
 * - rculist_front() returns a const pointer to accommodate for an RCU reader.
 * - rculist_splice_hidden(): Spliced elements may not have been visible to
 *   RCU readers before the operation.
 * - rculist_poison(): Only poisons the 'prev' pointer.
 *
 * The following functions are variations of the struct ovs_list functions with
 * similar names, but are now restricted to the writer use:
 *
 * - rculist_back_protected()
 * - rculist_is_short_protected()
 * - rculist_is_singleton_protected()
 */

#include <stdbool.h>
#include <stddef.h>
#include "ovs-rcu.h"
#include "util.h"

/* A non-existing mutex to make it more difficult for an user to accidentally
 * keep using the 'prev' pointer.  This may be helpful when porting code from
 * struct ovs_list to rculist. */
extern struct ovs_mutex rculist_fake_mutex;

/* Doubly linked list head or element. */
struct rculist {
    /* Previous list element. */
    struct rculist *prev OVS_GUARDED_BY(rculist_fake_mutex);

    /* Next list element. */
    OVSRCU_TYPE(struct rculist *) next;
};

/* Easier access to 'next' member. */
static inline const struct rculist *rculist_next(const struct rculist *);
static inline struct rculist *rculist_next_protected(const struct rculist *);

/* List initialization. */
#define RCUOVS_LIST_INITIALIZER(LIST) { LIST, OVSRCU_INITIALIZER(LIST) }

static inline void rculist_init(struct rculist *list);
static inline void rculist_poison(struct rculist *elem);

/* List insertion. */
static inline void rculist_insert(struct rculist *list, struct rculist *elem);
static inline void rculist_splice_hidden(struct rculist *before,
                                         struct rculist *first,
                                         struct rculist *last);
static inline void rculist_push_front(struct rculist *list,
                                      struct rculist *elem);
static inline void rculist_push_back(struct rculist *list,
                                     struct rculist *elem);
static inline void rculist_replace(struct rculist *replacement,
                                   struct rculist *replaced);
static inline void rculist_move(struct rculist *dst, struct rculist *src);

/* List removal. */
static inline struct rculist *rculist_remove(struct rculist *elem);
static inline struct rculist *rculist_pop_front(struct rculist *list);
static inline struct rculist *rculist_pop_back(struct rculist *list);

/* List elements. */
static inline const struct rculist *rculist_front(const struct rculist *);
static inline struct rculist *rculist_back_protected(const struct rculist *);

/* List properties. */
static inline size_t rculist_size(const struct rculist *);
static inline bool rculist_is_empty(const struct rculist *);
static inline bool rculist_is_singleton_protected(const struct rculist *);
static inline bool rculist_is_short_protected(const struct rculist *);


/* Inline implementations. */

static inline const struct rculist *
rculist_next(const struct rculist *list)
{
    return ovsrcu_get(struct rculist *, &list->next);
}

static inline struct rculist *
rculist_next_protected(const struct rculist *list)

{
    return ovsrcu_get_protected(struct rculist *, &list->next);
}

static inline void
rculist_init(struct rculist *list)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    list->prev = list;
    ovsrcu_init(&list->next, list);
}

#define RCULIST_POISON (struct rculist *)(UINTPTR_MAX / 0xf * 0xc)

/* Initializes 'list' with pointers that will (probably) cause segfaults if
 * dereferenced and, better yet, show up clearly in a debugger. */
static inline void
rculist_poison(struct rculist *list)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    list->prev = RCULIST_POISON;
}

/* Initializes 'list' with pointers that will (probably) cause segfaults if
 * dereferenced and, better yet, show up clearly in a debugger.
 *
 * This variant poisons also the next pointer, so this may not be called if
 * this list element is still visible to RCU readers. */
static inline void
rculist_poison__(struct rculist *list)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    rculist_poison(list);
    ovsrcu_set_hidden(&list->next, RCULIST_POISON);
}

/* rculist insertion. */
static inline void
rculist_insert(struct rculist *before, struct rculist *elem)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    elem->prev = before->prev;
    ovsrcu_set_hidden(&elem->next, before);
    ovsrcu_set(&before->prev->next, elem);
    before->prev = elem;
}

/* Removes elements 'first' though 'last' (exclusive) from their current list,
 * which may NOT be visible to any other threads (== be hidden from them),
 * then inserts them just before 'before'. */
static inline void
rculist_splice_hidden(struct rculist *before, struct rculist *first,
                      struct rculist *last)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rculist *last_next;

    if (first == last) {
        return;
    }
    last = last->prev;

    /* Cleanly remove 'first'...'last' from its current list. */
    last_next = rculist_next_protected(last);
    last_next->prev = first->prev;
    ovsrcu_set_hidden(&first->prev->next, last_next);

    /* Splice 'first'...'last' into new list. */
    first->prev = before->prev;
    ovsrcu_set(&last->next, before);
    ovsrcu_set(&before->prev->next, first);
    before->prev = last;
}

/* Inserts 'elem' at the beginning of 'list', so that it becomes the front in
 * 'list'. */
static inline void
rculist_push_front(struct rculist *list, struct rculist *elem)
{
    rculist_insert(rculist_next_protected(list), elem);
}

/* Inserts 'elem' at the end of 'list', so that it becomes the back in
 * 'list'. */
static inline void
rculist_push_back(struct rculist *list, struct rculist *elem)
{
    rculist_insert(list, elem);
}

/* Puts 'element' in the position currently occupied by 'position'.
 *
 * Afterward, 'position' is not linked to from the list any more, but still
 * links to the nodes in the list, and may still be referenced by other threads
 * until all other threads quiesce.  The replaced node ('position') may not be
 * re-inserted, re-initialized, or deleted until after all other threads have
 * quiesced (use ovsrcu_postpone). */
static inline void
rculist_replace(struct rculist *element, struct rculist *position)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rculist *position_next = rculist_next_protected(position);

    ovsrcu_set_hidden(&element->next, position_next);
    position_next->prev = element;
    element->prev = position->prev;
    ovsrcu_set(&element->prev->next, element);
    rculist_poison(position);
}

/* Initializes 'dst' with the contents of 'src', compensating for moving it
 * around in memory.  The effect is that, if 'src' was the head of a list, now
 * 'dst' is the head of a list containing the same elements.
 *
 * Memory for 'src' must be kept around until the next RCU quiescent period.
 * rculist cannot be simply reallocated, so there is no rculist_moved(). */
static inline void
rculist_move(struct rculist *dst, struct rculist *src)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    if (!rculist_is_empty(src)) {
        struct rculist *src_next = rculist_next_protected(src);

        dst->prev = src->prev;
        ovsrcu_set_hidden(&dst->next, src_next);

        src_next->prev = dst;
        ovsrcu_set(&src->prev->next, dst);
    } else {
        rculist_init(dst);
    }
    rculist_poison(src);
}

/* Removes 'elem' from its list and returns the element that followed it.
 * Has no effect when 'elem' is initialized, but not in a list.
 * Undefined behavior if 'elem' is not initialized.
 *
 * Afterward, 'elem' is not linked to from the list any more, but still links
 * to the nodes in the list, and may still be referenced by other threads until
 * all other threads quiesce.  The removed node ('elem') may not be
 * re-inserted, re-initialized, or deleted until after all other threads have
 * quiesced (use ovsrcu_postpone).
 */
static inline struct rculist *
rculist_remove(struct rculist *elem)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rculist *elem_next = rculist_next_protected(elem);

    elem_next->prev = elem->prev;
    ovsrcu_set(&elem->prev->next, elem_next);
    rculist_poison(elem);
    return elem_next;
}

/* Removes the front element from 'list' and returns it.  Undefined behavior if
 * 'list' is empty before removal.
 *
 * Afterward, teh returned former first node is not linked to from the list any
 * more, but still links to the nodes in the list, and may still be referenced
 * by other threads until all other threads quiesce.  The returned node may not
 * be re-inserted, re-initialized, or deleted until after all other threads
 * have quiesced (use ovsrcu_postpone). */
static inline struct rculist *
rculist_pop_front(struct rculist *list)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rculist *front = rculist_next_protected(list);
    rculist_remove(front);
    return front;
}

/* Removes the back element from 'list' and returns it.
 * Undefined behavior if 'list' is empty before removal.
 *
 * Afterward, teh returned former last node is not linked to from the list any
 * more, but still links to the nodes in the list, and may still be referenced
 * by other threads until all other threads quiesce.  The returned node may not
 * be re-inserted, re-initialized, or deleted until after all other threads
 * have quiesced (use ovsrcu_postpone). */
static inline struct rculist *
rculist_pop_back(struct rculist *list)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rculist *back = list->prev;
    rculist_remove(back);
    return back;
}

/* Returns the front element in 'list_'.
 * Undefined behavior if 'list_' is empty. */
static inline const struct rculist *
rculist_front(const struct rculist *list)
{
    ovs_assert(!rculist_is_empty(list));

    return rculist_next(list);
}

/* Returns the back element in 'list_'.
 * Returns the 'list_' itself, if 'list_' is empty. */
static inline struct rculist *
rculist_back_protected(const struct rculist *list)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    return CONST_CAST(struct rculist *, list)->prev;
}

/* Returns the number of elements in 'list'.
 * Runs in O(n) in the number of elements. */
static inline size_t
rculist_size(const struct rculist *list)
{
    const struct rculist *e;
    size_t cnt = 0;

    for (e = rculist_next(list); e != list; e = rculist_next(e)) {
        cnt++;
    }
    return cnt;
}

/* Returns true if 'list' is empty, false otherwise. */
static inline bool
rculist_is_empty(const struct rculist *list)
{
    return rculist_next(list) == list;
}

/* Returns true if 'list' has 0 or 1 elements, false otherwise. */
static inline bool
rculist_is_short_protected(const struct rculist *list)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    return rculist_next_protected(list) == list->prev;
}

/* Returns true if 'list' has exactly 1 element, false otherwise. */
static inline bool
rculist_is_singleton_protected(const struct rculist *list)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    const struct rculist *list_next = rculist_next_protected(list);

    return list_next == list->prev && list_next != list;
}

#define RCULIST_FOR_EACH(ITER, MEMBER, RCULIST)                         \
    for (INIT_CONTAINER(ITER, rculist_next(RCULIST), MEMBER);           \
         &(ITER)->MEMBER != (RCULIST);                                  \
         ASSIGN_CONTAINER(ITER, rculist_next(&(ITER)->MEMBER), MEMBER))
#define RCULIST_FOR_EACH_CONTINUE(ITER, MEMBER, RCULIST)                \
    for (ASSIGN_CONTAINER(ITER, rculist_next(&(ITER)->MEMBER), MEMBER); \
         &(ITER)->MEMBER != (RCULIST);                                  \
         ASSIGN_CONTAINER(ITER, rculist_next(&(ITER)->MEMBER), MEMBER))

#define RCULIST_FOR_EACH_REVERSE_PROTECTED(ITER, MEMBER, RCULIST)       \
    for (INIT_CONTAINER(ITER, (RCULIST)->prev, MEMBER);                 \
         &(ITER)->MEMBER != (RCULIST);                                  \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER))
#define RCULIST_FOR_EACH_REVERSE_PROTECTED_CONTINUE(ITER, MEMBER, RCULIST) \
    for (ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER);           \
         &(ITER)->MEMBER != (RCULIST);                                  \
         ASSIGN_CONTAINER(ITER, (ITER)->MEMBER.prev, MEMBER))

#define RCULIST_FOR_EACH_PROTECTED(ITER, MEMBER, RCULIST)               \
    for (INIT_CONTAINER(ITER, rculist_next_protected(RCULIST), MEMBER); \
         &(ITER)->MEMBER != (RCULIST);                                  \
         ASSIGN_CONTAINER(ITER, rculist_next_protected(&(ITER)->MEMBER), \
                          MEMBER))

#define RCULIST_FOR_EACH_SAFE_PROTECTED(ITER, NEXT, MEMBER, RCULIST)    \
    for (INIT_CONTAINER(ITER, rculist_next_protected(RCULIST), MEMBER); \
         (&(ITER)->MEMBER != (RCULIST)                                  \
          ? INIT_CONTAINER(NEXT, rculist_next_protected(&(ITER)->MEMBER), \
                           MEMBER), 1 : 0);                             \
         (ITER) = (NEXT))

#endif /* rculist.h */
