/*
 * Copyright (c) 2014, 2016 Nicira, Inc.
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

#ifndef PVECTOR_H
#define PVECTOR_H 1

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "ovs-rcu.h"
#include "util.h"

/* Concurrent Priority Vector
 * ==========================
 *
 * Concurrent priority vector holds non-NULL pointers to objects in an
 * increasing priority order and allows readers to traverse the vector without
 * being concerned about writers modifying the vector as they are traversing
 * it.
 *
 * The priority order is maintained as a linear vector of elements to allow
 * for efficient memory prefetching.
 *
 * Concurrency is implemented with OVS RCU so that the readers can assume
 * that once they have taken a pointer to the vector with
 * pvector_cursor_init(), the 'size' member will not decrease, so that
 * they can safely read 'size' entries from 'vector', and find that each
 * entry has a valid, non-NULL 'ptr', and the vector is in order from highest
 * to lowest 'priority'.  The 'priority' values can change any time, but only
 * so that the order of the entries does not change, so readers can use
 * 'priority' values read at any time after acquisition of the vector pointer.
 *
 * Writers can concurrently add entries to the end of the vector, incrementing
 * 'size', or update the 'priority' value of an entry, but only if that does
 * not change the ordering of the entries.  Writers will never change the 'ptr'
 * values, or decrement the 'size' on a copy that readers have access to.
 *
 * Most modifications are internally staged at the 'temp' vector, from which
 * they can be published at 'impl' by calling cpvector_publish().  This saves
 * unnecessary memory allocations when many changes are done back-to-back.
 * 'temp' may contain NULL pointers and it may be in unsorted order.  It is
 * sorted before it is published at 'impl', which also removes the NULLs from
 * the published vector.
 */

struct pvector_entry {
    int priority;
    void *ptr;
};

/* Non-concurrent priority vector. */
struct pvector {
    size_t size;       /* Number of entries in the vector. */
    size_t allocated;  /* Number of allocated entries. */
    struct pvector_entry vector[];
};

struct pvector *pvector_alloc(size_t);
void pvector_push_back(struct pvector **, void *ptr, int priority);
void pvector_remove(struct pvector *, void *ptr);
void pvector_sort(struct pvector *);

/* Iteration.
 *
 *
 * Thread-safety
 * =============
 *
 * These iterators operate on the non-concurrent pvector, and are not thread
 * safe.  Any entry may be skipped if entires are removed (with
 * pvector_remove()) during iteration.
 *
 * Example
 * =======
 *
 *     struct my_node {
 *         int data;
 *     };
 *
 *     struct my_node elem1, elem2, *iter;
 *     struct pvector *my_pvector;
 *
 *     my_pvector = pvector_alloc(0);
 *     ...add data...
 *     pvector_push_back(&my_pvector, &elem1, 1);
 *     pvector_push_back(&my_pvector, &elem2, 2);
 *     ...sort...
 *     pvector_sort(my_pvector);
 *     ...
 *     PVECTOR_FOR_EACH (iter, &my_cpvector) {
 *         ...operate on '*iter'...
 *         ...elem2 to be seen before elem1...
 *     }
 *     ...remove entries...
 *     pvector_remove(my_pvector, &elem1);
 *     ...
 *     free(my_pvector);
 *
 * Currently there is no PVECTOR_FOR_EACH_SAFE variant.
 *
 * The PVECTOR_FOR_EACH_PRIORITY limits the iteration to entries with higher
 * than or equal to the given priority and allows for object lookahead.
 */
struct pvector_cursor {
    size_t size;        /* Number of entries in the vector. */
    size_t entry_idx;   /* Current index. */
    const struct pvector_entry *vector;
};

static inline struct pvector_cursor pvector_cursor_init(const struct pvector *,
                                                        size_t n_ahead,
                                                        size_t obj_size);
static inline void *pvector_cursor_next(struct pvector_cursor *,
                                        int stop_at_priority,
                                        size_t n_ahead, size_t obj_size);
static inline void pvector_cursor_lookahead(const struct pvector_cursor *,
                                            int n, size_t size);

#define PVECTOR_FOR_EACH(PTR, PVECTOR)                                  \
    for (struct pvector_cursor cursor__ = pvector_cursor_init(PVECTOR, 0, 0); \
         ((PTR) = pvector_cursor_next(&cursor__, INT_MIN, 0, 0)) != NULL; )

/* Loop while priority is higher than or equal to 'PRIORITY' and prefetch
 * objects of size 'SZ' 'N' objects ahead from the current object. */
#define PVECTOR_FOR_EACH_PRIORITY(PTR, PRIORITY, N, SZ, PVECTOR)        \
    for (struct pvector_cursor cursor__ = pvector_cursor_init(PVECTOR, N, SZ); \
         ((PTR) = pvector_cursor_next(&cursor__, PRIORITY, N, SZ)) != NULL; )

#define PVECTOR_CURSOR_FOR_EACH(PTR, CURSOR, PVECTOR)                   \
    for (*(CURSOR) = pvector_cursor_init(PVECTOR, 0, 0);                \
         ((PTR) = pvector_cursor_next(CURSOR, INT_MIN, 0, 0)) != NULL; )

#define PVECTOR_CURSOR_FOR_EACH_CONTINUE(PTR, CURSOR)                   \
    for (; ((PTR) = pvector_cursor_next(CURSOR, INT_MIN, 0, 0)) != NULL; )


/* Concurrent priority vector. */
struct cpvector {
    OVSRCU_TYPE(struct pvector *) impl;
    struct pvector *temp;
};

/* Initialization. */
void cpvector_init(struct cpvector *);
void cpvector_destroy(struct cpvector *);

/* Insertion and deletion.  These work on 'temp'.  */
void cpvector_insert(struct cpvector *, void *, int priority);
void cpvector_change_priority(struct cpvector *, void *, int priority);
void cpvector_remove(struct cpvector *, void *);

/* Make the modified cpvector available for iteration. */
static inline void cpvector_publish(struct cpvector *);

/* Count.  These operate on the published cpvector. */
static inline size_t cpvector_count(const struct cpvector *);
static inline bool cpvector_is_empty(const struct cpvector *);

static inline struct pvector *cpvector_get_pvector(const struct cpvector *);

/* Iteration.
 *
 *
 * Thread-safety
 * =============
 *
 * Iteration is safe even in a cpvector that is changing concurrently.
 * Multiple writers must exclude each other via e.g., a mutex.
 *
 * Example
 * =======
 *
 *     struct my_node {
 *         int data;
 *     };
 *
 *     struct my_node elem1, elem2, *iter;
 *     struct cpvector my_cpvector;
 *
 *     cpvector_init(&my_cpvector);
 *     ...add data...
 *     cpvector_insert(&my_cpvector, &elem1, 1);
 *     cpvector_insert(&my_cpvector, &elem2, 2);
 *     ...
 *     CPVECTOR_FOR_EACH (iter, &my_cpvector) {
 *         ...operate on '*iter'...
 *         ...elem2 to be seen before elem1...
 *     }
 *     ...
 *     cpvector_destroy(&my_cpvector);
 *
 * There is no CPVECTOR_FOR_EACH_SAFE variant as iteration is performed on RCU
 * protected instance of the priority vector.  Any concurrent modifications
 * that would be disruptive for readers (such as deletions), will be performed
 * on a new instance.  To see any of the modifications, a new iteration loop
 * has to be started.
 *
 * The CPVECTOR_FOR_EACH_PRIORITY limits the iteration to entries with higher
 * than or equal to the given priority and allows for object lookahead.
 *
 * The iteration loop must be completed without entering the OVS RCU quiescent
 * period.  That is, an old iteration loop must not be continued after any
 * blocking IO (VLOG is non-blocking, so that is OK).
 */

#define CPVECTOR_FOR_EACH(PTR, CPVECTOR)                \
    PVECTOR_FOR_EACH(PTR, cpvector_get_pvector(CPVECTOR))

#define CPVECTOR_FOR_EACH_PRIORITY(PTR, PRIORITY, N, SZ, CPVECTOR)      \
    PVECTOR_FOR_EACH_PRIORITY(PTR, PRIORITY, N, SZ,                     \
                              cpvector_get_pvector(CPVECTOR))

#define CPVECTOR_CURSOR_FOR_EACH(PTR, CURSOR, CPVECTOR)                 \
    PVECTOR_CURSOR_FOR_EACH(PTR, CURSOR, cpvector_get_pvector(CPVECTOR))

#define CPVECTOR_CURSOR_FOR_EACH_CONTINUE(PTR, CURSOR)  \
    PVECTOR_CURSOR_FOR_EACH_CONTINUE(PTR, CURSOR)


/* Inline implementations. */

static inline struct pvector_cursor
pvector_cursor_init(const struct pvector *pvec, size_t n_ahead,
                    size_t obj_size)
{
    struct pvector_cursor cursor;

    ovs_prefetch_range(pvec->vector, pvec->size * sizeof pvec->vector[0]);

    cursor.size = pvec->size;
    cursor.vector = pvec->vector;
    cursor.entry_idx = -1;

    for (size_t i = 0; i < n_ahead; i++) {
        /* Prefetch the first objects. */
        pvector_cursor_lookahead(&cursor, i, obj_size);
    }
    return cursor;
}

static inline void *pvector_cursor_next(struct pvector_cursor *cursor,
                                        int lowest_priority,
                                        size_t n_ahead, size_t obj_size)
{
    if (++cursor->entry_idx < cursor->size &&
        cursor->vector[cursor->entry_idx].priority >= lowest_priority) {
        if (n_ahead) {
            pvector_cursor_lookahead(cursor, n_ahead, obj_size);
        }
        return cursor->vector[cursor->entry_idx].ptr;
    }
    return NULL;
}

static inline void pvector_cursor_lookahead(const struct pvector_cursor *cursor,
                                            int n, size_t size)
{
    if (cursor->entry_idx + n < cursor->size) {
        ovs_prefetch_range(cursor->vector[cursor->entry_idx + n].ptr, size);
    }
}

static inline struct pvector *
cpvector_get_pvector(const struct cpvector *cpvec)
{
    return ovsrcu_get(struct pvector *, &cpvec->impl);
}

static inline size_t cpvector_count(const struct cpvector *cpvec)
{
    return cpvector_get_pvector(cpvec)->size;
}

static inline bool cpvector_is_empty(const struct cpvector *cpvec)
{
    return cpvector_count(cpvec) == 0;
}

void cpvector_publish__(struct cpvector *);

/* Make the modified cpvector available for iteration. */
static inline void cpvector_publish(struct cpvector *cpvec)
{
    if (cpvec->temp) {
        cpvector_publish__(cpvec);
    }
}

#endif /* pvector.h */
