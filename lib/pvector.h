/*
 * Copyright (c) 2014 Nicira, Inc.
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
 */

struct pvector_entry {
    unsigned int priority;
    void *ptr;
};

/* Writers will preallocate space for some entries at the end to avoid future
 * reallocations. */
enum { PVECTOR_EXTRA_ALLOC = 4 };

struct pvector_impl {
    size_t size;       /* Number of entries in the vector. */
    size_t allocated;  /* Number of allocated entries. */
    struct pvector_entry vector[];
};

/* Concurrent priority vector. */
struct pvector {
    OVSRCU_TYPE(struct pvector_impl *) impl;
};

/* Initialization. */
void pvector_init(struct pvector *);
void pvector_destroy(struct pvector *);

/* Count. */
static inline size_t pvector_count(const struct pvector *);
static inline bool pvector_is_empty(const struct pvector *);

/* Insertion and deletion. */
void pvector_insert(struct pvector *, void *, unsigned int);
void pvector_change_priority(struct pvector *, void *, unsigned int);
void pvector_remove(struct pvector *, void *);

/* Iteration.
 *
 *
 * Thread-safety
 * =============
 *
 * Iteration is safe even in a pvector that is changing concurrently.
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
 *     struct pvector my_pvector;
 *
 *     pvector_init(&my_pvector);
 *     ...add data...
 *     pvector_insert(&my_pvector, &elem1, 1);
 *     pvector_insert(&my_pvector, &elem2, 2);
 *     ...
 *     PVECTOR_FOR_EACH (iter, &my_pvector) {
 *         ...operate on '*iter'...
 *         ...elem2 to be seen before elem1...
 *     }
 *     ...
 *     pvector_destroy(&my_pvector);
 *
 * There is no PVECTOR_FOR_EACH_SAFE variant as iteration is performed on RCU
 * protected instance of the priority vector.  Any concurrent modifications
 * that would be disruptive for readers (such as deletions), will be performed
 * on a new instance.  To see any of the modifications, a new iteration loop
 * has to be started.
 *
 * The PVECTOR_FOR_EACH_PRIORITY limits the iteration to entries with higher
 * than given priority and allows for object lookahead.
 *
 * The iteration loop must be completed without entering the OVS RCU quiescent
 * period.  That is, an old iteration loop must not be continued after any
 * blocking IO (VLOG is non-blocking, so that is OK).
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
                                        int64_t stop_at_priority,
                                        size_t n_ahead, size_t obj_size);
static inline void pvector_cursor_lookahead(const struct pvector_cursor *,
                                            int n, size_t size);

#define PVECTOR_FOR_EACH(PTR, PVECTOR)                                  \
    for (struct pvector_cursor cursor__ = pvector_cursor_init(PVECTOR, 0, 0); \
         ((PTR) = pvector_cursor_next(&cursor__, -1, 0, 0)) != NULL; )

/* Loop while priority is higher than 'PRIORITY' and prefetch objects
 * of size 'SZ' 'N' objects ahead from the current object. */
#define PVECTOR_FOR_EACH_PRIORITY(PTR, PRIORITY, N, SZ, PVECTOR)        \
    for (struct pvector_cursor cursor__ = pvector_cursor_init(PVECTOR, N, SZ); \
         ((PTR) = pvector_cursor_next(&cursor__, PRIORITY, N, SZ)) != NULL; )


/* Inline implementations. */

static inline struct pvector_cursor
pvector_cursor_init(const struct pvector *pvec,
                    size_t n_ahead, size_t obj_size)
{
    const struct pvector_impl *impl;
    struct pvector_cursor cursor;

    impl = ovsrcu_get(struct pvector_impl *, &pvec->impl);

    ovs_prefetch_range(impl->vector, impl->size * sizeof impl->vector[0]);

    cursor.size = impl->size;
    cursor.vector = impl->vector;
    cursor.entry_idx = -1;

    for (size_t i = 0; i < n_ahead; i++) {
        /* Prefetch the first objects. */
        pvector_cursor_lookahead(&cursor, i, obj_size);
    }
    return cursor;
}

static inline void *pvector_cursor_next(struct pvector_cursor *cursor,
                                        int64_t stop_at_priority,
                                        size_t n_ahead, size_t obj_size)
{
    if (++cursor->entry_idx < cursor->size &&
        cursor->vector[cursor->entry_idx].priority > stop_at_priority) {
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

static inline size_t pvector_count(const struct pvector *pvec)
{
    return ovsrcu_get(struct pvector_impl *, &pvec->impl)->size;
}

static inline bool pvector_is_empty(const struct pvector *pvec)
{
    return pvector_count(pvec) == 0;
}

#endif /* pvector.h */
