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

#include <config.h>
#include "pvector.h"

static struct pvector_impl *
pvector_impl_get(const struct pvector *pvec)
{
    return ovsrcu_get(struct pvector_impl *, &pvec->impl);
}

static struct pvector_impl *
pvector_impl_alloc(size_t size)
{
    struct pvector_impl *impl;

    impl = xmalloc(sizeof *impl + size * sizeof impl->vector[0]);
    impl->size = 0;
    impl->allocated = size;

    return impl;
}

static struct pvector_impl *
pvector_impl_dup(struct pvector_impl *old)
{
    return xmemdup(old, sizeof *old + old->allocated * sizeof old->vector[0]);
}

/* Initializes 'pvec' as an empty concurrent priority vector. */
void
pvector_init(struct pvector *pvec)
{
    ovsrcu_set(&pvec->impl, pvector_impl_alloc(PVECTOR_EXTRA_ALLOC));
}

/* Destroys 'pvec'.
 *
 * The client is responsible for destroying any data previously held in
 * 'pvec'. */
void
pvector_destroy(struct pvector *pvec)
{
    ovsrcu_postpone(free, pvector_impl_get(pvec));
    ovsrcu_set(&pvec->impl, NULL); /* Poison. */
}

/* Iterators for callers that need the 'index' afterward. */
#define PVECTOR_IMPL_FOR_EACH(ENTRY, INDEX, IMPL)          \
    for ((INDEX) = 0;                                      \
         (INDEX) < (IMPL)->size                            \
             && ((ENTRY) = &(IMPL)->vector[INDEX], true);  \
         (INDEX)++)

static int
pvector_entry_cmp(const void *a_, const void *b_)
{
    unsigned int a = ((const struct pvector_entry *)a_)->priority;
    unsigned int b = ((const struct pvector_entry *)b_)->priority;

    return a > b ? -1 : a < b;
}

static void
pvector_impl_sort(struct pvector_impl *impl)
{
    qsort(impl->vector, impl->size, sizeof *impl->vector, pvector_entry_cmp);
}

/* Returns the index with priority equal or lower than 'target_priority',
 * which will be one past the vector if none exists. */
static int
pvector_impl_find_priority(struct pvector_impl *impl,
                           unsigned int target_priority)
{
    const struct pvector_entry *entry;
    int index;

    PVECTOR_IMPL_FOR_EACH (entry, index, impl) {
        if (entry->priority <= target_priority) {
            break;
        }
    }
    return index;
}

/* Returns the index of the 'ptr' in the vector, or -1 if none is found. */
static int
pvector_impl_find(struct pvector_impl *impl, void *target)
{
    const struct pvector_entry *entry;
    int index;

    PVECTOR_IMPL_FOR_EACH (entry, index, impl) {
        if (entry->ptr == target) {
            return index;
        }
    }
    return -1;
}

void
pvector_insert(struct pvector *pvec, void *ptr, unsigned int priority)
{
    struct pvector_impl *old, *new;
    int index;

    ovs_assert(ptr != NULL);

    old = pvector_impl_get(pvec);

    /* Check if can add to the end without reallocation. */
    if (old->allocated > old->size &&
        (!old->size || priority <= old->vector[old->size - 1].priority)) {
        old->vector[old->size].ptr = ptr;
        old->vector[old->size].priority = priority;
        /* Size increment must not be visible to the readers before the new
         * entry is stored. */
        atomic_thread_fence(memory_order_release);
        ++old->size;
    } else {
        new = pvector_impl_alloc(old->size + 1 + PVECTOR_EXTRA_ALLOC);

        index = pvector_impl_find_priority(old, priority);
        /* Now at the insertion index. */
        memcpy(new->vector, old->vector, index * sizeof old->vector[0]);
        new->vector[index].ptr = ptr;
        new->vector[index].priority = priority;
        memcpy(&new->vector[index + 1], &old->vector[index],
               (old->size - index) * sizeof old->vector[0]);
        new->size = old->size + 1;

        ovsrcu_set(&pvec->impl, new);
        ovsrcu_postpone(free, old);
    }
}

void
pvector_remove(struct pvector *pvec, void *ptr)
{
    struct pvector_impl *old, *new;
    int index;

    old = pvector_impl_get(pvec);

    ovs_assert(old->size > 0);

    index = pvector_impl_find(old, ptr);
    ovs_assert(index >= 0);
    /* Now at the index of the entry to be deleted. */

    /* We do not try to delete the last entry without reallocation so that
     * the readers can read the 'size' once in the beginning of each iteration.
     */

    /* Keep extra space for insertions to the end. */
    new = pvector_impl_alloc(old->size - 1 + PVECTOR_EXTRA_ALLOC);

    memcpy(new->vector, old->vector, index * sizeof old->vector[0]);
    memcpy(&new->vector[index], &old->vector[index + 1],
           (old->size - (index + 1)) * sizeof old->vector[0]);

    new->size = old->size - 1;

    ovsrcu_set(&pvec->impl, new);
    ovsrcu_postpone(free, old);
}

/* Change entry's 'priority' and keep the vector ordered. */
void
pvector_change_priority(struct pvector *pvec, void *ptr, unsigned int priority)
{
    struct pvector_impl *old = pvector_impl_get(pvec);
    int index = pvector_impl_find(old, ptr);

    ovs_assert(index >= 0);
    /* Now at the index of the entry to be updated. */

    if ((priority > old->vector[index].priority && index > 0
         && priority > old->vector[index - 1].priority)
        || (priority < old->vector[index].priority && index < old->size - 1
            && priority < old->vector[index + 1].priority)) {
        /* Have to reallocate to reorder. */
        struct pvector_impl *new = pvector_impl_dup(old);

        new->vector[index].priority = priority;
        pvector_impl_sort(new);

        ovsrcu_set(&pvec->impl, new);
        ovsrcu_postpone(free, old);
    } else {
        /* Can update in place. Readers are free to use either value,
         * so we do not try to synchronize here. */
        old->vector[index].priority = priority;
    }
}
