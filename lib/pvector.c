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

#include <config.h>
#include "pvector.h"

/* Writers will preallocate space for some entries at the end to avoid future
 * reallocations. */
enum { PVECTOR_EXTRA_ALLOC = 4 };

struct pvector *
pvector_alloc(size_t size)
{
    struct pvector *pvec;

    pvec = xmalloc(sizeof *pvec + size * sizeof pvec->vector[0]);
    pvec->size = 0;
    pvec->allocated = size;

    return pvec;
}

static struct pvector *
pvector_dup(const struct pvector *old)
{
    struct pvector *pvec = pvector_alloc(old->size + PVECTOR_EXTRA_ALLOC);

    pvec->size = old->size;
    memcpy(pvec->vector, old->vector, old->size * sizeof old->vector[0]);
    return pvec;
}

/* Iterator for callers that need the 'index' afterward. */
#define PVECTOR_FOR_EACH_ENTRY(ENTRY, INDEX, IMPL)         \
    for ((INDEX) = 0;                                      \
         (INDEX) < (IMPL)->size                            \
             && ((ENTRY) = &(IMPL)->vector[INDEX], true);  \
         (INDEX)++)

static int
pvector_entry_cmp(const void *a_, const void *b_)
{
    const struct pvector_entry *ap = a_;
    const struct pvector_entry *bp = b_;
    int a = ap->priority;
    int b = bp->priority;

    return a > b ? -1 : a < b;
}

void
pvector_sort(struct pvector *pvec)
{
    qsort(pvec->vector, pvec->size, sizeof *pvec->vector, pvector_entry_cmp);
}

/* Returns the index of the 'ptr' in the vector, or -1 if none is found. */
static int
pvector_find(const struct pvector *pvec, void *target)
{
    const struct pvector_entry *entry;
    int index;

    PVECTOR_FOR_EACH_ENTRY (entry, index, pvec) {
        if (entry->ptr == target) {
            return index;
        }
    }
    return -1;
}

/* May re-allocate 'impl' */
void
pvector_push_back(struct pvector **pvecp, void *ptr, int priority)
{
    struct pvector *pvec = *pvecp;

    if (pvec->size == pvec->allocated) {
        pvec = pvector_dup(pvec);
        free(*pvecp);
        *pvecp = pvec;
    }
    /* Insert at the end, will be sorted later. */
    pvec->vector[pvec->size].ptr = ptr;
    pvec->vector[pvec->size].priority = priority;
    pvec->size++;
}

void
pvector_remove(struct pvector *pvec, void *ptr)
{
    int index;

    index = pvector_find(pvec, ptr);
    ovs_assert(index >= 0);
    /* Now at the index of the entry to be deleted.
     * Swap another entry in if needed, can be sorted later. */
    pvec->size--;
    if (index != pvec->size) {
        pvec->vector[index] = pvec->vector[pvec->size];
    }
}


/* Concurrent version. */

/* Initializes 'cpvec' as an empty concurrent priority vector. */
void
cpvector_init(struct cpvector *cpvec)
{
    ovsrcu_set(&cpvec->impl, pvector_alloc(PVECTOR_EXTRA_ALLOC));
    cpvec->temp = NULL;
}

/* Destroys 'cpvec'.
 *
 * The client is responsible for destroying any data previously held in
 * 'pvec'. */
void
cpvector_destroy(struct cpvector *cpvec)
{
    free(cpvec->temp);
    cpvec->temp = NULL;
    ovsrcu_postpone(free, cpvector_get_pvector(cpvec));
    ovsrcu_set(&cpvec->impl, NULL); /* Poison. */
}

void
cpvector_insert(struct cpvector *cpvec, void *ptr, int priority)
{
    struct pvector *temp = cpvec->temp;
    struct pvector *old = cpvector_get_pvector(cpvec);

    ovs_assert(ptr != NULL);

    /* Check if can add to the end without reallocation. */
    if (!temp && old->allocated > old->size &&
        (!old->size || priority <= old->vector[old->size - 1].priority)) {
        old->vector[old->size].ptr = ptr;
        old->vector[old->size].priority = priority;
        /* Size increment must not be visible to the readers before the new
         * entry is stored. */
        atomic_thread_fence(memory_order_release);
        ++old->size;
    } else {
        if (!temp) {
            cpvec->temp = pvector_dup(old);
        }
        pvector_push_back(&cpvec->temp, ptr, priority);
    }
}

void
cpvector_remove(struct cpvector *cpvec, void *ptr)
{
    struct pvector *temp = cpvec->temp;

    if (!temp) {
        temp = pvector_dup(cpvector_get_pvector(cpvec));
        cpvec->temp = temp;
    }
    ovs_assert(temp->size > 0);
    pvector_remove(temp, ptr);   /* Publish will sort. */
}

/* Change entry's 'priority' and keep the vector ordered. */
void
cpvector_change_priority(struct cpvector *cpvec, void *ptr, int priority)
{
    struct pvector *old = cpvec->temp;
    int index;

    if (!old) {
        old = cpvector_get_pvector(cpvec);
    }

    index = pvector_find(old, ptr);

    ovs_assert(index >= 0);
    /* Now at the index of the entry to be updated. */

    /* Check if can not update in place. */
    if ((priority > old->vector[index].priority && index > 0
         && priority > old->vector[index - 1].priority)
        || (priority < old->vector[index].priority && index < old->size - 1
            && priority < old->vector[index + 1].priority)) {
        /* Have to use a temp. */
        if (!cpvec->temp) {
            /* Have to reallocate to reorder. */
            cpvec->temp = pvector_dup(old);
            old = cpvec->temp;
            /* Publish will sort. */
        }
    }
    old->vector[index].priority = priority;
}

/* Make the modified pvector available for iteration. */
void cpvector_publish__(struct cpvector *cpvec)
{
    struct pvector *temp = cpvec->temp;

    cpvec->temp = NULL;
    pvector_sort(temp); /* Also removes gaps. */
    ovsrcu_postpone(free, ovsrcu_get_protected(struct pvector *,
                                               &cpvec->impl));
    ovsrcu_set(&cpvec->impl, temp);
}
