/*
 * Copyright (c) 2013, 2014 Nicira, Inc.
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

#include "fat-rwlock.h"

#include <errno.h>

#include "hmap.h"
#include "list.h"
#include "ovs-thread.h"
#include "random.h"

/* This system's cache line size, in bytes.
 * Being wrong hurts performance but not correctness. */
#define CACHE_LINE_SIZE 64      /* Correct for most CPUs. */
BUILD_ASSERT_DECL(IS_POW2(CACHE_LINE_SIZE));

struct fat_rwlock_slot {
    /* Membership in rwlock's list of "struct fat_rwlock_slot"s.
     *
     * fat_rwlock_destroy() sets 'rwlock' to NULL to indicate that this
     * slot may be destroyed. */
    struct list list_node;      /* In struct rwlock's 'threads' list. */
    struct fat_rwlock *rwlock;  /* Owner. */

    /* Mutex.
     *
     * A thread holding the read-lock holds its own mutex.
     *
     * A thread holding the write-lock holds every thread's mutex, plus
     * 'rwlock->mutex'. */
    struct ovs_mutex mutex;

    /* This thread's locking status for 'rwlock':
     *
     *     - 0: This thread does not have any lock on 'rwlock'.  This thread
     *       does not have 'mutex' locked.
     *
     *     - 1: This thread has a read-lock on 'rwlock' and holds 'mutex'.
     *
     *     - 2...UINT_MAX-1: This thread has recursively taken the read-lock on
     *       'rwlock' to the level of 'depth'.  This thread holds 'mutex'.
     *
     *     - UINT_MAX: This thread has the write-lock on 'rwlock' and holds
     *       'mutex' (plus the 'mutex' of all of 'rwlock''s other slots).
     *
     * Accessed only by the slot's own thread, so no synchronization is
     * needed. */
    unsigned int depth;

    /* To prevent two of these structures from accidentally occupying the same
     * cache line (causing "false sharing"), we cache-align each of these data
     * structures.  That requires malloc()ing extra space and throwing away
     * some space at the beginning, which means that the pointer to this struct
     * isn't necessarily the pointer to the beginning of the block, and so we
     * need to retain the original pointer to free later.
     *
     * Accessed only by a single thread, so no synchronization is needed. */
    void *base;                /* Pointer to pass to free() for this block.  */
};

static void
free_slot(struct fat_rwlock_slot *slot)
{
    if (slot->depth) {
        abort();
    }

    list_remove(&slot->list_node);
    free(slot->base);
}

static void
slot_destructor(void *slot_)
{
    struct fat_rwlock_slot *slot = slot_;
    struct fat_rwlock *rwlock = slot->rwlock;

    ovs_mutex_lock(&rwlock->mutex);
    free_slot(slot);
    ovs_mutex_unlock(&rwlock->mutex);
}

/* Initialize 'rwlock' as a new fat_rwlock. */
void
fat_rwlock_init(struct fat_rwlock *rwlock)
{
    ovsthread_key_create(&rwlock->key, slot_destructor);
    ovs_mutex_init(&rwlock->mutex);
    ovs_mutex_lock(&rwlock->mutex);
    list_init(&rwlock->threads);
    ovs_mutex_unlock(&rwlock->mutex);
}

/* Destroys 'rwlock', which must not be locked or otherwise in use by any
 * thread. */
void
fat_rwlock_destroy(struct fat_rwlock *rwlock)
{
    struct fat_rwlock_slot *slot, *next;

    /* Order is important here.  By destroying the thread-specific data first,
     * before we destroy the slots, we ensure that the thread-specific
     * data destructor can't race with our loop below. */
    ovsthread_key_delete(rwlock->key);

    LIST_FOR_EACH_SAFE (slot, next, list_node, &rwlock->threads) {
        free_slot(slot);
    }
    ovs_mutex_destroy(&rwlock->mutex);
}

static struct fat_rwlock_slot *
fat_rwlock_get_slot__(struct fat_rwlock *rwlock)
{
    struct fat_rwlock_slot *slot;
    void *base;

    /* Fast path. */
    slot = ovsthread_getspecific(rwlock->key);
    if (slot) {
        return slot;
    }

    /* Slow path: create a new slot for 'rwlock' in this thread. */

    /* Allocate room for:
     *
     *     - Up to CACHE_LINE_SIZE - 1 bytes before the per-thread, so that
     *       the start of the slot doesn't potentially share a cache line.
     *
     *     - The slot itself.
     *
     *     - Space following the slot up to the end of the cache line, so
     *       that the end of the slot doesn't potentially share a cache
     *       line. */
    base = xmalloc((CACHE_LINE_SIZE - 1)
                   + ROUND_UP(sizeof *slot, CACHE_LINE_SIZE));
    slot = (void *) ROUND_UP((uintptr_t) base, CACHE_LINE_SIZE);

    slot->base = base;
    slot->rwlock = rwlock;
    ovs_mutex_init(&slot->mutex);
    slot->depth = 0;

    ovs_mutex_lock(&rwlock->mutex);
    list_push_back(&rwlock->threads, &slot->list_node);
    ovs_mutex_unlock(&rwlock->mutex);

    ovsthread_setspecific(rwlock->key, slot);

    return slot;
}

/* Locks 'rwlock' for reading.  The read-lock is recursive: it may be acquired
 * any number of times by a single thread (which must then release it the same
 * number of times for it to truly be released). */
void
fat_rwlock_rdlock(const struct fat_rwlock *rwlock_)
    OVS_ACQ_RDLOCK(rwlock_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct fat_rwlock *rwlock = CONST_CAST(struct fat_rwlock *, rwlock_);
    struct fat_rwlock_slot *this = fat_rwlock_get_slot__(rwlock);

    switch (this->depth) {
    case UINT_MAX:
        /* This thread already holds the write-lock. */
        abort();

    case 0:
        ovs_mutex_lock(&this->mutex);
        /* fall through */
    default:
        this->depth++;
        break;
    }
}

/* Tries to lock 'rwlock' for reading.  If successful, returns 0.  If taking
 * the lock would require blocking, returns EBUSY (without blocking). */
int
fat_rwlock_tryrdlock(const struct fat_rwlock *rwlock_)
    OVS_TRY_RDLOCK(0, rwlock_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct fat_rwlock *rwlock = CONST_CAST(struct fat_rwlock *, rwlock_);
    struct fat_rwlock_slot *this = fat_rwlock_get_slot__(rwlock);
    int error;

    switch (this->depth) {
    case UINT_MAX:
        return EBUSY;

    case 0:
        error = ovs_mutex_trylock(&this->mutex);
        if (error) {
            return error;
        }
        /* fall through */
    default:
        this->depth++;
        break;
    }

    return 0;
}

/* Locks 'rwlock' for writing.
 *
 * The write lock is not recursive. */
void
fat_rwlock_wrlock(const struct fat_rwlock *rwlock_)
    OVS_ACQ_WRLOCK(rwlock_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct fat_rwlock *rwlock = CONST_CAST(struct fat_rwlock *, rwlock_);
    struct fat_rwlock_slot *this = fat_rwlock_get_slot__(rwlock);
    struct fat_rwlock_slot *slot;

    ovs_assert(!this->depth);
    this->depth = UINT_MAX;

    ovs_mutex_lock(&rwlock->mutex);
    LIST_FOR_EACH (slot, list_node, &rwlock->threads) {
        ovs_mutex_lock(&slot->mutex);
    }
}

/* Unlocks 'rwlock', which the current thread must have locked for reading or
 * for writing.  If the read lock has been taken recursively, it must be
 * released the same number of times to be truly released. */
void
fat_rwlock_unlock(const struct fat_rwlock *rwlock_)
    OVS_RELEASES(rwlock_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct fat_rwlock *rwlock = CONST_CAST(struct fat_rwlock *, rwlock_);
    struct fat_rwlock_slot *this = fat_rwlock_get_slot__(rwlock);
    struct fat_rwlock_slot *slot;

    switch (this->depth) {
    case UINT_MAX:
        LIST_FOR_EACH (slot, list_node, &rwlock->threads) {
            ovs_mutex_unlock(&slot->mutex);
        }
        ovs_mutex_unlock(&rwlock->mutex);
        this->depth = 0;
        break;

    case 0:
        /* This thread doesn't hold any lock. */
        abort();

    case 1:
        ovs_mutex_unlock(&this->mutex);
    default:
        this->depth--;
        break;
    }
}
