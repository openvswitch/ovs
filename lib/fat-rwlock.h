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

#ifndef FAT_RWLOCK_H
#define FAT_RWLOCK_H 1

#include "compiler.h"
#include "list.h"
#include "ovs-thread.h"

/* "Fat rwlock".
 *
 * This implements a reader-writer lock that uses a lot of memory (128 to 192
 * bytes per thread that takes the lock) but avoids cache line bouncing when
 * taking the read side.  Thus, a fat_rwlock is a good choice for rwlocks taken
 * frequently by readers.
 */
struct OVS_LOCKABLE fat_rwlock {
    ovsthread_key_t key;

    /* Contains "struct fat_rwlock_slot"s, one for each thread that has taken
     * this lock.  Guarded by 'mutex'. */
    struct list threads OVS_GUARDED;
    struct ovs_mutex mutex;
};

void fat_rwlock_init(struct fat_rwlock *);
void fat_rwlock_destroy(struct fat_rwlock *);

void fat_rwlock_rdlock(const struct fat_rwlock *rwlock) OVS_ACQ_RDLOCK(rwlock);
int fat_rwlock_tryrdlock(const struct fat_rwlock *rwlock)
    OVS_TRY_RDLOCK(0, rwlock);
void fat_rwlock_wrlock(const struct fat_rwlock *rwlock) OVS_ACQ_WRLOCK(rwlock);
void fat_rwlock_unlock(const struct fat_rwlock *rwlock) OVS_RELEASES(rwlock);

#endif /* fat-rwlock.h */
