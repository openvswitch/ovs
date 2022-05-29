/*
 * Copyright (c) 2021 NVIDIA Corporation.
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

#ifndef ID_FPOOL_H
#define ID_FPOOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Fast ID pool.
 * =============
 *
 * Unordered pool of unique 32 bits IDs.
 *
 * Multiple users are registered at initialization.  Each one gets a cache
 * of ID.  When each thread allocates from the pool using its own user ID,
 * the pool scales for concurrent allocation.
 *
 * New IDs are always in the range of '[floor, next_id]', where 'next_id' is
 * in the range of '[last_allocated_ID + nb_user * cache_size + 1]'.
 * This means that a new ID is not always the smallest available ID, but it is
 * still from a limited range.
 *
 * Users should ensure that an ID is *never* freed twice.  Not doing so will
 * have the effect of double-allocating such ID afterward.
 *
 * Thread-safety
 * =============
 *
 * APIs are thread safe.
 * Multiple threads can share the same user ID if necessary.
 */

#define ID_FPOOL_CACHE_SIZE 64

struct id_fpool;

/* nb_user is the number of expected users of the pool,
 * in terms of execution threads. */
struct id_fpool *id_fpool_create(unsigned int nb_user,
                                 uint32_t base, uint32_t n_ids);
void id_fpool_destroy(struct id_fpool *pool);

/* uid is the thread user-id. It should be within '[0, nb_user)'. */
bool id_fpool_new_id(struct id_fpool *pool, unsigned int uid, uint32_t *id);

/* uid is the thread user-id. It should be within '[0, nb_user)'.
 * An allocated ID must never be freed twice. */
void id_fpool_free_id(struct id_fpool *pool, unsigned int uid, uint32_t id);

#endif  /* ID_FPOOL_H */
