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

#ifndef CCMAP_H
#define CCMAP_H 1

#include <stdbool.h>
#include <stdint.h>
#include "ovs-rcu.h"
#include "util.h"

/* Concurrent hash map for numerical counts of given hash values.
 * ==============================================================
 *
 * A single-writer, multiple-reader count hash table that efficiently supports
 * duplicates.
 *
 *
 * Thread-safety
 * =============
 *
 * The general rules are:
 *
 *    - Only a single thread may safely call into ccmap_inc(),
 *      or ccmap_dec() at any given time.
 *
 *    - Any number of threads may use functions and macros that search
 *      a given ccmap, even in parallel with other threads
 *      calling ccmap_inc() or ccmap_dec().
 */

/* Concurrent hash map. */
struct ccmap {
    OVSRCU_TYPE(struct ccmap_impl *) impl;
};

/* Initialization. */
void ccmap_init(struct ccmap *);
void ccmap_destroy(struct ccmap *);

/* Count. */
size_t ccmap_count(const struct ccmap *);
bool ccmap_is_empty(const struct ccmap *);

/* Insertion and deletion.  Return the current count after the operation. */
uint32_t ccmap_inc(struct ccmap *, uint32_t hash);
uint32_t ccmap_dec(struct ccmap *, uint32_t hash);

uint32_t ccmap_find(const struct ccmap *, uint32_t hash);

#endif /* ccmap.h */
