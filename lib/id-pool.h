/*
 * Copyright (c) 2014 Nicira, Inc.
 * Copyright (c) 2014 Netronome.
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

#ifndef ID_POOL_H
#define ID_POOL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct id_pool;

struct id_pool *id_pool_create(uint32_t base, uint32_t n_ids);
void id_pool_destroy(struct id_pool *);
bool id_pool_alloc_id(struct id_pool *, uint32_t *id);
void id_pool_free_id(struct id_pool *, uint32_t id);
void id_pool_add(struct id_pool *, uint32_t id);

/*
 * ID pool.
 * ========
 *
 * Pool of unique 32bit ids.
 *
 *
 * Thread-safety
 * =============
 *
 * APIs are not thread safe.
 */
#endif  /* id-pool.h */
