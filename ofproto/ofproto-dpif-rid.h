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

#ifndef OFPROTO_DPIF_RID_H
#define OFPROTO_DPIF_RID_H

#include <stddef.h>
#include <stdint.h>

struct recirc_id_pool;

/*
 * Recirculation ID pool.
 * ======================
 *
 * Recirculation ID needs to be unique for each datapath. Recirculation
 * ID pool keeps track recirculation ids.
 *
 * Typically, there is one recirculation ID pool for each backer.
 *
 * In theory, Recirculation ID can be any uint32_t value, except 0.
 * The implementation usually limits it to a smaller range to ease
 * debugging.
 *
 * Thread-safety
 * =============
 *
 * All APIs are thread safe.
 *
 */
struct recirc_id_pool *recirc_id_pool_create(void);
void  recirc_id_pool_destroy(struct recirc_id_pool *pool);
uint32_t recirc_id_alloc(struct recirc_id_pool *pool);
void recirc_id_free(struct recirc_id_pool *pool, uint32_t recirc_id);
#endif
