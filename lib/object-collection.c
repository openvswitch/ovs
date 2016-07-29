/*
 * Copyright (c) 2016 Nicira, Inc.
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

#include "object-collection.h"
#include "util.h"

void
object_collection_init(struct object_collection *coll)
{
    coll->objs = coll->stub;
    coll->n = 0;
    coll->capacity = ARRAY_SIZE(coll->stub);
}

void
object_collection_add(struct object_collection *coll, void *obj)
{
    if (coll->n >= coll->capacity) {
        size_t old_size, new_size;

        old_size = coll->capacity * sizeof *coll->objs;
        coll->capacity *= 2;
        new_size = coll->capacity * sizeof *coll->objs;

        if (coll->objs == coll->stub) {
            coll->objs = xmalloc(new_size);
            memcpy(coll->objs, coll->stub, old_size);
        } else {
            coll->objs = xrealloc(coll->objs, new_size);
        }
    }

    coll->objs[coll->n++] = obj;
}

void
object_collection_remove(struct object_collection *coll, void *obj)
{
    size_t i;

    for (i = 0; i < coll->n; i++) {
        if (coll->objs[i] == obj) {
            break;
        }
    }
    if (i == coll->n) {
        return;
    }

    coll->n--;
    /* Swap the last item in if needed. */
    if (i != coll->n) {
        coll->objs[i] = coll->objs[coll->n];
    }

    /* Shrink? Watermark at '/ 4' to get hysteresis and leave spare
     * capacity. */
    if (coll->objs != coll->stub && coll->n <= coll->capacity / 4) {
        size_t actual_size, new_size;

        actual_size = coll->n * sizeof *coll->objs;
        coll->capacity /= 2;
        new_size = coll->capacity * sizeof *coll->objs;

        if (new_size <= sizeof(coll->stub)) {
            memcpy(coll->stub, coll->objs, actual_size);
            free(coll->objs);
            coll->objs = coll->stub;
        } else {
            coll->objs = xrealloc(coll->objs, new_size);
        }
    }
}

void
object_collection_move(struct object_collection *to,
                       struct object_collection *from)
{
    ovs_assert(to->n == 0);

    *to = *from;
    if (from->objs == from->stub) {
        to->objs = to->stub;
    }
    object_collection_init(from);
}

/* Returns a NULL-terminated array of object pointers,
 * destroys 'rules'. */
void *
object_collection_detach(struct object_collection *coll)
{
    void **array;

    object_collection_add(coll, NULL);

    if (coll->objs == coll->stub) {
        coll->objs = xmemdup(coll->objs, coll->n * sizeof *coll->objs);
    }

    array = coll->objs;
    object_collection_init(coll);

    return array;
}

void
object_collection_destroy(struct object_collection *coll)
{
    if (coll->objs != coll->stub) {
        free(coll->objs);
    }

    /* Make repeated destruction harmless. */
    object_collection_init(coll);
}
