/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2013 Nicira, Inc.
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
#include "tag.h"

#define LOG2_N_TAG_BITS (N_TAG_BITS == 32 ? 5 : N_TAG_BITS == 64 ? 6 : 0)
BUILD_ASSERT_DECL(LOG2_N_TAG_BITS > 0);

/* Returns a tag deterministically generated from 'seed'.
 *
 * 'seed' should have data in all of its bits; if it has data only in its
 * low-order bits then the resulting tags will be poorly distributed.  Use a
 * hash function such as hash_bytes() to generate 'seed' if necessary. */
tag_type
tag_create_deterministic(uint32_t seed)
{
    int x = seed & (N_TAG_BITS - 1);
    int y = (seed >> LOG2_N_TAG_BITS) % (N_TAG_BITS - 1);
    y += y >= x;
    return (1u << x) | (1u << y);
}

/* Initializes 'tracker'. */
void
tag_tracker_init(struct tag_tracker *tracker)
{
    memset(tracker, 0, sizeof *tracker);
}

/* Adds 'add' to '*tags' and records the bits added in 'tracker'. */
void
tag_tracker_add(struct tag_tracker *tracker, tag_type *tags, tag_type add)
{
    *tags |= add;
    for (; add; add = zero_rightmost_1bit(add)) {
        tracker->counts[rightmost_1bit_idx(add)]++;
    }
}

/* Removes 'sub' from 'tracker' and unsets any bits in '*tags' that no
 * remaining tag includes. */
void
tag_tracker_subtract(struct tag_tracker *tracker, tag_type *tags, tag_type sub)
{
    for (; sub; sub = zero_rightmost_1bit(sub)) {
        if (!--tracker->counts[rightmost_1bit_idx(sub)]) {
            *tags &= ~rightmost_1bit(sub);
        }
    }
}
