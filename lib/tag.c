/*
 * Copyright (c) 2008, 2009, 2010, 2011 Nicira, Inc.
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
#include <limits.h>
#include "random.h"
#include "type-props.h"
#include "util.h"

#define N_TAG_BITS (CHAR_BIT * sizeof(tag_type))
BUILD_ASSERT_DECL(IS_POW2(N_TAG_BITS));

#define LOG2_N_TAG_BITS (N_TAG_BITS == 32 ? 5 : N_TAG_BITS == 64 ? 6 : 0)
BUILD_ASSERT_DECL(LOG2_N_TAG_BITS > 0);

/* Returns a randomly selected tag. */
tag_type
tag_create_random(void)
{
    int x, y;
    do {
        uint16_t r = random_uint16();
        x = r & (N_TAG_BITS - 1);
        y = r >> (16 - LOG2_N_TAG_BITS);
    } while (x == y);
    return (1u << x) | (1u << y);
}

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

/* Initializes 'set' as an empty tag set. */
void
tag_set_init(struct tag_set *set)
{
    memset(set, 0, sizeof *set);
}

static bool
tag_is_worth_adding(const struct tag_set *set, tag_type tag)
{
    if (!tag) {
        /* Nothing to add. */
        return false;
    } else if ((set->total & tag) != tag) {
        /* 'set' doesn't have all the bits in 'tag', so we need to add it. */
        return true;
    } else {
        /* We can drop it if some member of 'set' already includes all of the
         * 1-bits in 'tag'.  (tag_set_intersects() does a different test:
         * whether some member of 'set' has at least two 1-bit in common with
         * 'tag'.) */
        int i;

        for (i = 0; i < TAG_SET_SIZE; i++) {
            if ((set->tags[i] & tag) == tag) {
                return false;
            }
        }
        return true;
    }
}

/* Adds 'tag' to 'set'. */
void
tag_set_add(struct tag_set *set, tag_type tag)
{
    if (tag_is_worth_adding(set, tag)) {
        /* XXX We could do better by finding the set member to which we would
         * add the fewest number of 1-bits.  This would reduce the amount of
         * ambiguity, since e.g. three 1-bits match 3 * 2 / 2 = 3 unique tags
         * whereas four 1-bits match 4 * 3 / 2 = 6 unique tags. */
        tag_type *t = &set->tags[set->n++ % TAG_SET_SIZE];
        *t |= tag;
        if (*t == TYPE_MAXIMUM(tag_type)) {
            set->tags[0] = *t;
        }

        set->total |= tag;
    }
}

/* Adds all the tags in 'other' to 'set'. */
void
tag_set_union(struct tag_set *set, const struct tag_set *other)
{
    size_t i;

    for (i = 0; i < TAG_SET_SIZE; i++) {
        tag_set_add(set, other->tags[i]);
    }
}
