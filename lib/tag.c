/*
 * Copyright (c) 2008, 2009 Nicira Networks.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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
    int y = (seed >> LOG2_N_TAG_BITS) % 31;
    y += y >= x;
    return (1u << x) | (1u << y);
}

/* Initializes 'set' as an empty tag set. */
void
tag_set_init(struct tag_set *set)
{
    memset(set, 0, sizeof *set);
}

/* Adds 'tag' to 'set'. */
void
tag_set_add(struct tag_set *set, tag_type tag)
{
    if (tag && (!tag_is_valid(tag) || !tag_set_intersects(set, tag))) {
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

