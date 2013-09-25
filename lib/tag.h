/*
 * Copyright (c) 2008, 2011, 2012, 2013 Nicira, Inc.
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

#ifndef TAG_H
#define TAG_H 1

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>
#include "util.h"

/*
 * Tagging support.
 *
 * A 'tag' represents an arbitrary category.  Currently, tags are used to
 * represent categories of flows and in particular the value of the 64-bit
 * "metadata" field in the flow.  The universe of possible categories is very
 * large (2**64).  The number of categories in use at a given time can also be
 * large.  This means that keeping track of category membership via
 * conventional means (lists, bitmaps, etc.) is likely to be expensive.
 *
 * Tags are actually implemented via a "superimposed coding", as discussed in
 * Knuth TAOCP v.3 section 6.5 "Retrieval on Secondary Keys".  A tag is an
 * unsigned integer in which exactly 2 bits are set to 1 and the rest set to 0.
 * For 32-bit integers (as currently used) there are 32 * 31 / 2 = 496 unique
 * tags; for 64-bit integers there are 64 * 63 / 2 = 2,016.
 *
 * Because there is a small finite number of unique tags, tags must collide
 * after some number of them have been created.  In practice we generally
 * create tags by choosing bits randomly or based on a hash function.
 *
 * The key property of tags is that we can combine them without increasing the
 * amount of data required using bitwise-OR, since the result has the 1-bits
 * from both tags set.  The necessary tradeoff is that the result is even more
 * ambiguous: if combining two tags yields a value with 4 bits set to 1, then
 * the result value will test as having 4 * 3 / 2 = 6 unique tags, not just the
 * two tags that we combined.
 *
 * The upshot is this: a value that is the bitwise-OR combination of a number
 * of tags will always include the tags that were combined, but it may contain
 * any number of additional tags as well.  This is acceptable for our use,
 * since we want to be sure that we check every classifier table that contains
 * a rule with a given metadata value, but it is OK if we check a few extra
 * tables as well.
 *
 * If we combine too many tags, then the result will have every bit set, so
 * that it will test as including every tag.  This can happen, but we hope that
 * this is not the common case.
 */

/* Represents a tag, or the combination of 0 or more tags. */
typedef uint32_t tag_type;

#define N_TAG_BITS (CHAR_BIT * sizeof(tag_type))
BUILD_ASSERT_DECL(IS_POW2(N_TAG_BITS));

/* A 'tag_type' value that intersects every tag. */
#define TAG_ALL UINT32_MAX

/* An arbitrary tag. */
#define TAG_ARBITRARY UINT32_C(3)

tag_type tag_create_deterministic(uint32_t seed);
static inline bool tag_intersects(tag_type, tag_type);

/* Returns true if 'a' and 'b' have at least one tag in common,
 * false if their set of tags is disjoint. */
static inline bool
tag_intersects(tag_type a, tag_type b)
{
    tag_type x = a & b;
    return (x & (x - 1)) != 0;
}

/* Adding tags is easy, but subtracting is hard because you can't tell whether
 * a bit was set only by the tag you're removing or by multiple tags.  The
 * tag_tracker data structure counts the number of tags that set each bit,
 * which allows for efficient subtraction. */
struct tag_tracker {
    unsigned int counts[N_TAG_BITS];
};

void tag_tracker_init(struct tag_tracker *);
void tag_tracker_add(struct tag_tracker *, tag_type *, tag_type);
void tag_tracker_subtract(struct tag_tracker *, tag_type *, tag_type);

#endif /* tag.h */
