/*
 * Copyright (c) 2008, 2009, 2010, 2013 Nicira, Inc.
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

/* A non-exhaustive test for some of the functions and macros declared in
 * hindex.h. */

#include <config.h>
#include "hindex.h"
#include <string.h>
#include "hash.h"
#include "random.h"
#include "util.h"

#undef NDEBUG
#include <assert.h>

/* Sample hindex element. */
struct element {
    int value;
    struct hindex_node node;
};

typedef size_t hash_func(int value);

static int
compare_ints(const void *a_, const void *b_)
{
    const int *a = a_;
    const int *b = b_;
    return *a < *b ? -1 : *a > *b;
}

/* Verifies that 'hindex' contains exactly the 'n' values in 'values'. */
static void
check_hindex(struct hindex *hindex, const int values[], size_t n,
           hash_func *hash)
{
    int *sort_values, *hindex_values;
    struct element *e;
    size_t i;

    /* Check that all the values are there in iteration. */
    sort_values = xmalloc(sizeof *sort_values * n);
    hindex_values = xmalloc(sizeof *sort_values * n);

    i = 0;
    HINDEX_FOR_EACH (e, node, hindex) {
        assert(i < n);
        hindex_values[i++] = e->value;
    }
    assert(i == n);

    memcpy(sort_values, values, sizeof *sort_values * n);
    qsort(sort_values, n, sizeof *sort_values, compare_ints);
    qsort(hindex_values, n, sizeof *hindex_values, compare_ints);

    for (i = 0; i < n; i++) {
        assert(sort_values[i] == hindex_values[i]);
    }

    free(hindex_values);
    free(sort_values);

    /* Check that all the values are there in lookup. */
    for (i = 0; i < n; i++) {
        size_t count = 0;

        HINDEX_FOR_EACH_WITH_HASH (e, node, hash(values[i]), hindex) {
            count += e->value == values[i];
        }
        assert(count == 1);
    }

    /* Check counters. */
    assert(hindex_is_empty(hindex) == !n);
    assert(hindex->n_unique <= n);
}

/* Puts the 'n' values in 'values' into 'elements', and then puts those
 * elements into 'hindex'. */
static void
make_hindex(struct hindex *hindex, struct element elements[],
          int values[], size_t n, hash_func *hash)
{
    size_t i;

    hindex_init(hindex);
    for (i = 0; i < n; i++) {
        elements[i].value = i;
        hindex_insert(hindex, &elements[i].node, hash(elements[i].value));
        values[i] = i;
    }
}

static void
shuffle(int *p, size_t n)
{
    for (; n > 1; n--, p++) {
        int *q = &p[random_range(n)];
        int tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

/* Prints the 'n' values in 'values', plus 'name' as a title. */
static void OVS_UNUSED
print_ints(const char *name, const int *values, size_t n)
{
    size_t i;

    printf("%s:", name);
    for (i = 0; i < n; i++) {
        printf(" %d", values[i]);
    }
    printf("\n");
}

/* Prints the values in 'hindex', plus 'name' as a title. */
static void OVS_UNUSED
print_hindex(const char *name, struct hindex *hindex)
{
    struct element *e;

    printf("%s:", name);
    HINDEX_FOR_EACH (e, node, hindex) {
        printf(" %d(%"PRIuSIZE")", e->value, e->node.hash & hindex->mask);
    }
    printf("\n");
}

static size_t
unique_hash(int value)
{
    return value;
}

static size_t
good_hash(int value)
{
    return hash_int(value, 0x1234abcd);
}

static size_t
constant_hash(int value OVS_UNUSED)
{
    return 123;
}

static size_t
mod4_hash(int value)
{
    return value % 4;
}

static size_t
mod3_hash(int value)
{
    return value % 3;
}

static size_t
mod2_hash(int value)
{
    return value % 2;
}

static size_t
multipart_hash(int value)
{
    return (mod4_hash(value) << 16) | (constant_hash(value) & 0xFFFF);
}

/* Tests basic hindex insertion and deletion. */
static void
test_hindex_insert_delete(hash_func *hash)
{
    enum { N_ELEMS = 100 };

    struct element elements[N_ELEMS];
    int values[N_ELEMS];
    struct hindex hindex;
    size_t i;

    hindex_init(&hindex);
    for (i = 0; i < N_ELEMS; i++) {
        elements[i].value = i;
        hindex_insert(&hindex, &elements[i].node, hash(i));
        values[i] = i;
        check_hindex(&hindex, values, i + 1, hash);
    }
    shuffle(values, N_ELEMS);
    for (i = 0; i < N_ELEMS; i++) {
        hindex_remove(&hindex, &elements[values[i]].node);
        check_hindex(&hindex, values + (i + 1), N_ELEMS - (i + 1), hash);
    }
    hindex_destroy(&hindex);
}

/* Tests basic hindex_reserve() and hindex_shrink(). */
static void
test_hindex_reserve_shrink(hash_func *hash)
{
    enum { N_ELEMS = 32 };

    size_t i;

    for (i = 0; i < N_ELEMS; i++) {
        struct element elements[N_ELEMS];
        int values[N_ELEMS];
        struct hindex hindex;
        size_t j;

        hindex_init(&hindex);
        hindex_reserve(&hindex, i);
        for (j = 0; j < N_ELEMS; j++) {
            elements[j].value = j;
            hindex_insert(&hindex, &elements[j].node, hash(j));
            values[j] = j;
            check_hindex(&hindex, values, j + 1, hash);
        }
        shuffle(values, N_ELEMS);
        for (j = 0; j < N_ELEMS; j++) {
            hindex_remove(&hindex, &elements[values[j]].node);
            hindex_shrink(&hindex);
            check_hindex(&hindex, values + (j + 1), N_ELEMS - (j + 1), hash);
        }
        hindex_destroy(&hindex);
    }
}

/* Tests that HINDEX_FOR_EACH_SAFE properly allows for deletion of the current
 * element of a hindex.  */
static void
test_hindex_for_each_safe(hash_func *hash)
{
    enum { MAX_ELEMS = 10 };
    size_t n;
    unsigned long int pattern;

    for (n = 0; n <= MAX_ELEMS; n++) {
        for (pattern = 0; pattern < 1ul << n; pattern++) {
            struct element elements[MAX_ELEMS];
            int values[MAX_ELEMS];
            struct hindex hindex;
            struct element *e, *next;
            size_t n_remaining;
            int i;

            make_hindex(&hindex, elements, values, n, hash);

            i = 0;
            n_remaining = n;
            HINDEX_FOR_EACH_SAFE (e, next, node, &hindex) {
                assert(i < n);
                if (pattern & (1ul << e->value)) {
                    size_t j;
                    hindex_remove(&hindex, &e->node);
                    for (j = 0; ; j++) {
                        assert(j < n_remaining);
                        if (values[j] == e->value) {
                            values[j] = values[--n_remaining];
                            break;
                        }
                    }
                }
                check_hindex(&hindex, values, n_remaining, hash);
                i++;
            }
            assert(i == n);

            for (i = 0; i < n; i++) {
                if (pattern & (1ul << i)) {
                    n_remaining++;
                }
            }
            assert(n == n_remaining);

            hindex_destroy(&hindex);
        }
    }
}

static void
run_test(void (*function)(hash_func *))
{
    hash_func *hash_funcs[] = {
        unique_hash,
        good_hash,
        constant_hash,
        mod4_hash,
        mod3_hash,
        mod2_hash,
        multipart_hash,
    };
    size_t i;

    for (i = 0; i < ARRAY_SIZE(hash_funcs); i++) {
        function(hash_funcs[i]);
        printf(".");
        fflush(stdout);
    }
}

int
main(void)
{
    run_test(test_hindex_insert_delete);
    run_test(test_hindex_for_each_safe);
    run_test(test_hindex_reserve_shrink);
    printf("\n");
    return 0;
}

