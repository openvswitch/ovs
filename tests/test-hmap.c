/*
 * Copyright (c) 2008, 2009, 2010 Nicira, Inc.
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
 * hmap.h. */

#include <config.h>
#include "hmap.h"
#include <string.h>
#include "hash.h"
#include "util.h"

#undef NDEBUG
#include <assert.h>

/* Sample hmap element. */
struct element {
    int value;
    struct hmap_node node;
};

typedef size_t hash_func(int value);

static int
compare_ints(const void *a_, const void *b_)
{
    const int *a = a_;
    const int *b = b_;
    return *a < *b ? -1 : *a > *b;
}

/* Verifies that 'hmap' contains exactly the 'n' values in 'values'. */
static void
check_hmap(struct hmap *hmap, const int values[], size_t n,
           hash_func *hash)
{
    int *sort_values, *hmap_values;
    struct element *e;
    size_t i;

    /* Check that all the values are there in iteration. */
    sort_values = xmalloc(sizeof *sort_values * n);
    hmap_values = xmalloc(sizeof *sort_values * n);

    i = 0;
    HMAP_FOR_EACH (e, node, hmap) {
        assert(i < n);
        hmap_values[i++] = e->value;
    }
    assert(i == n);

    memcpy(sort_values, values, sizeof *sort_values * n);
    qsort(sort_values, n, sizeof *sort_values, compare_ints);
    qsort(hmap_values, n, sizeof *hmap_values, compare_ints);

    for (i = 0; i < n; i++) {
        assert(sort_values[i] == hmap_values[i]);
    }

    free(hmap_values);
    free(sort_values);

    /* Check that all the values are there in lookup. */
    for (i = 0; i < n; i++) {
        size_t count = 0;

        HMAP_FOR_EACH_WITH_HASH (e, node, hash(values[i]), hmap) {
            count += e->value == values[i];
        }
        assert(count == 1);
    }

    /* Check counters. */
    assert(hmap_is_empty(hmap) == !n);
    assert(hmap_count(hmap) == n);
}

/* Puts the 'n' values in 'values' into 'elements', and then puts those
 * elements into 'hmap'. */
static void
make_hmap(struct hmap *hmap, struct element elements[],
          int values[], size_t n, hash_func *hash)
{
    size_t i;

    hmap_init(hmap);
    for (i = 0; i < n; i++) {
        elements[i].value = i;
        hmap_insert(hmap, &elements[i].node, hash(elements[i].value));
        values[i] = i;
    }
}

static void
shuffle(int *p, size_t n)
{
    for (; n > 1; n--, p++) {
        int *q = &p[rand() % n];
        int tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

#if 0
/* Prints the values in 'hmap', plus 'name' as a title. */
static void
print_hmap(const char *name, struct hmap *hmap)
{
    struct element *e;

    printf("%s:", name);
    HMAP_FOR_EACH (e, node, hmap) {
        printf(" %d(%zu)", e->value, e->node.hash & hmap->mask);
    }
    printf("\n");
}

/* Prints the 'n' values in 'values', plus 'name' as a title. */
static void
print_ints(const char *name, const int *values, size_t n)
{
    size_t i;

    printf("%s:", name);
    for (i = 0; i < n; i++) {
        printf(" %d", values[i]);
    }
    printf("\n");
}
#endif

static size_t
identity_hash(int value)
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

/* Tests basic hmap insertion and deletion. */
static void
test_hmap_insert_delete(hash_func *hash)
{
    enum { N_ELEMS = 100 };

    struct element elements[N_ELEMS];
    int values[N_ELEMS];
    struct hmap hmap;
    size_t i;

    hmap_init(&hmap);
    for (i = 0; i < N_ELEMS; i++) {
        elements[i].value = i;
        hmap_insert(&hmap, &elements[i].node, hash(i));
        values[i] = i;
        check_hmap(&hmap, values, i + 1, hash);
    }
    shuffle(values, N_ELEMS);
    for (i = 0; i < N_ELEMS; i++) {
        hmap_remove(&hmap, &elements[values[i]].node);
        check_hmap(&hmap, values + (i + 1), N_ELEMS - (i + 1), hash);
    }
    hmap_destroy(&hmap);
}

/* Tests basic hmap_reserve() and hmap_shrink(). */
static void
test_hmap_reserve_shrink(hash_func *hash)
{
    enum { N_ELEMS = 32 };

    size_t i;

    for (i = 0; i < N_ELEMS; i++) {
        struct element elements[N_ELEMS];
        int values[N_ELEMS];
        struct hmap hmap;
        size_t j;

        hmap_init(&hmap);
        hmap_reserve(&hmap, i);
        for (j = 0; j < N_ELEMS; j++) {
            elements[j].value = j;
            hmap_insert(&hmap, &elements[j].node, hash(j));
            values[j] = j;
            check_hmap(&hmap, values, j + 1, hash);
        }
        shuffle(values, N_ELEMS);
        for (j = 0; j < N_ELEMS; j++) {
            hmap_remove(&hmap, &elements[values[j]].node);
            hmap_shrink(&hmap);
            check_hmap(&hmap, values + (j + 1), N_ELEMS - (j + 1), hash);
        }
        hmap_destroy(&hmap);
    }
}

/* Tests that HMAP_FOR_EACH_SAFE properly allows for deletion of the current
 * element of a hmap.  */
static void
test_hmap_for_each_safe(hash_func *hash)
{
    enum { MAX_ELEMS = 10 };
    size_t n;
    unsigned long int pattern;

    for (n = 0; n <= MAX_ELEMS; n++) {
        for (pattern = 0; pattern < 1ul << n; pattern++) {
            struct element elements[MAX_ELEMS];
            int values[MAX_ELEMS];
            struct hmap hmap;
            struct element *e, *next;
            size_t n_remaining;
            int i;

            make_hmap(&hmap, elements, values, n, hash);

            i = 0;
            n_remaining = n;
            HMAP_FOR_EACH_SAFE (e, next, node, &hmap) {
                assert(i < n);
                if (pattern & (1ul << e->value)) {
                    size_t j;
                    hmap_remove(&hmap, &e->node);
                    for (j = 0; ; j++) {
                        assert(j < n_remaining);
                        if (values[j] == e->value) {
                            values[j] = values[--n_remaining];
                            break;
                        }
                    }
                }
                check_hmap(&hmap, values, n_remaining, hash);
                i++;
            }
            assert(i == n);

            for (i = 0; i < n; i++) {
                if (pattern & (1ul << i)) {
                    n_remaining++;
                }
            }
            assert(n == n_remaining);

            hmap_destroy(&hmap);
        }
    }
}

static void
run_test(void (*function)(hash_func *))
{
    hash_func *hash_funcs[] = { identity_hash, good_hash, constant_hash };
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
    run_test(test_hmap_insert_delete);
    run_test(test_hmap_for_each_safe);
    run_test(test_hmap_reserve_shrink);
    printf("\n");
    return 0;
}

