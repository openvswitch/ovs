/*
 * Copyright (c) 2012 Nicira, Inc.
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

/* A test for for functions and macros declared in heap.h. */

#include <config.h>
#include "heap.h"
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include "command-line.h"
#include "random.h"
#include "util.h"

#undef NDEBUG
#include <assert.h>

/* Sample heap element. */
struct element {
    uint32_t full_pri;
    struct heap_node heap_node;
};

static struct element *
element_from_heap_node(const struct heap_node *node)
{
    return CONTAINER_OF(node, struct element, heap_node);
}

static int
compare_uint32s(const void *a_, const void *b_)
{
    const uint32_t *a = a_;
    const uint32_t *b = b_;
    return *a < *b ? -1 : *a > *b;
}

/* Verifies that 'heap' is internally consistent and contains all 'n' of the
 * 'priorities'. */
static void
check_heap(const struct heap *heap, const uint32_t priorities[], size_t n)
{
    uint32_t *priorities_copy;
    uint32_t *elements_copy;
    struct element *element;
    size_t i;

    assert(heap_count(heap) == n);
    assert(heap_is_empty(heap) == !n);
    if (n > 0) {
        assert(heap_max(heap) == heap->array[1]);
    }

    /* Check indexes. */
    for (i = 1; i <= n; i++) {
        assert(heap->array[i]->idx == i);
    }

    /* Check that priority values are internally consistent. */
    for (i = 1; i <= n; i++) {
        element = element_from_heap_node(heap->array[i]);
        assert(element->heap_node.priority == (element->full_pri >> 16));
    }

    /* Check the heap property. */
    for (i = 1; i <= n; i++) {
        size_t parent = heap_parent__(i);
        size_t left = heap_left__(i);
        size_t right = heap_right__(i);

        if (parent >= 1) {
            assert(heap->array[parent]->priority >= heap->array[i]->priority);
        }
        if (left <= n) {
            assert(heap->array[left]->priority <= heap->array[i]->priority);
        }
        if (right <= n) {
            assert(heap->array[right]->priority <= heap->array[i]->priority);
        }
    }

    /* Check that HEAP_FOR_EACH iterates all the nodes in order. */
    i = 0;
    HEAP_FOR_EACH (element, heap_node, heap) {
        assert(i < n);
        assert(&element->heap_node == heap->array[i + 1]);
        i++;
    }
    assert(i == n);

    priorities_copy = xmemdup(priorities, n * sizeof *priorities);
    elements_copy = xmalloc(n * sizeof *priorities);
    i = 0;
    HEAP_FOR_EACH (element, heap_node, heap) {
        elements_copy[i++] = element->heap_node.priority;
    }

    qsort(priorities_copy, n, sizeof *priorities_copy, compare_uint32s);
    qsort(elements_copy, n, sizeof *elements_copy, compare_uint32s);
    for (i = 0; i < n; i++) {
        assert((priorities_copy[i] >> 16) == elements_copy[i]);
    }

    free(priorities_copy);
    free(elements_copy);
}

static void
shuffle(uint32_t *p, size_t n)
{
    for (; n > 1; n--, p++) {
        uint32_t *q = &p[random_range(n)];
        uint32_t tmp = *p;
        *p = *q;
        *q = tmp;
    }
}

/* Prints the values in 'heap', plus 'name' as a title. */
static void OVS_UNUSED
print_heap(const char *name, struct heap *heap)
{
    struct element *e;

    printf("%s:", name);
    HEAP_FOR_EACH (e, heap_node, heap) {
        printf(" %"PRIu32":%"PRIu32, e->full_pri >> 16, e->full_pri & 0xffff);
    }
    printf("\n");
}

static int
factorial(int n_items)
{
    int n, i;

    n = 1;
    for (i = 2; i <= n_items; i++) {
        n *= i;
    }
    return n;
}

static void
swap(uint32_t *a, uint32_t *b)
{
    uint32_t tmp = *a;
    *a = *b;
    *b = tmp;
}

static void
reverse(uint32_t *a, int n)
{
    int i;

    for (i = 0; i < n / 2; i++) {
        int j = n - (i + 1);
        swap(&a[i], &a[j]);
    }
}

static bool
next_permutation(uint32_t *a, int n)
{
    int k;

    for (k = n - 2; k >= 0; k--) {
        if ((a[k] >> 16) < (a[k + 1] >> 16)) {
            int l;

            for (l = n - 1; ; l--) {
                if ((a[l] >> 16) > (a[k] >> 16)) {
                    swap(&a[k], &a[l]);
                    reverse(a + (k + 1), n - (k + 1));
                    return true;
                }
            }
        }
    }
    return false;
}

static void
test_insert_delete__(struct element *elements,
                     const uint32_t *insert,
                     const uint32_t *delete,
                     size_t n)
{
    struct heap heap;
    size_t i;

    heap_init(&heap);
    check_heap(&heap, NULL, 0);
    for (i = 0; i < n; i++) {
        uint32_t priority = insert[i];

        elements[i].full_pri = priority;
        heap_insert(&heap, &elements[i].heap_node, priority >> 16);
        check_heap(&heap, insert, i + 1);
    }

    for (i = 0; i < n; i++) {
        struct element *element;

        HEAP_FOR_EACH (element, heap_node, &heap) {
            if (element->full_pri == delete[i]) {
                goto found;
            }
        }
        OVS_NOT_REACHED();

    found:
        heap_remove(&heap, &element->heap_node);
        check_heap(&heap, delete + i + 1, n - (i + 1));
    }
    heap_destroy(&heap);
}

static void
test_insert_delete_raw__(struct element *elements,
                         const uint32_t *insert, unsigned int insert_pattern,
                         const uint32_t *delete, unsigned int delete_pattern,
                         size_t n)
{
    struct heap heap;
    size_t i;

    heap_init(&heap);
    check_heap(&heap, NULL, 0);
    for (i = 0; i < n; i++) {
        uint32_t priority = insert[i];

        elements[i].full_pri = priority;
        heap_raw_insert(&heap, &elements[i].heap_node, priority >> 16);
        if (insert_pattern & (1u << i)) {
            heap_rebuild(&heap);
            check_heap(&heap, insert, i + 1);
        }
    }

    for (i = 0; i < n; i++) {
        struct element *element;

        HEAP_FOR_EACH (element, heap_node, &heap) {
            if (element->full_pri == delete[i]) {
                goto found;
            }
        }
        OVS_NOT_REACHED();

    found:
        heap_raw_remove(&heap, &element->heap_node);
        if (delete_pattern & (1u << i)) {
            heap_rebuild(&heap);
            check_heap(&heap, delete + i + 1, n - (i + 1));
        }
    }
    heap_destroy(&heap);
}

static void
test_heap_insert_delete_same_order(int argc OVS_UNUSED,
                                   char *argv[] OVS_UNUSED)
{
    enum { N_ELEMS = 7 };

    uint32_t insert[N_ELEMS];
    int n_permutations;
    size_t i;

    for (i = 0; i < N_ELEMS; i++) {
        insert[i] = i << 16;
    }

    n_permutations = 0;
    do {
        struct element elements[N_ELEMS];

        n_permutations++;
        test_insert_delete__(elements, insert, insert, N_ELEMS);
    } while (next_permutation(insert, N_ELEMS));
    assert(n_permutations == factorial(N_ELEMS));
}

static void
test_heap_insert_delete_reverse_order(int argc OVS_UNUSED,
                                      char *argv[] OVS_UNUSED)
{
    enum { N_ELEMS = 7 };

    uint32_t insert[N_ELEMS];
    int n_permutations;
    size_t i;

    for (i = 0; i < N_ELEMS; i++) {
        insert[i] = i << 16;
    }

    n_permutations = 0;
    do {
        struct element elements[N_ELEMS];
        uint32_t delete[N_ELEMS];

        n_permutations++;

        for (i = 0; i < N_ELEMS; i++) {
            delete[N_ELEMS - i - 1] = insert[i];
        }

        test_insert_delete__(elements, insert, delete, N_ELEMS);
    } while (next_permutation(insert, N_ELEMS));
    assert(n_permutations == factorial(N_ELEMS));
}

static void
test_heap_insert_delete_every_order(int argc OVS_UNUSED,
                                    char *argv[] OVS_UNUSED)
{
    enum { N_ELEMS = 5 };

    uint32_t insert[N_ELEMS];
    int outer_permutations;
    size_t i;

    for (i = 0; i < N_ELEMS; i++) {
        insert[i] = i << 16;
    }

    outer_permutations = 0;
    do {
        struct element elements[N_ELEMS];
        uint32_t delete[N_ELEMS];
        int inner_permutations;

        outer_permutations++;

        for (i = 0; i < N_ELEMS; i++) {
            delete[i] = i << 16;
        }

        inner_permutations = 0;
        do {
            inner_permutations++;
            test_insert_delete__(elements, insert, delete, N_ELEMS);
        } while (next_permutation(delete, N_ELEMS));
        assert(inner_permutations == factorial(N_ELEMS));
    } while (next_permutation(insert, N_ELEMS));
    assert(outer_permutations == factorial(N_ELEMS));
}

static void
test_heap_insert_delete_same_order_with_dups(int argc OVS_UNUSED,
                                             char *argv[] OVS_UNUSED)
{
    enum { N_ELEMS = 7 };

    unsigned int pattern;
    size_t i;

    for (pattern = 0; pattern < (1u << N_ELEMS); pattern += 2) {
        int n_permutations, expected_permutations;
        uint32_t insert[N_ELEMS];
        int j;

        j = 0;
        for (i = 0; i < N_ELEMS; i++) {
            if (i && !(pattern & (1u << i))) {
                j++;
            }
            insert[i] = (j << 16) | i;
        }

        expected_permutations = factorial(N_ELEMS);
        for (i = 0; i < N_ELEMS; ) {
            j = i + 1;
            if (pattern & (1u << i)) {
                for (; j < N_ELEMS; j++) {
                    if (!(pattern & (1u << j))) {
                        break;
                    }
                }
                expected_permutations /= factorial(j - i + 1);
            }
            i = j;
        }

        n_permutations = 0;
        do {
            struct element elements[N_ELEMS];

            n_permutations++;
            test_insert_delete__(elements, insert, insert, N_ELEMS);
        } while (next_permutation(insert, N_ELEMS));
        assert(n_permutations == expected_permutations);
    }
}

static void
test_heap_raw_insert(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum { N_ELEMS = 7 };

    uint32_t insert[N_ELEMS];
    int n_permutations;
    size_t i;

    for (i = 0; i < N_ELEMS; i++) {
        insert[i] = i << 16;
    }

    n_permutations = 0;
    do {
        struct element elements[N_ELEMS];

        n_permutations++;
        test_insert_delete_raw__(elements,
                                 insert, 1u << (N_ELEMS - 1),
                                 insert, UINT_MAX,
                                 N_ELEMS);
    } while (next_permutation(insert, N_ELEMS));
    assert(n_permutations == factorial(N_ELEMS));
}

static void
test_heap_raw_delete(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    enum { N_ELEMS = 16 };

    uint32_t insert[N_ELEMS];
    uint32_t delete[N_ELEMS];
    size_t i;

    for (i = 0; i < N_ELEMS; i++) {
        insert[i] = i << 16;
        delete[i] = i << 16;
    }

    for (i = 0; i < 1000; i++) {
        struct element elements[N_ELEMS];

        shuffle(insert, N_ELEMS);
        shuffle(delete, N_ELEMS);

        test_insert_delete_raw__(elements,
                                 insert, 0,
                                 delete,
                                 (1u << (N_ELEMS - 1)) | (1u << (N_ELEMS / 2)),
                                 N_ELEMS);
    }
}

static const struct command commands[] = {
    { "insert-delete-same-order", 0, 0, test_heap_insert_delete_same_order, },
    { "insert-delete-reverse-order", 0, 0,
      test_heap_insert_delete_reverse_order, },
    { "insert-delete-every-order", 0, 0,
      test_heap_insert_delete_every_order, },
    { "insert-delete-same-order-with-dups", 0, 0,
      test_heap_insert_delete_same_order_with_dups, },
    { "raw-insert", 0, 0, test_heap_raw_insert, },
    { "raw-delete", 0, 0, test_heap_raw_delete, },
};

int
main(int argc, char *argv[])
{
    set_program_name(argv[0]);

    run_command(argc - 1, argv + 1, commands);

    return 0;
}
