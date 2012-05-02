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

/* A non-exhaustive test for some of the functions and macros declared in
 * list.h. */

#include <config.h>
#include "list.h"
#include <string.h>

#undef NDEBUG
#include <assert.h>

/* Sample list element. */
struct element {
    int value;
    struct list node;
};

/* Puts the 'n' values in 'values' into 'elements', and then puts those
 * elements in order into 'list'. */
static void
make_list(struct list *list, struct element elements[],
          int values[], size_t n)
{
    size_t i;

    list_init(list);
    for (i = 0; i < n; i++) {
        elements[i].value = i;
        list_push_back(list, &elements[i].node);
        values[i] = i;
    }
}

/* Verifies that 'list' contains exactly the 'n' values in 'values', in the
 * specified order. */
static void
check_list(struct list *list, const int values[], size_t n)
{
    struct element *e;
    size_t i;

    i = 0;
    LIST_FOR_EACH (e, node, list) {
        assert(i < n);
        assert(e->value == values[i]);
        i++;
    }
    assert(&e->node == list);
    assert(i == n);

    i = 0;
    LIST_FOR_EACH_REVERSE (e, node, list) {
        assert(i < n);
        assert(e->value == values[n - i - 1]);
        i++;
    }
    assert(&e->node == list);
    assert(i == n);

    assert(list_is_empty(list) == !n);
    assert(list_is_singleton(list) == (n == 1));
    assert(list_is_short(list) == (n < 2));
    assert(list_size(list) == n);
}

#if 0
/* Prints the values in 'list', plus 'name' as a title. */
static void
print_list(const char *name, struct list *list)
{
    struct element *e;

    printf("%s:", name);
    LIST_FOR_EACH (e, node, list) {
        printf(" %d", e->value);
    }
    printf("\n");
}
#endif

/* Tests basic list construction. */
static void
test_list_construction(void)
{
    enum { MAX_ELEMS = 100 };
    size_t n;

    for (n = 0; n <= MAX_ELEMS; n++) {
        struct element elements[MAX_ELEMS];
        int values[MAX_ELEMS];
        struct list list;

        make_list(&list, elements, values, n);
        check_list(&list, values, n);
    }
}

/* Tests that LIST_FOR_EACH_SAFE properly allows for deletion of the current
 * element of a list.  */
static void
test_list_for_each_safe(void)
{
    enum { MAX_ELEMS = 10 };
    size_t n;
    unsigned long int pattern;

    for (n = 0; n <= MAX_ELEMS; n++) {
        for (pattern = 0; pattern < 1ul << n; pattern++) {
            struct element elements[MAX_ELEMS];
            int values[MAX_ELEMS];
            struct list list;
            struct element *e, *next;
            size_t values_idx, n_remaining;
            int i;

            make_list(&list, elements, values, n);

            i = 0;
            values_idx = 0;
            n_remaining = n;
            LIST_FOR_EACH_SAFE (e, next, node, &list) {
                assert(i < n);
                if (pattern & (1ul << i)) {
                    list_remove(&e->node);
                    n_remaining--;
                    memmove(&values[values_idx], &values[values_idx + 1],
                            sizeof *values * (n_remaining - values_idx));
                } else {
                    values_idx++;
                }
                check_list(&list, values, n_remaining);
                i++;
            }
            assert(i == n);
            assert(&e->node == &list);

            for (i = 0; i < n; i++) {
                if (pattern & (1ul << i)) {
                    n_remaining++;
                }
            }
            assert(n == n_remaining);
        }
    }
}

static void
run_test(void (*function)(void))
{
    function();
    printf(".");
}

int
main(void)
{
    run_test(test_list_construction);
    run_test(test_list_for_each_safe);
    printf("\n");
    return 0;
}

