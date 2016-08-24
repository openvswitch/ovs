/*
 * Copyright (c) 2008, 2009, 2010, 2011, 2014 Nicira, Inc.
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
 * openvswitch/list.h. */

#include <config.h>
#undef NDEBUG
#include "openvswitch/list.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ovstest.h"

/* Sample list element. */
struct element {
    int value;
    struct ovs_list node;
};

/* Puts the 'n' values in 'values' into 'elements', and then puts those
 * elements in order into 'list'. */
static void
make_list(struct ovs_list *list, struct element elements[],
          int values[], size_t n)
{
    size_t i;

    ovs_list_init(list);
    for (i = 0; i < n; i++) {
        elements[i].value = i;
        ovs_list_push_back(list, &elements[i].node);
        values[i] = i;
    }
}

/* Verifies that 'list' contains exactly the 'n' values in 'values', in the
 * specified order. */
static void
check_list(struct ovs_list *list, const int values[], size_t n)
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

    assert(ovs_list_is_empty(list) == !n);
    assert(ovs_list_is_singleton(list) == (n == 1));
    assert(ovs_list_is_short(list) == (n < 2));
    assert(ovs_list_size(list) == n);
}

#if 0
/* Prints the values in 'list', plus 'name' as a title. */
static void
print_list(const char *name, struct ovs_list *list)
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
        struct ovs_list list;

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
            struct ovs_list list;
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
                    ovs_list_remove(&e->node);
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

/* Tests that LIST_FOR_EACH_POP removes the elements of a list.  */
static void
test_list_for_each_pop(void)
{
    enum { MAX_ELEMS = 10 };
    size_t n;

    for (n = 0; n <= MAX_ELEMS; n++) {
        struct element elements[MAX_ELEMS];
        int values[MAX_ELEMS];
        struct ovs_list list;
        struct element *e;
        size_t n_remaining;

        make_list(&list, elements, values, n);

        n_remaining = n;
        LIST_FOR_EACH_POP (e, node, &list) {
            n_remaining--;
            memmove(values, values + 1, sizeof *values * n_remaining);
            check_list(&list, values, n_remaining);
        }
    }
}

/* Tests the transplant of one list into another  */
static void
test_list_push_back_all(void)
{
    struct ovs_list list_a, list_b;
    struct element a, b, c, d;

    a.value = 0;
    b.value = 1;
    c.value = 2;
    d.value = 3;

    ovs_list_init(&list_a);
    ovs_list_init(&list_b);

    ovs_list_insert(&list_a, &a.node);
    ovs_list_insert(&list_a, &b.node);
    ovs_list_insert(&list_b, &c.node);
    ovs_list_insert(&list_b, &d.node);

    /* Check test preconditions */
    assert(2 == ovs_list_size(&list_a));
    assert(2 == ovs_list_size(&list_b));

    /* Perform transplant */
    ovs_list_push_back_all(&list_a, &list_b);

    /* Check expected result */
    assert(4 == ovs_list_size(&list_a));
    assert(0 == ovs_list_size(&list_b));

    struct element *node;
    int n = 0;
    LIST_FOR_EACH(node, node, &list_a) {
        assert(n == node->value);
        n++;
    }
    assert(n == 4);
}

static void
run_test(void (*function)(void))
{
    function();
    printf(".");
}

static void
test_list_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    run_test(test_list_construction);
    run_test(test_list_for_each_safe);
    run_test(test_list_for_each_pop);
    run_test(test_list_push_back_all);
    printf("\n");
}

OVSTEST_REGISTER("test-list", test_list_main);
