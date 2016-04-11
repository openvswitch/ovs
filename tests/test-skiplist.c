/* Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 * All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

/* A non-exhaustive test for some of the functions and macros declared in
 * skiplist.h. */

#include <config.h>
#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "ovstest.h"
#include "skiplist.h"
#include "random.h"
#include "util.h"

static void
test_skiplist_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED);

static int test_skiplist_cmp(const void *a, const void *b, const void *conf);

static void test_skiplist_insert(void);
static void test_skiplist_delete(void);
static void test_skiplist_find(void);
static void test_skiplist_forward_to(void);
static void test_skiplist_random(void);

static int test_skiplist_cmp(const void *a, const void *b, const void *conf OVS_UNUSED)
{
    const int *n = (const int *)a;
    const int *m = (const int *)b;
    return (*n > *m) - (*n < *m);
}

static void test_skiplist_insert(void)
{
    struct skiplist *sl = skiplist_create(14, test_skiplist_cmp, NULL);
    skiplist_set_free_func(sl, free);
    int i;
    int *integer;
    /* Insert a million rows */
    for(i = 0; i < 1000000; i++){
        integer = malloc(sizeof(int));
        *integer = i;
        skiplist_insert(sl, integer);
    }

    /* Check that the skiplist maintains the list sorted */
    struct skiplist_node *node = skiplist_first(sl);

    for(i = 0; i < 1000000; i++){
        integer = (int*)skiplist_get_data(node);
        assert(i == *integer);
        node = skiplist_next(node);
    }

    skiplist_destroy(sl);
}

static void test_skiplist_delete(void)
{
    struct skiplist *sl = skiplist_create(3, test_skiplist_cmp, NULL);
    int a, b, c;
    a = 1;
    b = 2;
    c = 3;
    /* Insert rows */
    skiplist_insert(sl, &a);
    skiplist_insert(sl, &c);
    skiplist_insert(sl, &b);

    /* Check that the items exists */
    assert(a == *(int *)skiplist_get_data(skiplist_find(sl, &a)));
    assert(b == *(int *)skiplist_get_data(skiplist_find(sl, &b)));
    assert(c == *(int *)skiplist_get_data(skiplist_find(sl, &c)));

    /* Delete b*/
    skiplist_delete(sl, &b);

    /* Check that the items doesn't exists */
    assert(a == *(int *)skiplist_get_data(skiplist_find(sl, &a)));
    assert(NULL == skiplist_get_data(skiplist_find(sl, &b)));
    assert(c == *(int *)skiplist_get_data(skiplist_find(sl, &c)));

    skiplist_destroy(sl);
}

static void test_skiplist_find(void)
{
    struct skiplist *sl = skiplist_create(14, test_skiplist_cmp, NULL);
    skiplist_set_free_func(sl, free);

    int i;
    int *integer;
    /* Insert a many rows */
    for(i = 0; i < 1000000; i++){
        integer = malloc(sizeof(int));
        *integer = i;
        skiplist_insert(sl, integer);
    }

    /* Seek all the items */
    for(i = 0; i < 1000000; i++){
        integer = (int*)skiplist_get_data(skiplist_find(sl, &i));
        assert(i == *integer);
    }

    skiplist_destroy(sl);
}

static void test_skiplist_forward_to(void)
{
    struct skiplist *sl = skiplist_create(3, test_skiplist_cmp, NULL);
    int a, b, c, d, x;
    a = 1;
    b = 3;
    c = 7;
    d = 10;
    /* Insert rows */
    skiplist_insert(sl, &a);
    skiplist_insert(sl, &c);
    skiplist_insert(sl, &b);
    skiplist_insert(sl, &d);

    /* Check that forward_to returns the expected value */
    x = a;
    assert(a == *(int *)skiplist_get_data(skiplist_forward_to(sl, &x)));

    x = 2;
    assert(b == *(int *)skiplist_get_data(skiplist_forward_to(sl, &x)));

    x = 5;
    assert(c == *(int *)skiplist_get_data(skiplist_forward_to(sl, &x)));

    x = 8;
    assert(d == *(int *)skiplist_get_data(skiplist_forward_to(sl, &x)));

    x = 15;
    assert(NULL == (int *)skiplist_get_data(skiplist_forward_to(sl, &x)));

    /* Destroy skiplist */
    skiplist_destroy(sl);
}

static void
test_skiplist_random(void)
{
    int j;
    for(j=1; j<64; j++) {
        struct skiplist *sl = skiplist_create(j, test_skiplist_cmp, NULL);
        int total_numbers = 50;
        int expected_count = 0;
        int *numbers = malloc(sizeof(int) * total_numbers);
        int i, op, element;
        for(i = 0; i < total_numbers; i++){
            numbers[i] = i;
        }
        random_init();
        for(i = 0; i < total_numbers*1000; i++){
            op = random_uint32() % 2;
            element = random_range(total_numbers);
            if(op == 0){
                if(!skiplist_find(sl, &numbers[element])) {
                    expected_count++;
                }
                skiplist_insert(sl, &numbers[element]);
            } else {
                if(skiplist_find(sl, &numbers[element])) {
                    expected_count--;
                }
                skiplist_delete(sl, &numbers[element]);
            }
            ovs_assert(expected_count == skiplist_get_size(sl));
        }

        skiplist_destroy(sl);
        free(numbers);
    }
}

static void
test_skiplist_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    printf("skiplist insert\n");
    test_skiplist_insert();
    printf("skiplist delete\n");
    test_skiplist_delete();
    printf("skiplist find\n");
    test_skiplist_find();
    printf("skiplist forward_to\n");
    test_skiplist_forward_to();
    printf("skiplist random\n");
	test_skiplist_random();
    printf("\n");
}

OVSTEST_REGISTER("test-skiplist", test_skiplist_main);
