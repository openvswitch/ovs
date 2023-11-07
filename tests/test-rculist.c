/*
 * Copyright (c) 2023 Red Hat, Inc.
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
#undef NDEBUG
#include <unistd.h>

#include "openvswitch/list.h"
#include "ovstest.h"
#include "ovs-thread.h"
#include "random.h"
#include "rculist.h"
#include "util.h"

enum { MAX_ELEMS = 10, MAX_CHECKS = 200 };

/* Sample list element. */
struct element {
    int value;
    struct rculist node;
};

static void
do_usleep(unsigned int usecs)
{
#ifdef _WIN32
    Sleep(MAX(usecs / 1000, 1));
#else
    usleep(usecs);
#endif
}

/* Continuously check the integrity of the list until it's empty. */
static void *
checker_main(void *aux)
{
    struct rculist *list = (struct rculist *) aux;
    struct element *elem;
    bool checked = false;

    for (int i = 0; i < MAX_CHECKS; i++) {
        int value = -1;

        RCULIST_FOR_EACH (elem, node, list) {
            ovs_assert(value <= elem->value);
            ovs_assert(elem->value < MAX_ELEMS);
            value = elem->value;
            if (!checked) {
                checked = true;
            }
            do_usleep(10);
        }

        ovsrcu_quiesce();

        if (checked && rculist_is_empty(list)) {
            break;
        }
    }
    return NULL;
}

/* Run test while a thread checks the integrity of the list.
 * Tests must end up emptying the list. */
static void
run_test_while_checking(void (*function)(struct rculist *list))
{
    struct rculist list;
    pthread_t checker;

    rculist_init(&list);

    checker = ovs_thread_create("checker", checker_main, &list);
    function(&list);

    ovs_assert(rculist_is_empty(&list));
    ovsrcu_quiesce();
    xpthread_join(checker, NULL);
    printf(".");
}

static void
test_rculist_insert_delete__(struct rculist *list, bool long_version)
{
    struct element *elem;
    int value;

    for (int i = 1; i < MAX_ELEMS; i++) {
        elem = xmalloc(sizeof *elem);
        elem->value = i;
        rculist_insert(list, &elem->node);
        /* Leave some time for checkers to iterate through. */
        do_usleep(random_range(1000));
    }

    ovsrcu_quiesce();

    value = MAX_ELEMS;
    RCULIST_FOR_EACH_REVERSE_PROTECTED (elem, node, list) {
        ovs_assert (elem->value <= value);
        value = elem->value;
    }

    if (long_version) {
        struct element *next;
        RCULIST_FOR_EACH_SAFE_PROTECTED (elem, next, node, list) {
            rculist_remove(&elem->node);
            ovsrcu_postpone(free, elem);
            /* Leave some time for checkers to iterate through. */
            do_usleep(random_range(1000));
        }
    } else {
        RCULIST_FOR_EACH_SAFE_PROTECTED (elem, node, list) {
            rculist_remove(&elem->node);
            ovsrcu_postpone(free, elem);
            /* Leave some time for checkers to iterate through. */
            do_usleep(random_range(1000));
        }
    }
}

static void
test_rculist_insert_delete(struct rculist *list)
{
    test_rculist_insert_delete__(list, false);
}

static void
test_rculist_insert_delete_long(struct rculist *list)
{
    test_rculist_insert_delete__(list, true);
}

static void
test_rculist_push_front_pop_back(struct rculist *list)
{
    struct element *elem;

    for (int i = MAX_ELEMS - 1; i > 0; i--) {
        elem = xmalloc(sizeof *elem);
        elem->value = i;
        rculist_push_front(list, &elem->node);
        /* Leave some time for checkers to iterate through. */
        do_usleep(random_range(1000));
    }

    ovsrcu_quiesce();

    while (!rculist_is_empty(list)) {
        elem = CONTAINER_OF(rculist_pop_back(list), struct element, node);
        ovsrcu_postpone(free, elem);
        /* Leave some time for checkers to iterate through. */
        do_usleep(random_range(1000));
    }
}

static void
test_rculist_push_back_pop_front(struct rculist *list)
{
    struct element *elem;

    for (int i = 0; i < MAX_ELEMS; i++) {
        elem = xmalloc(sizeof *elem);
        elem->value = i;
        rculist_push_back(list, &elem->node);
        /* Leave some time for checkers to iterate through. */
        do_usleep(random_range(1000));
    }

    ovsrcu_quiesce();

    while (!rculist_is_empty(list)) {
        elem = CONTAINER_OF(rculist_pop_front(list), struct element, node);
        ovsrcu_postpone(free, elem);
        /* Leave some time for checkers to iterate through. */
        do_usleep(random_range(1000));
    }
}

static void
test_rculist_splice(struct rculist *list)
{
    struct element *elem;
    struct rculist other;

    rculist_init(&other);

    /* Insert elements in list by splicing an intermediate rculist. */
    for (int i = 0; i < MAX_ELEMS; i++) {
        elem = xmalloc(sizeof *elem);
        elem->value = i;
        rculist_insert(&other, &elem->node);
        rculist_splice_hidden(list, rculist_next_protected(&other), &other);
        rculist_init(&other);
        /* Leave some time for checkers to iterate through. */
        do_usleep(random_range(1000));
    }

    ovsrcu_quiesce();

    ovs_assert(rculist_size(list) == MAX_ELEMS);
    ovs_assert(rculist_is_empty(&other));
    while (!rculist_is_empty(list)) {
        elem = CONTAINER_OF(rculist_pop_front(list), struct element, node);
        ovsrcu_postpone(free, elem);
        /* Leave some time for checkers to iterate through. */
        do_usleep(random_range(1000));
    }
}

static void
test_rculist_main(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    run_test_while_checking(test_rculist_insert_delete);
    run_test_while_checking(test_rculist_insert_delete_long);
    run_test_while_checking(test_rculist_push_back_pop_front);
    run_test_while_checking(test_rculist_push_front_pop_back);
    run_test_while_checking(test_rculist_splice);
    printf("\n");
}

OVSTEST_REGISTER("test-rculist", test_rculist_main);
