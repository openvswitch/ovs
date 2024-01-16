/*
 * Copyright (c) 2023 Canonical Ltd.
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
#include "cooperative-multitasking.h"
#include "cooperative-multitasking-private.h"
#include "openvswitch/hmap.h"
#include "ovstest.h"
#include "timeval.h"
#include "util.h"
#include "openvswitch/vlog.h"

struct fixture_arg {
    bool called;
};

static void fixture_run_wrap(void *arg);

#define FIXTURE_RUN_NAME "fixture_run"

static void
fixture_run(struct fixture_arg *arg)
{
    cooperative_multitasking_set(&fixture_run_wrap, (void *) arg,
                                 time_msec(), 0, FIXTURE_RUN_NAME);
    if (arg) {
        arg->called = true;
    }
}

static void
fixture_run_wrap(void *arg)
{
    struct fixture_arg *fixture_arg = (struct fixture_arg *) arg;

    fixture_run(fixture_arg);
}


static void fixture_other_run_wrap(void *arg);

#define FIXTURE_OTHER_RUN_NAME "fixture_other_run"

static void
fixture_other_run(struct fixture_arg *arg)
{
    cooperative_multitasking_set(&fixture_other_run_wrap, (void *) arg,
                                 time_msec(), 0, FIXTURE_OTHER_RUN_NAME);
    if (arg) {
        arg->called = true;
    }
}

static void
fixture_other_run_wrap(void *arg)
{
    struct fixture_arg *fixture_arg = (struct fixture_arg *) arg;

    fixture_other_run(fixture_arg);
}

static void
test_cm_set_registration(void)
{
    struct cm_entry *cm_entry;
    struct fixture_arg arg1 = {
        .called = false,
    };
    struct fixture_arg arg2 = {
        .called = false,
    };

    timeval_stop();
    long long int now = time_msec();

    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg1, 0, 1000,
                                 FIXTURE_RUN_NAME);
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg2, 0, 2000,
                                 FIXTURE_RUN_NAME);
    cooperative_multitasking_set(&fixture_other_run_wrap, NULL, 0, 3000,
                                 FIXTURE_OTHER_RUN_NAME);

    ovs_assert(hmap_count(&cooperative_multitasking_callbacks) == 3);

    HMAP_FOR_EACH (cm_entry, node, &cooperative_multitasking_callbacks) {
        if (cm_entry->arg == (void *) &arg1) {
            ovs_assert(cm_entry->cb == &fixture_run_wrap);
            ovs_assert(cm_entry->threshold == 1000);
            ovs_assert(cm_entry->last_run == now);
        } else if (cm_entry->arg == (void *) &arg2) {
            ovs_assert(cm_entry->cb == &fixture_run_wrap);
            ovs_assert(cm_entry->threshold == 2000);
            ovs_assert(cm_entry->last_run == now);
        } else if (cm_entry->cb == &fixture_other_run_wrap) {
            ovs_assert(cm_entry->arg == NULL);
            ovs_assert(cm_entry->threshold == 3000);
            ovs_assert(cm_entry->last_run == now);
        } else {
            OVS_NOT_REACHED();
        }
    }

    cooperative_multitasking_remove(&fixture_other_run_wrap, NULL);
    ovs_assert(hmap_count(&cooperative_multitasking_callbacks) == 2);
    cooperative_multitasking_remove(&fixture_run_wrap, (void *) &arg2);
    ovs_assert(hmap_count(&cooperative_multitasking_callbacks) == 1);

    cooperative_multitasking_destroy();
}

static void
test_cm_set_update(void)
{
    struct cm_entry *cm_entry;
    struct fixture_arg arg1 = {
        .called = false,
    };
    struct fixture_arg arg2 = {
        .called = false,
    };

    timeval_stop();
    long long int now = time_msec();

    /* First register a couple of callbacks. */
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg1, 0, 0,
                                 FIXTURE_RUN_NAME);
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg2, 0, 0,
                                 FIXTURE_RUN_NAME);

    ovs_assert(hmap_count(&cooperative_multitasking_callbacks) == 2);

    HMAP_FOR_EACH (cm_entry, node, &cooperative_multitasking_callbacks) {
        if (cm_entry->arg == (void *) &arg1) {
            ovs_assert(cm_entry->threshold == 0);
            ovs_assert(cm_entry->last_run == now);
        } else if (cm_entry->arg == (void *) &arg2) {
            ovs_assert(cm_entry->threshold == 0);
            ovs_assert(cm_entry->last_run == now);
        } else {
            OVS_NOT_REACHED();
        }
    }

    /* Update 'last_run' and 'threshold' for each callback and validate
     * that the correct entry was actually updated. */
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg1, 1, 2,
                                 FIXTURE_RUN_NAME);
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg2, 3, 4,
                                 FIXTURE_RUN_NAME);

    HMAP_FOR_EACH (cm_entry, node, &cooperative_multitasking_callbacks) {
        if (cm_entry->arg == (void *) &arg1) {
            ovs_assert(cm_entry->threshold == 2);
            ovs_assert(cm_entry->last_run == 1);
        } else if (cm_entry->arg == (void *) &arg2) {
            ovs_assert(cm_entry->threshold == 4);
            ovs_assert(cm_entry->last_run == 3);
        } else {
            OVS_NOT_REACHED();
        }
    }

    /* Confirm that providing 0 for 'last_run' or 'threshold' leaves the
     * existing value untouched. */
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg1, 0, 5,
                                 FIXTURE_RUN_NAME);
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg2, 6, 0,
                                 FIXTURE_RUN_NAME);

    HMAP_FOR_EACH (cm_entry, node, &cooperative_multitasking_callbacks) {
        if (cm_entry->arg == (void *) &arg1) {
            ovs_assert(cm_entry->threshold == 5);
            ovs_assert(cm_entry->last_run == 1);
        } else if (cm_entry->arg == (void *) &arg2) {
            ovs_assert(cm_entry->threshold == 4);
            ovs_assert(cm_entry->last_run == 6);
        } else {
            OVS_NOT_REACHED();
        }
    }

    cooperative_multitasking_destroy();
}

static void
test_cm_yield(void)
{
    struct cm_entry *cm_entry;
    struct fixture_arg arg1 = {
        .called = false,
    };
    struct fixture_arg arg2 = {
        .called = false,
    };

    timeval_stop();
    long long int now = time_msec();

    /* First register a couple of callbacks. */
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg1, 0, 1000,
                                 FIXTURE_RUN_NAME);
    cooperative_multitasking_set(&fixture_run_wrap, (void *) &arg2, 0, 2000,
                                 FIXTURE_RUN_NAME);

    ovs_assert(hmap_count(&cooperative_multitasking_callbacks) == 2);

    /* Call to yield should not execute callbacks until time threshold. */
    cooperative_multitasking_yield();
    ovs_assert(arg1.called == false);
    ovs_assert(arg2.called == false);

    HMAP_FOR_EACH (cm_entry, node, &cooperative_multitasking_callbacks) {
        ovs_assert(cm_entry->last_run == now);
    }

    /* Move clock forward and confirm the expected callbacks to be executed. */
    timeval_warp(1000);
    timeval_stop();
    cooperative_multitasking_yield();
    ovs_assert(arg1.called == true);
    ovs_assert(arg2.called == false);

    /* Move clock forward and confirm the expected callbacks to be executed. */
    arg1.called = arg2.called = false;
    timeval_warp(1000);
    timeval_stop();
    cooperative_multitasking_yield();
    ovs_assert(arg1.called == true);
    ovs_assert(arg2.called == true);

    cooperative_multitasking_destroy();
}

static void fixture_buggy_run_wrap(void *arg);

#define FIXTURE_BUGGY_RUN_NAME "fixture_buggy_run"

static void
fixture_buggy_run(struct fixture_arg *arg)
{
    cooperative_multitasking_set(&fixture_buggy_run_wrap, (void *) arg,
                                 time_msec(), 0, FIXTURE_BUGGY_RUN_NAME);
    if (arg) {
        arg->called = true;
    }
    /* A real run function MUST NOT directly or indirectly call yield, this is
     * here to test the detection of such a programming error. */
    cooperative_multitasking_yield();
}

static void
fixture_buggy_run_wrap(void *arg)
{
    struct fixture_arg *fixture_arg = (struct fixture_arg *) arg;

    fixture_buggy_run(fixture_arg);
}

static void
test_cooperative_multitasking_nested_yield(int argc OVS_UNUSED, char *argv[])
{
    struct fixture_arg arg1 = {
        .called = false,
    };

    set_program_name(argv[0]);
    vlog_set_pattern(VLF_CONSOLE, "%c|%p|%m");
    vlog_set_levels(NULL, VLF_SYSLOG, VLL_OFF);

    time_msec(); /* Ensure timeval is initialized. */

    cooperative_multitasking_set(&fixture_buggy_run_wrap, (void *) &arg1,
                                 0, 1000, FIXTURE_BUGGY_RUN_NAME);
    timeval_warp(1000);
    cooperative_multitasking_yield();
    cooperative_multitasking_destroy();
}

static void
test_cooperative_multitasking(int argc OVS_UNUSED, char *argv[] OVS_UNUSED)
{
    time_msec(); /* Ensure timeval is initialized. */

    test_cm_set_registration();
    test_cm_set_update();
    test_cm_yield();
}

OVSTEST_REGISTER("test-cooperative-multitasking",
                 test_cooperative_multitasking);
OVSTEST_REGISTER("test-cooperative-multitasking-nested-yield",
                 test_cooperative_multitasking_nested_yield);
