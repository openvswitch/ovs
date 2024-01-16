/*
 * Copyright (c) 2024 Canonical Ltd.
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

#ifndef COOPERATIVE_MULTITASKING_H
#define COOPERATIVE_MULTITASKING_H 1

/*
 * cooperative-multitasking, interleaved execution for Open vSwitch.
 *
 * Overview
 * ========
 *
 * One of the goals of Open vSwitch is to be as resource efficient as
 * possible.  Core parts of the program has been implemented as asynchronous
 * state machines, and when absolutely necessary additional threads are used.
 *
 * Modules with mostly synchronous and single threaded code that are expected
 * to have heavy processing, can make use of the cooperative-multitasking
 * interface to yield to modules that have registered callbacks at a time
 * threshold.
 *
 * Typical Usage
 * =============
 *
 * The module that provides the callback typically has a run() function that is
 * already part of the main processing loop and can then register like this:
 *
 * static void my_run_cb(void *arg);
 *
 * static void
 * my_run(struct data *my_data)
 * {
 *     ...
 *
 *     cooperative_multitasking_set(&my_run_cb, (void *) my_data,
 *                                  time_msec(), 1000, "my_run");
 * }
 *
 * static void
 * my_run_cb (void *arg)
 * {
 *     struct data *my_data = (struct data *) arg;
 *
 *     my_run(my_data);
 * }
 *
 * static void
 * my_destroy(struct data *my_data)
 * {
 *     ...
 *
 *     cooperatrive_multitasking_remove(&my_run_cb, (void *) my_data);
 * }
 *
 * The module that is expected to have heavy processing can yield like this:
 *
 * HMAP_FOR_EACH (row, hmap_node, &src_table->rows) {
 *     cooperative_multitasking_yield();
 *
 *     ...
 * }
 *
 * Rules for implementation
 * ========================
 *
 * - The module that registers itself with a callback must not use the yield
 *   functionality inside nor should it be possible to do so via calls to other
 *   modules.
 *
 * - The module that registers the callback should be self-sufficient, i.e.
 *   the internal state of that module should not matter to the outside world,
 *   at least it should not matter for the call stack that enters the
 *   cooperative_multitasking_yield().
 *
 * - cooperative_multitasking_yield() must not be called from places that can
 *   loop indefinitely, only in places that eventually end, otherwise it may
 *   give a false impression that the server is working fine while it is stuck
 *   and not actually doing any useful work.
 *
 * Thread-safety
 * =============
 *
 * The cooperative-multitasking module and functions therein are not thread
 * safe and must only be used by one thread.
 */

void cooperative_multitasking_destroy(void);

void cooperative_multitasking_set(void (*cb)(void *), void *arg,
                                  long long int last_run,
                                  long long int threshold,
                                  const char *name);

void cooperative_multitasking_remove(void (*cb)(void *), void *arg);

void cooperative_multitasking_yield_at(const char *source_location);
#define cooperative_multitasking_yield() \
    cooperative_multitasking_yield_at(OVS_SOURCE_LOCATOR)

#endif /* COOPERATIVE_MULTITASKING_H */
