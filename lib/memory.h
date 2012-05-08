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

#ifndef MEMORY_H
#define MEMORY_H 1

/* Memory usage monitor.
 *
 * This is intended to be called as part of a daemon's main loop.  After some
 * time to allow the daemon to allocate an initial memory usage, it logs some
 * memory usage information (most of which must actually be provided by the
 * client).  At intervals, if the daemon's memory usage has grown
 * significantly, it again logs information.
 *
 * The monitor also has a unixctl interface.
 *
 * Intended usage in the program's main loop is like this:
 *
 * for (;;) {
 *     memory_run();
 *     if (memory_should_report()) {
 *          struct simap usage;
 *
 *          simap_init(&usage);
 *          ...fill in 'usage' with meaningful statistics...
 *          memory_report(&usage);
 *          simap_destroy(&usage);
 *     }
 *
 *     ...
 *
 *     memory_wait();
 *     poll_block();
 * }
 */

#include <stdbool.h>

struct simap;

void memory_run(void);
void memory_wait(void);

bool memory_should_report(void);
void memory_report(const struct simap *usage);

#endif /* memory.h */
