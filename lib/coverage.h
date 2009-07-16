/*
 * Copyright (c) 2009 Nicira Networks.
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

#ifndef COVERAGE_H
#define COVERAGE_H 1

/* This file implements a simple form of coverage instrumentation.  Points in
 * source code that are of interest must be explicitly annotated with
 * COVERAGE_INC.  The coverage counters may be logged at any time with
 * coverage_log().
 *
 * This form of coverage instrumentation is intended to be so lightweight that
 * it can be enabled in production builds.  It is obviously not a substitute
 * for traditional coverage instrumentation with e.g. "gcov", but it is still
 * a useful debugging tool. */

#include "vlog.h"

/* A coverage counter. */
struct coverage_counter {
    const char *name;           /* Textual name. */
    unsigned int count;         /* Count within the current epoch. */
    unsigned long long int total; /* Total count over all epochs. */
};

/* Increments the counter with the given NAME.  Coverage counters need not be
 * declared explicitly, but when you add the first coverage counter to a given
 * file, you must also add that file to COVERAGE_FILES in lib/automake.mk. */
#define COVERAGE_INC(NAME)                              \
    do {                                                \
        extern struct coverage_counter NAME##_count;    \
        NAME##_count.count++;                           \
    } while (0)

/* Adds AMOUNT to the coverage counter with the given NAME. */
#define COVERAGE_ADD(NAME, AMOUNT)                      \
    do {                                                \
        extern struct coverage_counter NAME##_count;    \
        NAME##_count.count += AMOUNT;                   \
    } while (0)

void coverage_init(void);
void coverage_log(enum vlog_level, bool suppress_dups);
void coverage_clear(void);

#endif /* coverage.h */
