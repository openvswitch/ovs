/*
 * Copyright (c) 2009, 2010, 2011, 2012 Nicira, Inc.
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

/* Defines COUNTER.  There must be exactly one such definition at file scope
 * within a program. */
#if USE_LINKER_SECTIONS
#define COVERAGE_DEFINE(COUNTER)                                        \
        COVERAGE_DEFINE__(COUNTER);                                     \
        extern struct coverage_counter *counter_ptr_##COUNTER;          \
        struct coverage_counter *counter_ptr_##COUNTER                  \
            __attribute__((section("coverage"))) = &counter_##COUNTER
#else
#define COVERAGE_DEFINE(MODULE) \
        extern struct coverage_counter counter_##MODULE
#endif

/* Adds 1 to COUNTER. */
#define COVERAGE_INC(COUNTER) counter_##COUNTER.count++;

/* Adds AMOUNT to COUNTER. */
#define COVERAGE_ADD(COUNTER, AMOUNT) counter_##COUNTER.count += (AMOUNT);

void coverage_init(void);
void coverage_log(void);
void coverage_clear(void);

/* Implementation detail. */
#define COVERAGE_DEFINE__(COUNTER)                              \
        extern struct coverage_counter counter_##COUNTER;       \
        struct coverage_counter counter_##COUNTER = { #COUNTER, 0, 0 }

#endif /* coverage.h */
