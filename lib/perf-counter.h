/*
 * Copyright (c) 2015 Nicira, Inc.
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

#ifndef __PERF_COUNTER_H
#define __PERF_COUNTER_H 1

/* Motivation
 * ==========
 *
 * It is sometimes desirable to gain performance insights of a program
 * by using hardware counters.  Recent Linux kernels started to support
 * a set of portable API for configuring and access those counter across
 * multiple platforms.
 *
 * APIs provided by perf-counter.h provides a set of APIs that are
 * semi-integrated into OVS user spaces. The infrastructure that initializes,
 * cleanup, display and clear them at run time is provided. However the
 * sample points are not. A programmer needs insert sample points when needed.
 *
 * Since there is no pre configured sample points, there is no run time
 * over head for the released product.
 *
 * Limitations
 * ===========
 * - Hard coded to sample CPU cycle count in user space only.
 * - Only one counter is sampled.
 * - Useful macros are only provided for function profiling.
 * - show and clear command applies to all counters, there is no way
 *   to select a sub-set of counter.
 *
 * Those are not fundamental limits, but only limited by current
 * implementation.
 *
 * Function instruction counter sample point Usage
 * ================================================
 *
 * There are two macros provided:
 *
 * Macro 'PERF_FUNCTON_COUNT_BEGIN' needs to be inserted towards the
 * beginning of the function where local variables are declared.
 *
 * Macro 'PERF_FUNCTON_COUNT_END' needs to appear in the same function,
 * some where below 'PERF_FUNCTION_COUNT_BEGIN', usually towards of
 * a function.
 *
 * For example:
 *
 *    void my_func() {
 *      int some_local_variable;
 *
 *      PERF_FUNCTION_COUNT_BEGIN;
 *
 *      < implementation >
 *
 *      PERF_FUNCTION_COUNT_END
 *    }
 *
 * This will maintain the number of times 'my_func()' is called, total
 * number of instructions '<implementation>' executed during all those calls.
 *
 * Currently there are two limitation:
 * 1). At most one pair can appear in the same variable scope.
 * 2). The Macros use function name as the counter name for display.
 *     Thus, all functions in one annotation session are required to
 *     have unique names.
 *
 * Note, there is no requirement for those macros to be balanced.
 * For example:
 *
 *    void my_func(int i){
 *
 *      PERF_FUNCTION_COUNT_BEGIN;
 *
 *      if (i == 300) {
 *          PERF_FUNCTION_COUNT_END;
 *          return;
 *      } else {
 *           <some code>
 *      }
 *    }
 * will work just fine.
 */

#if defined(__linux__) && defined(HAVE_LINUX_PERF_EVENT_H)
struct perf_counter {
    const char *name;
    bool once;
    uint64_t n_events;
    uint64_t total_count;
};

#define PERF_COUNTER_ONCE_INITIALIZER(name)  \
    {                                        \
        name,                                \
        false,                               \
        0,                                   \
        0,                                   \
    }

void perf_counters_init(void);
void perf_counters_destroy(void);
void perf_counters_clear(void);

uint64_t perf_counter_read(uint64_t *counter);
void perf_counter_accumulate(struct perf_counter *counter,
                             uint64_t start_count);
char *perf_counters_to_string(void);

/* User access macros. */
#define PERF_FUNCTION_BEGIN \
    static struct perf_counter x__ = PERF_COUNTER_ONCE_INITIALIZER(__func__); \
    uint64_t start_count__ = perf_counter_read(&start_count__);               \

#define PERF_FUNCTION_END \
    perf_counter_accumulate(&x__, start_count__);

#else

#define PERF_FUNCTON_BEGIN
#define PERF_FUNCTON_END

static inline void perf_counters_init(void) {}
static inline void perf_counters_destroy(void) {}
static inline void perf_counters_clear(void) {}
static inline char *
perf_counters_to_string(void)
{
    return xstrdup("Not Supported on this platform. Only available on Linux (version >= 2.6.32)");
}

#endif

#endif
