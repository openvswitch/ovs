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
 * Usage:
 * =======
 *
 * Adding performance counter is easy. Simply use the following macro to
 * wrap around the expression you are interested in measuring.
 *
 * PERF(name, expr).
 *
 * The 'expr' is a set of C expressions you are interested in measuring.
 * 'name' is the counter name.
 *
 * For example, if we are interested in performance of perf_func():
 *
 *    int perf_func() {
 *        <implemenation>
 *    }
 *
 *    void func() {
 *        int rt;
 *
 *        ...
 *        PERF("perf_func", rt = perf_func());
 *
 *        return rt;
 *    }
 *
 *
 * This will maintain the number of times 'perf_func()' is called, total
 * number of instructions '<implementation>' plus function call overhead
 * executed.
 *
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
#define PERF(name, expr) \
      { \
          static struct perf_counter c = PERF_COUNTER_ONCE_INITIALIZER(name);\
          uint64_t start_count = perf_counter_read(&start_count); \
                                                                  \
          expr;                                                   \
                                                                  \
          perf_counter_accumulate(&c, start_count);               \
      }
#else
#define PERF(name, expr) { expr; }

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
