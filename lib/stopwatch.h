/* Copyright (c) 2017 Red Hat, Inc.
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

#ifndef STOPWATCH_H
#define STOPWATCH_H 1

#include <stdbool.h>

enum stopwatch_units {
    SW_MS,
    SW_US,
    SW_NS,
};

struct stopwatch_stats {
    unsigned long long count;    /* Total number of samples. */
    enum stopwatch_units unit;   /* Unit of following values. */
    unsigned long long max;      /* Maximum value. */
    unsigned long long min;      /* Minimum value. */
    double pctl_95;              /* 95th percentile. */
    double ewma_50;              /* Exponentially weighted moving average
                                    (alpha 0.50). */
    double ewma_1;               /* Exponentially weighted moving average
                                    (alpha 0.01). */
};

/* Create a new stopwatch.
 * The "units" are not used for any calculations but are printed when
 * statistics are requested.
 */
void stopwatch_create(const char *name, enum stopwatch_units units);

/* Start a stopwatch. */
void stopwatch_start(const char *name, unsigned long long ts);

/* Stop a stopwatch. The elapsed time will be used for updating statistics
 * for this stopwatch.
 */
void stopwatch_stop(const char *name, unsigned long long ts);

/* Retrieve statistics calculated from collected samples */
bool stopwatch_get_stats(const char *name, struct stopwatch_stats *stats);

/* Block until all enqueued samples have been processed. */
void stopwatch_sync(void);

#endif /* stopwatch.h */
