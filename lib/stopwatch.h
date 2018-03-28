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

#endif /* stopwatch.h */
