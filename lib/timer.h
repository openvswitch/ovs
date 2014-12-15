/*
 * Copyright (c) 2011, 2013 Nicira, Inc.
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

#ifndef TIMER_H
#define TIMER_H 1

#include <stdbool.h>

#include "timeval.h"
#include "util.h"

struct timer {
    long long int t;
};

long long int timer_msecs_until_expired(const struct timer *);
void timer_wait_at(const struct timer *, const char *where);
#define timer_wait(timer) timer_wait_at(timer, OVS_SOURCE_LOCATOR)

/* Causes 'timer' to expire when 'duration' milliseconds have passed.
 *
 * May be used to initialize 'timer'. */
static inline void
timer_set_duration(struct timer *timer, long long int duration)
{
    timer->t = time_msec() + duration;
}

/* Causes 'timer' never to expire.
 *
 * May be used to initialize 'timer'. */
static inline void
timer_set_infinite(struct timer *timer)
{
    timer->t = LLONG_MAX;
}

/* Causes 'timer' to expire immediately.
 *
 * May be used to initialize 'timer'. */
static inline void
timer_set_expired(struct timer *timer)
{
    timer->t = LLONG_MIN;
}

/* True if 'timer' has expired. */
static inline bool
timer_expired(const struct timer *timer)
{
    return time_msec() >= timer->t;
}

/* Returns ture if 'timer' will never expire. */
static inline bool
timer_is_infinite(const struct timer *timer)
{
    return timer->t == LLONG_MAX;
}

#endif /* timer.h */
