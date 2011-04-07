/*
 * Copyright (c) 2011 Nicira Networks.
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

#include "timer.h"

#include "poll-loop.h"
#include "timeval.h"

/* Returns the number of milliseconds until 'timer' expires. */
long long int
timer_msecs_until_expired(const struct timer *timer)
{
    switch (timer->t) {
    case LLONG_MAX: return LLONG_MAX;
    case LLONG_MIN: return 0;
    default: return timer->t - time_msec();
    }
}

/* Causes poll_block() to wake when 'timer' expires. */
void
timer_wait(const struct timer *timer)
{
    if (timer->t < LLONG_MAX) {
        poll_timer_wait_until(timer->t);
    }
}

/* Returns the time at which 'timer' was set with 'duration'.  Infinite timers
 * were enabled at time LLONG_MAX.  Manually expired timers were enabled at
 * LLONG_MIN. */
long long int
timer_enabled_at(const struct timer *timer, long long int duration)
{
    switch (timer->t) {
    case LLONG_MAX: return LLONG_MAX;
    case LLONG_MIN: return LLONG_MIN;
    default: return timer->t - duration;
    }
}
