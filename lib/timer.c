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

#include <config.h>

#include "timer.h"

#include "openvswitch/poll-loop.h"
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

/* Causes poll_block() to wake when 'timer' expires.
 *
 * ('where' is used in debug logging.  Commonly one would use timer_wait() to
 * automatically provide the caller's source file and line number for
 * 'where'.) */
void
timer_wait_at(const struct timer *timer, const char *where)
{
    if (timer->t < LLONG_MAX) {
        poll_timer_wait_until_at(timer->t, where);
    }
}
