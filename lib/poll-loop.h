/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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

/* High-level wrapper around the "poll" system call.
 *
 * Intended usage is for the program's main loop to go about its business
 * servicing whatever events it needs to.  Then, when it runs out of immediate
 * tasks, it calls each subordinate module's "wait" function, which in turn
 * calls one (or more) of the functions poll_fd_wait(), poll_immediate_wake(),
 * and poll_timer_wait() to register to be awakened when the appropriate event
 * occurs.  Then the main loop calls poll_block(), which blocks until one of
 * the registered events happens. */

#ifndef POLL_LOOP_H
#define POLL_LOOP_H 1

#include <poll.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct poll_waiter;

/* Schedule events to wake up the following poll_block(). */
struct poll_waiter *poll_fd_wait(int fd, short int events);
void poll_timer_wait(long long int msec);
void poll_timer_wait_until(long long int msec);
void poll_immediate_wake(void);

/* Wait until an event occurs. */
void poll_block(void);

/* Cancel a file descriptor callback or event. */
void poll_cancel(struct poll_waiter *);

#ifdef  __cplusplus
}
#endif

#endif /* poll-loop.h */
